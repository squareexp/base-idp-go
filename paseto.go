package baseidp

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

var pasetoHeader = []byte("v4.public.")

type pasetoFooter struct {
	KID string `json:"kid"`
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

func UnsafeFooterKID(token string) (string, error) {
	footer, err := unsafeFooter(token)
	if err != nil {
		return "", err
	}
	return footer.KID, nil
}

func VerifyPASETOV4Public(token string, keySet PublicKeySet, config Config, options VerifyOptions) (*Principal, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 4 || parts[0] != "v4" || parts[1] != "public" {
		return nil, fmt.Errorf("%w: token is not PASETO v4.public", ErrInvalidToken)
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: decode payload: %v", ErrInvalidToken, err)
	}
	footerBytes, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return nil, fmt.Errorf("%w: decode footer: %v", ErrInvalidToken, err)
	}
	if len(payload) <= ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: payload is too short", ErrInvalidToken)
	}

	var footer pasetoFooter
	if err := json.Unmarshal(footerBytes, &footer); err != nil {
		return nil, fmt.Errorf("%w: decode footer json: %v", ErrInvalidToken, err)
	}
	if footer.Alg != "v4.public" || footer.Typ != "paseto" || footer.KID == "" {
		return nil, fmt.Errorf("%w: footer is not a Square v4.public footer", ErrInvalidToken)
	}

	key, err := selectPublicKey(keySet, footer.KID)
	if err != nil {
		return nil, err
	}

	message := payload[:len(payload)-ed25519.SignatureSize]
	signature := payload[len(payload)-ed25519.SignatureSize:]
	implicit := options.ImplicitAssertion
	if implicit == "" {
		implicit = defaultImplicitAssertion
	}
	pae := preAuthEncode([][]byte{pasetoHeader, message, footerBytes, []byte(implicit)})
	if !ed25519.Verify(key, pae, signature) {
		return nil, fmt.Errorf("%w: signature verification failed", ErrInvalidToken)
	}

	var claims AccessClaims
	if err := json.Unmarshal(message, &claims); err != nil {
		return nil, fmt.Errorf("%w: decode claims: %v", ErrInvalidToken, err)
	}
	_ = json.Unmarshal(message, &claims.RawClaims)

	if err := validateClaims(claims, config, options); err != nil {
		return nil, err
	}

	return &Principal{
		ID:             claims.GID,
		Subject:        claims.Sub,
		Email:          claims.Email,
		Name:           claims.Name,
		Role:           claims.Role,
		Scopes:         append([]string(nil), claims.SCP...),
		AccountContext: claims.Ctx,
		Claims:         claims,
	}, nil
}

func unsafeFooter(token string) (pasetoFooter, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 4 || parts[0] != "v4" || parts[1] != "public" {
		return pasetoFooter{}, fmt.Errorf("%w: token is not PASETO v4.public", ErrInvalidToken)
	}
	footerBytes, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return pasetoFooter{}, fmt.Errorf("%w: decode footer: %v", ErrInvalidToken, err)
	}
	var footer pasetoFooter
	if err := json.Unmarshal(footerBytes, &footer); err != nil {
		return pasetoFooter{}, fmt.Errorf("%w: decode footer json: %v", ErrInvalidToken, err)
	}
	return footer, nil
}

func selectPublicKey(keySet PublicKeySet, kid string) (ed25519.PublicKey, error) {
	for _, key := range keySet.Keys {
		if key.KID != kid || key.Alg != "v4.public" || key.CRV != "Ed25519" {
			continue
		}
		raw, err := decodeBase64Flexible(key.PublicKeyBase64)
		if err != nil {
			return nil, fmt.Errorf("%w: decode public key: %v", ErrInvalidToken, err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: Ed25519 public key has invalid size", ErrInvalidToken)
		}
		return ed25519.PublicKey(raw), nil
	}
	return nil, fmt.Errorf("%w: key id %q is not present in the Base key set", ErrInvalidToken, kid)
}

func validateClaims(claims AccessClaims, config Config, options VerifyOptions) error {
	config = config.normalized()
	issuer := options.Issuer
	if issuer == "" {
		issuer = config.Issuer
	}
	audience := firstNonEmpty(options.Audience, config.Audience, DefaultAudience)
	requiredScope := firstNonEmpty(options.RequiredScope, config.RequiredScope)
	skew := options.MaxClockSkew
	if skew <= 0 {
		skew = config.ClockSkew
	}

	if claims.TokenUse != "access" {
		return fmt.Errorf("%w: token_use must be access", ErrInvalidToken)
	}
	if claims.Iss != issuer || claims.Aud != audience {
		return fmt.Errorf("%w: issuer or audience mismatch", ErrInvalidToken)
	}
	if claims.GID == "" || claims.Sub == "" || claims.SID == "" || claims.Role == "" || claims.Ctx.Kind == "" {
		return fmt.Errorf("%w: required identity claims are missing", ErrInvalidToken)
	}

	now := time.Now()
	exp, err := parseClaimTime(claims.Exp)
	if err != nil {
		return fmt.Errorf("%w: invalid exp: %v", ErrInvalidToken, err)
	}
	nbf, err := parseClaimTime(claims.Nbf)
	if err != nil {
		return fmt.Errorf("%w: invalid nbf: %v", ErrInvalidToken, err)
	}
	if !exp.After(now.Add(-skew)) {
		return fmt.Errorf("%w: access token expired", ErrInvalidToken)
	}
	if nbf.After(now.Add(skew)) {
		return fmt.Errorf("%w: access token is not valid yet", ErrInvalidToken)
	}
	if requiredScope != "" && !hasString(claims.SCP, requiredScope) {
		return fmt.Errorf("%w: required scope %q is missing", ErrInsufficientScope, requiredScope)
	}
	return nil
}

func preAuthEncode(pieces [][]byte) []byte {
	var out bytes.Buffer
	_ = binary.Write(&out, binary.LittleEndian, uint64(len(pieces)))
	for _, piece := range pieces {
		_ = binary.Write(&out, binary.LittleEndian, uint64(len(piece)))
		out.Write(piece)
	}
	return out.Bytes()
}

func parseClaimTime(value string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, value)
}

func decodeBase64Flexible(value string) ([]byte, error) {
	encodings := []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	}
	var last error
	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(value)
		if err == nil {
			return decoded, nil
		}
		last = err
	}
	return nil, last
}

func hasString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
