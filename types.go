package squareidp

import (
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	DefaultAudience          = "square-experience"
	DefaultKeyCacheTTL       = 5 * time.Minute
	DefaultClockSkew         = 30 * time.Second
	defaultImplicitAssertion = "square-experience:idp:access:v1"
)

type Config struct {
	Issuer        string
	ClientID      string
	ClientSecret  string
	RedirectURI   string
	Scopes        []string
	Audience      string
	RequiredScope string
	HTTPClient    *http.Client
	KeyCacheTTL   time.Duration
	ClockSkew     time.Duration
}

func ConfigFromEnv() Config {
	return Config{
		Issuer:        os.Getenv("BASE_IDP_ISSUER"),
		ClientID:      os.Getenv("BASE_IDP_CLIENT_ID"),
		ClientSecret:  os.Getenv("BASE_IDP_CLIENT_SECRET"),
		RedirectURI:   os.Getenv("BASE_IDP_REDIRECT_URI"),
		Scopes:        SplitScopes(os.Getenv("BASE_IDP_SCOPES")),
		Audience:      envDefault("BASE_IDP_AUDIENCE", DefaultAudience),
		RequiredScope: os.Getenv("BASE_IDP_REQUIRED_SCOPE"),
	}
}

func (c Config) normalized() Config {
	c.Issuer = strings.TrimRight(c.Issuer, "/")
	if c.Audience == "" {
		c.Audience = DefaultAudience
	}
	if c.HTTPClient == nil {
		c.HTTPClient = http.DefaultClient
	}
	if c.KeyCacheTTL <= 0 {
		c.KeyCacheTTL = DefaultKeyCacheTTL
	}
	if c.ClockSkew <= 0 {
		c.ClockSkew = DefaultClockSkew
	}
	return c
}

type Metadata struct {
	Issuer                        string   `json:"issuer"`
	AuthorizationEndpoint         string   `json:"authorization_endpoint"`
	TokenEndpoint                 string   `json:"token_endpoint"`
	PASETOPublicKeyEndpoint       string   `json:"paseto_public_key_endpoint"`
	TokenFormat                   string   `json:"token_format"`
	PASETOPurpose                 string   `json:"paseto_purpose"`
	GrantTypesSupported           []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported,omitempty"`
	TokenEndpointAuthMethods      []string `json:"token_endpoint_auth_methods_supported,omitempty"`
}

type PublicKey struct {
	KID               string `json:"kid"`
	Alg               string `json:"alg"`
	KTY               string `json:"kty"`
	CRV               string `json:"crv"`
	PublicKeyBase64   string `json:"public_key_base64"`
	ImplicitAssertion string `json:"implicit_assertion,omitempty"`
}

type PublicKeySet struct {
	Keys []PublicKey `json:"keys"`
}

type AuthorizeOptions struct {
	ResponseType        string
	State               string
	Nonce               string
	Scopes              []string
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	AdditionalParameter map[string]string
}

type TokenOptions struct {
	Code         string
	CodeVerifier string
	RedirectURI  string
}

type RefreshOptions struct {
	RefreshToken string
	Scopes       []string
}

type TokenPair struct {
	AccessToken           string `json:"access_token"`
	RefreshToken          string `json:"refresh_token"`
	TokenType             string `json:"token_type"`
	ExpiresIn             int    `json:"expires_in"`
	RefreshTokenExpiresAt string `json:"refresh_token_expires_at"`
}

type AccountContext struct {
	Kind     string `json:"kind"`
	TenantID string `json:"tenant_id,omitempty"`
	ActorID  string `json:"actor_id,omitempty"`
	OwnerID  string `json:"owner_id,omitempty"`
}

type AccessClaims struct {
	Iss       string         `json:"iss"`
	Sub       string         `json:"sub"`
	Aud       string         `json:"aud"`
	Exp       string         `json:"exp"`
	Nbf       string         `json:"nbf"`
	Iat       string         `json:"iat"`
	JTI       string         `json:"jti"`
	GID       string         `json:"gid"`
	Email     string         `json:"email,omitempty"`
	Name      string         `json:"name,omitempty"`
	TokenUse  string         `json:"token_use"`
	SID       string         `json:"sid"`
	Ctx       AccountContext `json:"ctx"`
	Role      string         `json:"role"`
	Ent       []string       `json:"ent,omitempty"`
	EV        string         `json:"ev,omitempty"`
	AAL       int            `json:"aal"`
	AMR       []string       `json:"amr,omitempty"`
	AZP       string         `json:"azp,omitempty"`
	SCP       []string       `json:"scp,omitempty"`
	RawClaims map[string]any `json:"-"`
}

type Principal struct {
	ID             string
	Subject        string
	Email          string
	Name           string
	Role           string
	Scopes         []string
	AccountContext AccountContext
	Claims         AccessClaims
}

type VerifyOptions struct {
	Issuer              string
	Audience            string
	RequiredScope       string
	MaxClockSkew        time.Duration
	ImplicitAssertion   string
	TrustedPublicKeySet *PublicKeySet
}

func SplitScopes(value string) []string {
	return strings.Fields(value)
}

func JoinScopes(scopes []string) string {
	return strings.Join(scopes, " ")
}

func envDefault(name string, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
