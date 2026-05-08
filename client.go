package squareidp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

type Client struct {
	cfg Config

	mu            sync.RWMutex
	metadataCache *Metadata
	keyCache      *PublicKeySet
	keyCacheUntil time.Time
}

func New(config Config) (*Client, error) {
	config = config.normalized()
	if config.Issuer == "" || config.ClientID == "" || config.RedirectURI == "" {
		return nil, fmt.Errorf("%w: issuer, client id, and redirect uri are required", ErrInvalidConfig)
	}
	return &Client{cfg: config}, nil
}

func MustNew(config Config) *Client {
	client, err := New(config)
	if err != nil {
		panic(err)
	}
	return client
}

func (c *Client) Config() Config {
	return c.cfg
}

func (c *Client) AuthorizeURL(options AuthorizeOptions) (string, error) {
	responseType := firstNonEmpty(options.ResponseType, "code")
	redirectURI := firstNonEmpty(options.RedirectURI, c.cfg.RedirectURI)
	scopes := options.Scopes
	if len(scopes) == 0 {
		scopes = c.cfg.Scopes
	}

	u, err := url.Parse(c.cfg.Issuer + "/oauth2/authorize")
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("response_type", responseType)
	q.Set("client_id", c.cfg.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", JoinScopes(scopes))
	if options.State != "" {
		q.Set("state", options.State)
	}
	if options.Nonce != "" {
		q.Set("nonce", options.Nonce)
	}
	if options.CodeChallenge != "" {
		q.Set("code_challenge", options.CodeChallenge)
		q.Set("code_challenge_method", firstNonEmpty(options.CodeChallengeMethod, "S256"))
	}
	for key, value := range options.AdditionalParameter {
		if key != "" && value != "" {
			q.Set(key, value)
		}
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (c *Client) Discovery(ctx context.Context, force bool) (*Metadata, error) {
	c.mu.RLock()
	if c.metadataCache != nil && !force {
		defer c.mu.RUnlock()
		copy := *c.metadataCache
		return &copy, nil
	}
	c.mu.RUnlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.Issuer+"/.well-known/square-identity", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	var metadata Metadata
	if err := c.doJSON(req, &metadata, ErrDiscoveryFailed); err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.metadataCache = &metadata
	c.mu.Unlock()
	return &metadata, nil
}

func (c *Client) PublicKeys(ctx context.Context, force bool) (*PublicKeySet, error) {
	now := time.Now()
	c.mu.RLock()
	if c.keyCache != nil && !force && now.Before(c.keyCacheUntil) {
		defer c.mu.RUnlock()
		copy := *c.keyCache
		copy.Keys = append([]PublicKey(nil), c.keyCache.Keys...)
		return &copy, nil
	}
	c.mu.RUnlock()

	metadata, err := c.Discovery(ctx, false)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadata.PASETOPublicKeyEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	var keys PublicKeySet
	if err := c.doJSON(req, &keys, ErrKeyFetchFailed); err != nil {
		return nil, err
	}
	if len(keys.Keys) == 0 {
		return nil, fmt.Errorf("%w: Base returned an empty public key set", ErrKeyFetchFailed)
	}

	c.mu.Lock()
	c.keyCache = &keys
	c.keyCacheUntil = now.Add(c.cfg.KeyCacheTTL)
	c.mu.Unlock()
	return &keys, nil
}

func (c *Client) ExchangeCode(ctx context.Context, options TokenOptions) (*TokenPair, error) {
	if options.Code == "" {
		return nil, fmt.Errorf("%w: authorization code is required", ErrTokenExchange)
	}
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {options.Code},
		"client_id":    {c.cfg.ClientID},
		"redirect_uri": {firstNonEmpty(options.RedirectURI, c.cfg.RedirectURI)},
	}
	if c.cfg.ClientSecret != "" {
		form.Set("client_secret", c.cfg.ClientSecret)
	}
	if options.CodeVerifier != "" {
		form.Set("code_verifier", options.CodeVerifier)
	}
	return c.postToken(ctx, form)
}

func (c *Client) Refresh(ctx context.Context, options RefreshOptions) (*TokenPair, error) {
	if options.RefreshToken == "" {
		return nil, fmt.Errorf("%w: refresh token is required", ErrTokenExchange)
	}
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {options.RefreshToken},
		"client_id":     {c.cfg.ClientID},
	}
	if c.cfg.ClientSecret != "" {
		form.Set("client_secret", c.cfg.ClientSecret)
	}
	if len(options.Scopes) > 0 {
		form.Set("scope", JoinScopes(options.Scopes))
	}
	return c.postToken(ctx, form)
}

func (c *Client) VerifyAccessToken(ctx context.Context, token string, options VerifyOptions) (*Principal, error) {
	keySet := options.TrustedPublicKeySet
	if keySet == nil {
		keys, err := c.PublicKeys(ctx, false)
		if err != nil {
			return nil, err
		}
		keySet = keys
	}
	return VerifyPASETOV4Public(token, *keySet, c.cfg, options)
}

func (c *Client) postToken(ctx context.Context, form url.Values) (*TokenPair, error) {
	metadata, err := c.Discovery(ctx, false)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, metadata.TokenEndpoint, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var pair TokenPair
	if err := c.doJSON(req, &pair, ErrTokenExchange); err != nil {
		return nil, err
	}
	return &pair, nil
}

func (c *Client) doJSON(req *http.Request, out any, wrap error) error {
	res, err := c.cfg.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", wrap, err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("%w: read response: %v", wrap, err)
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return fmt.Errorf("%w: status=%d body=%s", wrap, res.StatusCode, string(body))
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("%w: decode json: %v", wrap, err)
	}
	return nil
}
