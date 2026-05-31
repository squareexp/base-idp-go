package baseidp

import "errors"

var (
	ErrInvalidConfig     = errors.New("base idp: invalid config")
	ErrConfigDiscovery   = errors.New("base idp: config discovery failed")
	ErrDiscoveryFailed   = errors.New("base idp: discovery failed")
	ErrKeyFetchFailed    = errors.New("base idp: key fetch failed")
	ErrTokenExchange     = errors.New("base idp: token exchange failed")
	ErrMissingBearer     = errors.New("base idp: missing bearer token")
	ErrInvalidToken      = errors.New("base idp: invalid access token")
	ErrInsufficientScope = errors.New("base idp: insufficient scope")
)
