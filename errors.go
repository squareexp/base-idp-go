package squareidp

import "errors"

var (
	ErrInvalidConfig     = errors.New("square idp: invalid config")
	ErrDiscoveryFailed   = errors.New("square idp: discovery failed")
	ErrKeyFetchFailed    = errors.New("square idp: key fetch failed")
	ErrTokenExchange     = errors.New("square idp: token exchange failed")
	ErrMissingBearer     = errors.New("square idp: missing bearer token")
	ErrInvalidToken      = errors.New("square idp: invalid access token")
	ErrInsufficientScope = errors.New("square idp: insufficient scope")
)
