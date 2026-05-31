package baseidp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

type contextKey string

const principalContextKey contextKey = "base-idp-principal"

type MiddlewareOptions struct {
	VerifyOptions
	CookieName   string
	ErrorHandler func(http.ResponseWriter, *http.Request, error)
}

func ContextWithPrincipal(ctx context.Context, principal *Principal) context.Context {
	return context.WithValue(ctx, principalContextKey, principal)
}

func PrincipalFromContext(ctx context.Context) (*Principal, bool) {
	principal, ok := ctx.Value(principalContextKey).(*Principal)
	return principal, ok && principal != nil
}

func BearerTokenFromRequest(r *http.Request, cookieName string) (string, error) {
	value := r.Header.Get("Authorization")
	if value != "" {
		parts := strings.Fields(value)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") && parts[1] != "" {
			return parts[1], nil
		}
	}
	if cookieName != "" {
		if cookie, err := r.Cookie(cookieName); err == nil && cookie.Value != "" {
			return cookie.Value, nil
		}
	}
	return "", ErrMissingBearer
}

func (c *Client) Middleware(options MiddlewareOptions) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, err := BearerTokenFromRequest(r, options.CookieName)
			if err != nil {
				writeMiddlewareError(w, r, err, options.ErrorHandler)
				return
			}

			principal, err := c.VerifyAccessToken(r.Context(), token, options.VerifyOptions)
			if err != nil {
				writeMiddlewareError(w, r, err, options.ErrorHandler)
				return
			}

			next.ServeHTTP(w, r.WithContext(ContextWithPrincipal(r.Context(), principal)))
		})
	}
}

func (c *Client) RequireAuth(next http.Handler, options MiddlewareOptions) http.Handler {
	return c.Middleware(options)(next)
}

func writeMiddlewareError(w http.ResponseWriter, r *http.Request, err error, handler func(http.ResponseWriter, *http.Request, error)) {
	if handler != nil {
		handler(w, r, err)
		return
	}

	status := http.StatusUnauthorized
	code := "unauthorized"
	if errors.Is(err, ErrInsufficientScope) {
		status = http.StatusForbidden
		code = "insufficient_scope"
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", `Bearer error="`+code+`"`)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": err.Error(),
	})
}
