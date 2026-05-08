# Square Base IDP Go SDK

Go SDK for Base identity integration in `net/http` services.

## Install

```bash
go get github.com/squareexp/idp-go
```

## Required Environment

```env
BASE_IDP_ISSUER=https://authlayer.squareexp.com
BASE_IDP_CLIENT_ID=<your-client-id>
BASE_IDP_CLIENT_SECRET=<your-client-secret-if-confidential>
BASE_IDP_REDIRECT_URI=<exact-registered-callback-url>
BASE_IDP_SCOPES="openid profile <product>:read <product>:write"
BASE_IDP_AUDIENCE=square-experience
```

Get these values from Base client registration.

## Verify Protected Routes

```go
package main

import (
  "log"
  "net/http"

  squareidp "github.com/squareexp/idp-go"
)

func main() {
  client := squareidp.MustNew(squareidp.ConfigFromEnv())

  mux := http.NewServeMux()
  mux.Handle("/api/projects", client.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    principal, _ := squareidp.PrincipalFromContext(r.Context())
    _, _ = w.Write([]byte(principal.ID))
  }), squareidp.MiddlewareOptions{
    VerifyOptions: squareidp.VerifyOptions{RequiredScope: "projects:read"},
  }))

  log.Fatal(http.ListenAndServe(":8080", mux))
}
```

## OAuth Code Exchange

```go
authorizeURL, _ := client.AuthorizeURL(squareidp.AuthorizeOptions{
  State: "csrf-state",
  Nonce: "nonce",
})

tokens, err := client.ExchangeCode(ctx, squareidp.TokenOptions{
  Code: code,
})
_ = authorizeURL
_ = tokens
_ = err
```

## Verification Model

The SDK verifies:
- PASETO `v4.public` signature (Ed25519)
- issuer and audience
- time-based claims
- `token_use=access`
- required scopes

Discovery keys are fetched and cached for offline verification after warm-up.
