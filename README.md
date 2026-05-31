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
BASE_IDP_ALLOWED_AUTH_METHODS="password magic_link"
BASE_IDP_REQUESTED_CLAIMS="email profile"
BASE_IDP_AUDIENCE=square-experience
```

Get these values from Base client registration.
`BASE_IDP_SECRET` still works as a legacy alias, but `BASE_IDP_CLIENT_SECRET` is the preferred server-side env name.

## Fast Init

If you want a one-command bootstrap path, generate the client registration payload and env block with the TypeScript SDK CLI and post it to the Base admin API:

```bash
npx base-idp init \
  --client-id console-gateway \
  --display-name "Base Console" \
  --product console \
  --app-domain console.cloud.squareexp.com \
  --redirect-uri http://localhost:3010/api/auth/callback \
  --allowed-redirect-uris http://localhost:3010/api/auth/callback \
  --allowed-origins http://localhost:3010 \
  --allowed-scopes "openid profile console:manage" \
  --allowed-auth-methods password,magic_link \
  --requested-claims email,profile
```

Add `--post --admin-token <token>` when you want the SDK to call `POST /admin/v1/clients` directly.

## How to Use the SDK in a Server Backend

This SDK is designed for `net/http` services that need to:

- generate the Base authorize URL
- exchange an authorization code for tokens
- verify PASETO access tokens offline
- protect routes with scopes

Typical flow:

1. Load `baseidp.ConfigFromEnv()`
2. Create a client with `baseidp.MustNew(...)`
3. Send the browser to `client.AuthorizeURL(...)`
4. In the callback, exchange the code with `client.ExchangeCode(...)`
5. Store the app session yourself
6. Protect API routes with `client.RequireAuth(...)`

For pure verification in a gateway, you can skip the login helpers and just call `VerifyAccessToken(...)` through middleware on every request.

## Verify Protected Routes

```go
package main

import (
  "log"
  "net/http"

  baseidp "github.com/squareexp/idp-go"
)

func main() {
  client := baseidp.MustNew(baseidp.ConfigFromEnv())

  mux := http.NewServeMux()
  mux.Handle("/api/projects", client.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    principal, _ := baseidp.PrincipalFromContext(r.Context())
    _, _ = w.Write([]byte(principal.ID))
  }), baseidp.MiddlewareOptions{
    VerifyOptions: baseidp.VerifyOptions{RequiredScope: "projects:read"},
  }))

  log.Fatal(http.ListenAndServe(":8080", mux))
}
```

## OAuth Code Exchange

```go
authorizeURL, _ := client.AuthorizeURL(baseidp.AuthorizeOptions{
  State: "csrf-state",
  Nonce: "nonce",
  AuthSessionID: "auth_session_id_if_you_have_one",
})

tokens, err := client.ExchangeCode(ctx, baseidp.TokenOptions{
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
