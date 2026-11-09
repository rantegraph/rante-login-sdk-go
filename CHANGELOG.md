# Changelog

## 1.0.1 (2026-11-09)

- **New module path:** the repository moved to the rantegraph organization on GitHub, so the module is now
  `github.com/rantegraph/rante-login-sdk-go` (it was `github.com/rante-corporation/rante-login-sdk-go`). Update your
  import paths; `go get github.com/rantegraph/rante-login-sdk-go@v1.0.1`. No code changes.
- **Example:** the website creates its own account on a person's first sign-in and finds it by `sub` afterwards.

## 1.0.0 (2026-11-09)

First release.

- **`Client`:** `CreateAuthorizationRequest`, `HandleCallback`, `ExchangeCode`, `ValidateIDToken`, `FetchUserInfo`, and
  the browser SDK cookie helpers. Built on go-oidc v3, golang.org/x/oauth2 and go-jose v4; Go 1.26 or later.
- **Client authentication:** `private_key_jwt` (RS256 or ES256) for server-side websites, and PKCE alone for
  browser-only websites.
- **Example:** `examples/nethttp`.
