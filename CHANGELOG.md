# Changelog

## 1.0.0 (2026-11-09)

First release.

- **`Client`:** `CreateAuthorizationRequest`, `HandleCallback`, `ExchangeCode`, `ValidateIDToken`, `FetchUserInfo`, and
  the browser SDK cookie helpers. Built on go-oidc v3, golang.org/x/oauth2 and go-jose v4; Go 1.26 or later.
- **Client authentication:** `private_key_jwt` (RS256 or ES256) for server-side websites, and PKCE alone for
  browser-only websites.
- **Example:** `examples/nethttp`.
