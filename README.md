# Rante Login SDK for Go

"Sign in with Rante" on your Go server. The SDK:

- builds the sign-in request (authorization code with PKCE, state and nonce);
- exchanges the code, proving it is your app with `private_key_jwt`, or with PKCE alone for browser-only apps;
- validates the ID token before you trust who signed in;
- calls the userinfo endpoint.

It finishes sign-ins started by the [Rante Login browser SDK](https://github.com/rante-corporation/rante-login-sdk)
too, including FedCM sign-ins in Chrome and Edge.

The SDK is a thin layer over three libraries:

- [go-oidc](https://github.com/coreos/go-oidc): discovery, the signing keys, and ID token verification;
- [golang.org/x/oauth2](https://pkg.go.dev/golang.org/x/oauth2): the authorize URL with PKCE, and the code exchange;
- [go-jose](https://github.com/go-jose/go-jose): the client assertion.

It needs Go 1.26 or later.

## Install

```sh
go get github.com/rante-corporation/rante-login-sdk-go
```

The module is fetched from GitHub; there's no separate registry for Go.

## Register your app

1. Sign in to the Rante Portal and register an app at <https://portal.rante.com/dev/apps>.
2. On the app's page, turn on Rante Login and add your redirect URI, for example
   `https://shop.example.com/auth/rante/callback`. Use `http://localhost:3000/auth/rante/callback` for the example
   in this repository.
3. Choose which information your site asks for (at least **Name**).
4. Choose the website type:
   - **Server-side website** (recommended for this SDK): your server proves itself with a Signed JWT key linked to
     the app.
     1. Make a key pair:
        `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out private.pem`, or
        `-algorithm EC -pkeyopt ec_paramgen_curve:P-256` for ES256.
     2. Make the public key: `openssl pkey -in private.pem -pubout -out public.pem`.
     3. At <https://portal.rante.com/dev/apikeys>, create a key with the **Signed JWT (RS256 or ES256)** method and paste
        `public.pem`.
     4. Link the key to the app, and note its prefix (`rk_live_…`).

     `private.pem` stays on your server.
   - **Browser-only website**: no key. The SDK sends only the PKCE verifier.
5. Copy the app's **Application (client) ID**.

## Sign people in

```go
import rantelogin "github.com/rante-corporation/rante-login-sdk-go"

pemBytes, _ := os.ReadFile("private.pem")
key, err := rantelogin.ParseSigningKeyPEM(os.Getenv("RANTE_LOGIN_KEY_PREFIX"), pemBytes)
rante, err := rantelogin.NewClient(rantelogin.Config{
	ClientID:    os.Getenv("RANTE_LOGIN_CLIENT_ID"),
	RedirectURI: "https://shop.example.com/auth/rante/callback",
	SigningKey:  key, // a server-side website; leave it nil for a browser-only website
}) // one client per app, shared: it caches the discovery document and the keys

// 1. Send the browser to Rante Login, and keep the rest of the request in the server-side session.
http.HandleFunc("GET /auth/rante/sign-in", func(w http.ResponseWriter, r *http.Request) {
	request, err := rante.CreateAuthorizationRequest(r.Context(), nil)
	// ... handle err
	session.Set("rante", request.Expected())
	http.Redirect(w, r, request.URL, http.StatusSeeOther)
})

// 2. At the redirect URI: check the response, exchange the code and validate the ID token.
http.HandleFunc("GET /auth/rante/callback", func(w http.ResponseWriter, r *http.Request) {
	expected := session.Take("rante") // each request is used once
	result, err := rante.HandleCallback(r.Context(), r.URL.Query(), expected)
	// result.IDToken.Subject is the person's ID on your website. It's pairwise: the same for your organization's
	// apps, and different for other organizations.
})
```

`HandleCallback` returns a `*rantelogin.Error` unless all of these hold:

- `state` matches;
- the response came from Rante Login (`iss`, [RFC 9207](https://www.rfc-editor.org/rfc/rfc9207));
- the token endpoint accepted the code;
- the ID token is valid. Specifically:
  - its RS256 signature checks out with the key that its `kid` names in Rante Login's JWKS;
  - `iss` is `https://login.rante.com/common/v2.0`;
  - `aud` is your client ID (and `azp`, when present);
  - `nonce` matches;
  - `exp` hasn't passed (a minute of clock skew is allowed);
  - `iat` and `sub` are present.

Rante Login releases an email address only once the person has verified it.

### Sign-ins started by the browser SDK

Your page can show the "Sign in with Rante" button instead, using the browser SDK with `serverSide: true`:

- **Redirect sign-ins:** the SDK keeps the PKCE verifier, state and nonce in the `rante_login_pkce`,
  `rante_login_state` and `rante_login_nonce` cookies. Read them at the redirect URI, then clear them:

  ```go
  expected := rantelogin.FromBrowserSDKCookies(r)
  rantelogin.ClearBrowserSDKCookies(w)
  result, err := rante.HandleCallback(r.Context(), r.URL.Query(), expected)
  ```

- **FedCM sign-ins** (Chrome and Edge): the ID token comes back to the page, which posts it to your server. Because
  the page could choose any nonce, issue one per session on the server, and pass it to
  `RanteLogin.renderButton(element, { nonce })`. Then check the token against it:

  ```go
  token, err := rante.ValidateIDToken(r.Context(), body.IDToken, session.Nonce)
  ```

### Userinfo

```go
userinfo, err := rante.FetchUserInfo(r.Context(), result.Tokens.AccessToken, result.IDToken.Subject)
```

The access token from the code exchange lasts 15 minutes. FedCM sign-ins return no access token.

## API

| | |
|---|---|
| `NewClient(Config)` | Fields: `ClientID`, `RedirectURI`, `Scope` (default `openid profile email`; request only scopes whose information the app asks for), `SigningKey`, `Issuer`, `HTTPClient` (default: a 10-second timeout, no redirects) and `ClockSkew` (default 60 s). |
| `ParseSigningKeyPEM(keyPrefix, pem)` or `&SigningKey{KeyPrefix, PrivateKey}` | An RSA key of at least 2048 bits (RS256) or an EC P-256 key (ES256): PKCS#8, PKCS#1 or SEC 1 PEM. |
| `CreateAuthorizationRequest(ctx, *AuthorizationOptions)` | Options: `Nonce`, `Prompt`, `LoginHint` and `MaxAge`; nil is fine. Returns `URL`, `State`, `Nonce` and `CodeVerifier`, plus `Expected()`. |
| `HandleCallback(ctx, r.URL.Query(), expected)` | Returns a `*Result` with `IDToken` (`Subject`, `Claims`) and `Tokens` (`AccessToken`, `TokenType`, `ExpiresIn`, `IDToken`, `Scope`). |
| `ExchangeCode(ctx, code, codeVerifier)` | The token request on its own. |
| `ValidateIDToken(ctx, rawIDToken, nonce)` | Returns an `*IDToken`. |
| `FetchUserInfo(ctx, accessToken, expectedSubject)` | Returns a `*UserInfo` with `Subject` and `Claims`. |
| `FromBrowserSDKCookies(r)`, `FromCookieHeader(header)`, `ClearBrowserSDKCookies(w)` | The browser SDK's cookies. The two `From` functions return nil when a cookie is missing. |
| `ClientAuthentication()` | `"private_key_jwt"` or `"none"`. |

### Errors

Every failure is a `*rantelogin.Error` (use `errors.As`) with a stable `Code`, a `Message`, and a `Status` when the
error came from Rante Login:

| Code | Meaning |
|---|---|
| `invalid_configuration` | A setting or key is wrong; the message says which. |
| `missing_transaction` | No expected values: the session or the browser SDK's cookies are gone. They last 10 minutes and must be on the redirect URI's origin. |
| `state_mismatch`, `issuer_mismatch`, `invalid_request` | The response doesn't belong to this sign-in, didn't come from Rante Login, or is malformed. |
| `access_denied`, `login_required`, `consent_required`, … | Rante Login's own error. `access_denied` means the person cancelled. |
| `invalid_client` | The token endpoint refused the app's authentication. Check the key prefix, that the key is linked to the app and not expired, and that the private key matches. A browser-only app must not have a key. |
| `invalid_grant` | The code was used already, is older than 60 seconds, or doesn't match the redirect URI or the PKCE verifier. |
| `invalid_id_token` | The ID token failed a check; the message says which. |
| `invalid_token`, `userinfo_subject_mismatch`, `userinfo_failed` | Userinfo refused the access token, answered for another person, or failed. |
| `discovery_failed`, `network_error`, `invalid_token_response`, `token_request_failed` | Rante Login couldn't be reached, or answered in an unexpected way. |

## Example

[`examples/nethttp`](examples/nethttp) is a small website on the standard library's `net/http` and `html/template`.
It signs people in three ways:

- the browser SDK's button, with FedCM in Chrome and Edge;
- the browser SDK's button with the redirect flow, elsewhere;
- a sign-in link that works without JavaScript, where the server starts the sign-in.

It also shows the person's claims and their userinfo, and sends a Content Security Policy that allows the browser SDK
and FedCM.

```sh
RANTE_LOGIN_CLIENT_ID=… RANTE_LOGIN_KEY_PREFIX=rk_live_… RANTE_LOGIN_PRIVATE_KEY_FILE=private.pem go run ./examples/nethttp
```

Then open <http://localhost:3000>. In PowerShell, set the variables first, for example
`$env:RANTE_LOGIN_CLIENT_ID = '…'`.

| Variable | Default | Meaning |
|---|---|---|
| `RANTE_LOGIN_CLIENT_ID` | (required) | The app's Application (client) ID. |
| `RANTE_LOGIN_REDIRECT_URI` | `http://localhost:3000/auth/rante/callback` | Exactly as registered. The example handles the callback at its path, and listens on its port. |
| `RANTE_LOGIN_KEY_PREFIX`, `RANTE_LOGIN_PRIVATE_KEY_FILE` | (none) | Server-side websites: the Signed JWT key's prefix, and its PEM private key. |
| `RANTE_LOGIN_SCOPE` | `openid profile email` | |
| `PORT`, `HOST` | the redirect URI's port, `127.0.0.1` | |

Open the site on the redirect URI's origin: browsers keep the sign-in cookies per host, so `localhost` and `127.0.0.1`
don't mix. The example keeps sessions in memory; a real site uses a session store.

## Tests

```sh
go test ./...
```

The tests run offline. `localidp_test.go` is a local OpenID provider on `httptest`, shaped like Rante Login:

- it publishes discovery and a JWKS, with keys generated for each run;
- it issues codes, and checks each token request: `client_id`, PKCE, the redirect URI, and the app's
  `private_key_jwt` assertion (algorithm, `kid`, `iss`, `sub`, `aud`, lifetime, a `jti` used once);
- it signs ID tokens, and serves userinfo.

The tests cover:

- successful sign-ins with RS256, ES256 and PKCE alone;
- every refusal: state, issuer, nonce, audience, `azp`, expiry, a missing `iat`, a foreign key, HS256 and `alg: none`;
- userinfo, configuration errors and network errors.

## Verified against Rante Login

On 9 November 2026 this version and its example signed in against the live `login.rante.com`, with a test app
registered in the Rante Portal and a real Rante account:

| Sign-in | App type | Client authentication |
|---|---|---|
| Redirect, started by the browser SDK's button | Server-side website | `private_key_jwt` with an RS256 key |
| Redirect, started by the server | Server-side website | `private_key_jwt` with an ES256 key |
| Redirect, started by the browser SDK's button | Browser-only website | none: PKCE alone |
| FedCM in Microsoft Edge | Browser-only website | none: the browser hands over the ID token |

In every run the server validated the ID token: the signature against the JWKS, `iss`, `aud` and `azp`, the nonce
and the expiry. The redirect runs also checked that:

- the browser SDK's cookies were cleared after a sign-in its button started;
- userinfo, called after the RS256 sign-in, returned the ID token's `sub`;
- signing out of the example worked.

The offline tests passed, and so did 21 checks against the running example (refusals, escaping and Origin checks).

## Production notes

- **HTTPS:** register an `https` redirect URI, and keep the state, nonce and verifier on the server.
- **Logs:** don't log the redirect URI's query: it carries the one-time code.
- **Signing out:** signing out of your website doesn't sign the person out of Rante.
- **Redirect URIs:** Rante Login accepts only `https`, or `http://localhost` / `http://127.0.0.1` with the exact
  port.
- **Grants:** it has no refresh tokens and no device code flow.

## License

[MIT](LICENSE)
