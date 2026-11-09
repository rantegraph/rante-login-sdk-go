// Package rantelogin is the Rante Login SDK for Go: "Sign in with Rante" on your server.
//
// It is a thin layer over github.com/coreos/go-oidc (discovery, the JWKS and ID token verification),
// golang.org/x/oauth2 (the authorize URL with PKCE, and the code exchange) and github.com/go-jose/go-jose (the
// private_key_jwt client assertion).
//
// Rante Login is an OpenID Connect provider (issuer https://login.rante.com/common/v2.0) with the authorization code
// flow with PKCE (S256), state, nonce and the iss response parameter (RFC 9207); client authentication by
// private_key_jwt (RFC 7523, a Signed JWT key linked to the app) for server-side websites, or PKCE alone for
// browser-only websites; RS256 ID tokens with a pairwise sub; and a userinfo endpoint.
package rantelogin

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"
)

// DefaultIssuer is Rante Login's issuer.
const DefaultIssuer = "https://login.rante.com/common/v2.0"

// The cookies the Rante Login browser SDK writes with serverSide: true (SameSite=Lax, 10 minutes, Path=/).
const (
	CookieCodeVerifier = "rante_login_pkce"
	CookieState        = "rante_login_state"
	CookieNonce        = "rante_login_nonce"
)

// BrowserSDKCookies lists the three cookies, for clearing them once read: each sign-in uses them once.
var BrowserSDKCookies = []string{CookieCodeVerifier, CookieState, CookieNonce}

const (
	assertionType     = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	assertionLifetime = 60 * time.Second // Rante Login accepts at most 5 minutes.
)

var (
	scopes          = []string{"openid", "profile", "email", "phone", "address", "rante.organization"}
	prompts         = []string{"none", "login", "consent", "select_account"}
	guidPattern     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	keyPrefixFormat = regexp.MustCompile(`^rk_live_[0-9a-f]{24}$`)
	errorCode       = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)
	noncePattern    = regexp.MustCompile(`^[\x21-\x7e]{1,256}$`)
	schemeAndHost   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://[^/?#]*`)
)

// Error is every failure the SDK reports. Code is stable and safe to show; OAuth errors (access_denied,
// invalid_grant, invalid_client, ...) keep their own codes. Status is the HTTP status when the error came from Rante
// Login.
type Error struct {
	Code    string
	Message string
	Status  int
	Err     error
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// Unwrap returns the underlying error, if any.
func (e *Error) Unwrap() error { return e.Err }

func newError(code, message string) *Error { return &Error{Code: code, Message: message} }

// SigningKey is a Signed JWT key linked to the app: its prefix as the Rante Portal shows it (sent as the client
// assertion's kid) and its private key, RSA of at least 2048 bits (RS256) or EC P-256 (ES256).
type SigningKey struct {
	KeyPrefix  string
	PrivateKey crypto.Signer
}

// ParseSigningKeyPEM reads an unencrypted PEM private key: PKCS#8 (BEGIN PRIVATE KEY, as openssl genpkey writes),
// PKCS#1 (BEGIN RSA PRIVATE KEY) or SEC 1 (BEGIN EC PRIVATE KEY).
func ParseSigningKeyPEM(keyPrefix string, pemBytes []byte) (*SigningKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, newError("invalid_configuration", "the signing key is not PEM")
	}
	var key any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, newError("invalid_configuration", "the signing key must be an unencrypted PEM private key, not "+block.Type)
	}
	if err != nil {
		return nil, &Error{Code: "invalid_configuration", Message: "the signing key could not be read", Err: err}
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, newError("invalid_configuration", "the signing key must be an RSA or EC P-256 private key")
	}
	signingKey := &SigningKey{KeyPrefix: keyPrefix, PrivateKey: signer}
	if _, err := signingKey.algorithm(); err != nil {
		return nil, err
	}
	return signingKey, nil
}

func (k *SigningKey) algorithm() (jose.SignatureAlgorithm, error) {
	if !keyPrefixFormat.MatchString(k.KeyPrefix) {
		return "", newError("invalid_configuration", "the key prefix must be the one the Rante Portal shows: rk_live_ and 24 hex digits")
	}
	switch key := k.PrivateKey.(type) {
	case *rsa.PrivateKey:
		if key.N.BitLen() < 2048 {
			return "", newError("invalid_configuration", "RSA signing keys must have at least 2048 bits")
		}
		return jose.RS256, nil
	case *ecdsa.PrivateKey:
		if key.Curve != elliptic.P256() {
			return "", newError("invalid_configuration", "EC signing keys must use the P-256 curve (ES256)")
		}
		return jose.ES256, nil
	}
	return "", newError("invalid_configuration", "the signing key must be an RSA or EC P-256 private key")
}

// Config is one app's settings.
type Config struct {
	// ClientID is the app's Application (client) ID.
	ClientID string
	// RedirectURI is exactly as registered on the app.
	RedirectURI string
	// Scope defaults to "openid profile email". Request only scopes whose information the app asks for.
	Scope string
	// SigningKey is set for server-side websites: the Signed JWT key linked to the app. Without it the client
	// authenticates with PKCE alone (browser-only websites).
	SigningKey *SigningKey
	// Issuer defaults to DefaultIssuer.
	Issuer string
	// HTTPClient makes the calls to Rante Login. Default: a client with a 10-second timeout that follows no redirects.
	HTTPClient *http.Client
	// ClockSkew allowed for the ID token's expiry. Default 60 seconds.
	ClockSkew time.Duration
}

// Client is a Rante Login client for one app. Create one per app and keep it: it caches the discovery document and
// the signing keys. It is safe for concurrent use.
type Client struct {
	clientID    string
	redirectURI string
	scope       string
	issuer      string
	signingKey  *SigningKey
	algorithm   jose.SignatureAlgorithm
	httpClient  *http.Client
	clockSkew   time.Duration

	mu       sync.Mutex
	provider *provider
}

type provider struct {
	oidc             *oidc.Provider
	verifier         *oidc.IDTokenVerifier
	oauth2           oauth2.Config
	userinfoEndpoint string
}

// NewClient checks the settings. It doesn't call Rante Login: the discovery document is fetched on first use.
func NewClient(cfg Config) (*Client, error) {
	c := &Client{
		clientID:   strings.ToLower(strings.TrimSpace(cfg.ClientID)),
		signingKey: cfg.SigningKey,
		httpClient: cfg.HTTPClient,
		clockSkew:  cfg.ClockSkew,
	}
	if !guidPattern.MatchString(c.clientID) {
		return nil, newError("invalid_configuration", "ClientID must be the app's Application (client) ID from the Rante Portal")
	}
	var err error
	if c.redirectURI, err = normalizeRedirectURI(cfg.RedirectURI); err != nil {
		return nil, err
	}
	if c.scope, err = normalizeScope(cfg.Scope); err != nil {
		return nil, err
	}
	if c.issuer, err = normalizeIssuer(cfg.Issuer); err != nil {
		return nil, err
	}
	if c.signingKey != nil {
		if c.algorithm, err = c.signingKey.algorithm(); err != nil {
			return nil, err
		}
	}
	if c.httpClient == nil {
		c.httpClient = &http.Client{
			Timeout:       10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	if c.clockSkew == 0 {
		c.clockSkew = 60 * time.Second
	}
	return c, nil
}

// ClientID is the app's client ID, in lower case.
func (c *Client) ClientID() string { return c.clientID }

// RedirectURI is the redirect URI, with its scheme and host in lower case like the browser SDK sends it.
func (c *Client) RedirectURI() string { return c.redirectURI }

// Scope is the scopes requested.
func (c *Client) Scope() string { return c.scope }

// Issuer is the issuer.
func (c *Client) Issuer() string { return c.issuer }

// ClientAuthentication is "private_key_jwt" with the app's Signed JWT key, or "none" (PKCE alone).
func (c *Client) ClientAuthentication() string {
	if c.signingKey != nil {
		return "private_key_jwt"
	}
	return "none"
}

// AuthorizationOptions are optional settings for CreateAuthorizationRequest.
type AuthorizationOptions struct {
	Nonce     string // your own nonce; default a random one
	Prompt    string // none, login, consent or select_account
	LoginHint string // a suggested account, up to 256 characters
	MaxAge    *int   // the maximum authentication age, in seconds
}

// AuthorizationRequest is a sign-in the server starts: send the browser to URL, and keep State, Nonce and
// CodeVerifier on the server until it comes back to the redirect URI.
type AuthorizationRequest struct {
	URL          string
	State        string
	Nonce        string
	CodeVerifier string
}

// Expected is what the sign-in must match at the redirect URI.
func (r *AuthorizationRequest) Expected() *ExpectedTransaction {
	return &ExpectedTransaction{State: r.State, Nonce: r.Nonce, CodeVerifier: r.CodeVerifier}
}

// ExpectedTransaction is what a sign-in must match at the redirect URI.
type ExpectedTransaction struct {
	State        string `json:"state"`
	Nonce        string `json:"nonce"`
	CodeVerifier string `json:"code_verifier"`
}

// Tokens is the token endpoint's answer.
type Tokens struct {
	AccessToken string // for the userinfo endpoint (15 minutes)
	TokenType   string // Bearer
	ExpiresIn   int64  // seconds, or 0 when not given
	IDToken     string // before validation
	Scope       string
}

// IDToken is a validated ID token.
type IDToken struct {
	// Subject is the person's ID on your website: pairwise, so the same for your organization's apps and different
	// for other organizations.
	Subject string
	// Claims are the token's claims, by their JWT names.
	Claims map[string]any
}

// Result is a finished sign-in.
type Result struct {
	IDToken IDToken
	Tokens  Tokens
}

// UserInfo is the userinfo endpoint's answer.
type UserInfo struct {
	Subject string
	Claims  map[string]any
}

// CreateAuthorizationRequest starts a sign-in on the server: the URL to send the browser to, and the values to keep
// (in the server-side session) until the browser comes back to the redirect URI. opts may be nil.
func (c *Client) CreateAuthorizationRequest(ctx context.Context, opts *AuthorizationOptions) (*AuthorizationRequest, error) {
	if opts == nil {
		opts = &AuthorizationOptions{}
	}
	nonce := opts.Nonce
	if nonce == "" {
		nonce = randomToken()
	} else if !noncePattern.MatchString(nonce) {
		return nil, newError("invalid_request", "nonce must be 1 to 256 printable ASCII characters without spaces")
	}
	prompt, err := checkPrompt(opts.Prompt)
	if err != nil {
		return nil, err
	}
	if len(opts.LoginHint) > 256 {
		return nil, newError("invalid_request", "LoginHint must be at most 256 characters")
	}
	if opts.MaxAge != nil && *opts.MaxAge < 0 {
		return nil, newError("invalid_request", "MaxAge must be a whole number of seconds")
	}
	p, err := c.discover(ctx)
	if err != nil {
		return nil, err
	}
	state := randomToken()
	codeVerifier := oauth2.GenerateVerifier()
	options := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(codeVerifier), oidc.Nonce(nonce)}
	if prompt != "" {
		options = append(options, oauth2.SetAuthURLParam("prompt", prompt))
	}
	if opts.LoginHint != "" {
		options = append(options, oauth2.SetAuthURLParam("login_hint", opts.LoginHint))
	}
	if opts.MaxAge != nil {
		options = append(options, oauth2.SetAuthURLParam("max_age", strconv.Itoa(*opts.MaxAge)))
	}
	return &AuthorizationRequest{URL: p.oauth2.AuthCodeURL(state, options...), State: state, Nonce: nonce, CodeVerifier: codeVerifier}, nil
}

// HandleCallback finishes a redirect sign-in at the redirect URI: it checks the response (query is r.URL.Query())
// against the values kept for it, exchanges the code and validates the ID token. expected comes from
// AuthorizationRequest.Expected, or from FromBrowserSDKCookies when the browser SDK started the sign-in.
func (c *Client) HandleCallback(ctx context.Context, query url.Values, expected *ExpectedTransaction) (*Result, error) {
	response := map[string]string{}
	for _, name := range []string{"code", "state", "iss", "error", "error_description"} {
		values := query[name]
		if len(values) > 1 {
			return nil, newError("invalid_request", "the response repeats "+name)
		}
		if len(values) == 1 {
			response[name] = values[0]
		}
	}
	if expected == nil || expected.State == "" || expected.Nonce == "" || expected.CodeVerifier == "" {
		return nil, newError("missing_transaction", "no sign-in is in progress for this browser, or it expired")
	}
	if !safeEqual(response["state"], expected.State) {
		return nil, newError("state_mismatch", "the response does not belong to the sign-in this browser started")
	}
	if response["iss"] != c.issuer { // RFC 9207
		return nil, newError("issuer_mismatch", "the response did not come from Rante Login")
	}
	if code := response["error"]; code != "" {
		description := clean(response["error_description"])
		if description == "" {
			description = code
		}
		if !errorCode.MatchString(code) {
			code = "authorization_failed"
		}
		return nil, newError(code, description)
	}
	if response["code"] == "" {
		return nil, newError("invalid_request", "the response has no code")
	}
	tokens, err := c.ExchangeCode(ctx, response["code"], expected.CodeVerifier)
	if err != nil {
		return nil, err
	}
	idToken, err := c.ValidateIDToken(ctx, tokens.IDToken, expected.Nonce)
	if err != nil {
		return nil, err
	}
	return &Result{IDToken: *idToken, Tokens: *tokens}, nil
}

// ExchangeCode is the token request: the code, the PKCE verifier and the app's client authentication.
func (c *Client) ExchangeCode(ctx context.Context, code, codeVerifier string) (*Tokens, error) {
	if code == "" || codeVerifier == "" {
		return nil, newError("invalid_request", "the code and the code verifier are required")
	}
	p, err := c.discover(ctx)
	if err != nil {
		return nil, err
	}
	// A browser-only app sends no credential at all: client_id and the PKCE verifier are its only proof.
	options := []oauth2.AuthCodeOption{oauth2.VerifierOption(codeVerifier)}
	if c.signingKey != nil {
		assertion, err := c.clientAssertion(p.oauth2.Endpoint.TokenURL)
		if err != nil {
			return nil, err
		}
		options = append(options, oauth2.SetAuthURLParam("client_assertion_type", assertionType),
			oauth2.SetAuthURLParam("client_assertion", assertion))
	}
	token, err := p.oauth2.Exchange(context.WithValue(ctx, oauth2.HTTPClient, c.httpClient), code, options...)
	if err != nil {
		var retrieve *oauth2.RetrieveError
		if errors.As(err, &retrieve) {
			code, description := retrieve.ErrorCode, clean(retrieve.ErrorDescription)
			status := 0
			if retrieve.Response != nil {
				status = retrieve.Response.StatusCode
			}
			if !errorCode.MatchString(code) {
				code = "token_request_failed"
			}
			if description == "" {
				description = fmt.Sprintf("the token endpoint answered %d", status)
			}
			return nil, &Error{Code: code, Message: description, Status: status, Err: err}
		}
		return nil, &Error{Code: "network_error", Message: "Rante Login could not be reached", Err: err}
	}
	idToken, _ := token.Extra("id_token").(string)
	if idToken == "" || token.AccessToken == "" || !strings.EqualFold(token.Type(), "Bearer") {
		return nil, newError("invalid_token_response", "the token response has no ID token or no Bearer access token")
	}
	scope, _ := token.Extra("scope").(string)
	return &Tokens{AccessToken: token.AccessToken, TokenType: "Bearer", ExpiresIn: token.ExpiresIn, IDToken: idToken, Scope: scope}, nil
}

// ValidateIDToken validates an ID token before you trust it: the RS256 signature with the key its kid names in Rante
// Login's JWKS, iss, aud (and azp), exp (with clock skew), iat, sub, and the nonce you expect.
func (c *Client) ValidateIDToken(ctx context.Context, rawIDToken, nonce string) (*IDToken, error) {
	if nonce == "" {
		return nil, newError("invalid_request", "the expected nonce is required")
	}
	if rawIDToken == "" {
		return nil, newError("invalid_id_token", "the ID token is missing")
	}
	p, err := c.discover(ctx)
	if err != nil {
		return nil, err
	}
	token, err := p.verifier.Verify(oidc.ClientContext(ctx, c.httpClient), rawIDToken)
	if err != nil {
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			return nil, &Error{Code: "network_error", Message: "Rante Login's signing keys could not be fetched", Err: err}
		}
		return nil, &Error{Code: "invalid_id_token", Message: "the ID token failed validation (" + clean(err.Error()) + ")", Err: err}
	}
	if !safeEqual(token.Nonce, nonce) {
		return nil, newError("invalid_id_token", "the ID token was issued for another sign-in (nonce)")
	}
	var claims map[string]any
	if err := token.Claims(&claims); err != nil {
		return nil, &Error{Code: "invalid_id_token", Message: "the ID token's claims could not be read", Err: err}
	}
	azp, hasAzp := claims["azp"]
	if (hasAzp && azp != c.clientID) || (!hasAzp && len(token.Audience) > 1) {
		return nil, newError("invalid_id_token", "the ID token was issued to another app (azp)")
	}
	if token.Subject == "" || claims["iat"] == nil {
		return nil, newError("invalid_id_token", "the ID token has no sub or no iat")
	}
	return &IDToken{Subject: token.Subject, Claims: claims}, nil
}

// FetchUserInfo returns the person's claims from the userinfo endpoint, with the access token from the code
// exchange (15 minutes). Pass the ID token's sub as expectedSubject (or ""): OpenID Connect requires that both match.
func (c *Client) FetchUserInfo(ctx context.Context, accessToken, expectedSubject string) (*UserInfo, error) {
	if accessToken == "" {
		return nil, newError("invalid_request", "an access token is required")
	}
	p, err := c.discover(ctx)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, p.userinfoEndpoint, nil)
	if err != nil {
		return nil, &Error{Code: "userinfo_failed", Message: "the userinfo request could not be built", Err: err}
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	request.Header.Set("Accept", "application/json")
	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, &Error{Code: "network_error", Message: "Rante Login could not be reached", Err: err}
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized {
		return nil, &Error{Code: "invalid_token", Message: "the access token was refused: it expired, or the person removed their consent", Status: 401}
	}
	var claims map[string]any
	body, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	subject := ""
	if response.StatusCode == http.StatusOK && json.Unmarshal(body, &claims) == nil {
		subject, _ = claims["sub"].(string)
	}
	if subject == "" {
		return nil, &Error{Code: "userinfo_failed", Message: fmt.Sprintf("the userinfo endpoint answered %d", response.StatusCode), Status: response.StatusCode}
	}
	if expectedSubject != "" && subject != expectedSubject {
		return nil, newError("userinfo_subject_mismatch", "the userinfo sub is not the ID token's sub")
	}
	return &UserInfo{Subject: subject, Claims: claims}, nil
}

// FromBrowserSDKCookies returns the values the browser SDK (serverSide: true) kept for a redirect sign-in, from the
// request's cookies, or nil when any is missing. Clear the cookies (ClearBrowserSDKCookies) once read.
func FromBrowserSDKCookies(r *http.Request) *ExpectedTransaction {
	read := func(name string) string {
		if cookie, err := r.Cookie(name); err == nil {
			return cookie.Value
		}
		return ""
	}
	return expectedFrom(read(CookieState), read(CookieNonce), read(CookieCodeVerifier))
}

// FromCookieHeader is FromBrowserSDKCookies for a Cookie header.
func FromCookieHeader(header string) *ExpectedTransaction {
	r := &http.Request{Header: http.Header{"Cookie": {header}}}
	return FromBrowserSDKCookies(r)
}

// ClearBrowserSDKCookies deletes the browser SDK's three cookies: each sign-in uses them once.
func ClearBrowserSDKCookies(w http.ResponseWriter) {
	for _, name := range BrowserSDKCookies {
		http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1, SameSite: http.SameSiteLaxMode})
	}
}

func expectedFrom(state, nonce, verifier string) *ExpectedTransaction {
	if state == "" || nonce == "" || verifier == "" {
		return nil
	}
	return &ExpectedTransaction{State: state, Nonce: nonce, CodeVerifier: verifier}
}

// discover fetches the discovery document once (a failed fetch is tried again next time). go-oidc checks that it
// names this issuer, and its remote key set caches the keys and fetches them again when a token names a kid it
// doesn't know (key rotation).
func (c *Client) discover(ctx context.Context) (*provider, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.provider != nil {
		return c.provider, nil
	}
	// The provider keeps this context's HTTP client for its key set, so it must outlive the request.
	discovery, err := oidc.NewProvider(oidc.ClientContext(context.WithoutCancel(ctx), c.httpClient), c.issuer)
	if err != nil {
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			return nil, &Error{Code: "network_error", Message: "Rante Login could not be reached", Err: err}
		}
		return nil, &Error{Code: "discovery_failed", Message: "the discovery document could not be used: " + clean(err.Error()), Err: err}
	}
	var metadata struct {
		UserinfoEndpoint string `json:"userinfo_endpoint"`
	}
	if err := discovery.Claims(&metadata); err != nil || metadata.UserinfoEndpoint == "" || discovery.Endpoint().TokenURL == "" {
		return nil, newError("discovery_failed", "the discovery document lacks an endpoint")
	}
	skew := c.clockSkew
	c.provider = &provider{
		oidc: discovery,
		verifier: discovery.Verifier(&oidc.Config{
			ClientID:             c.clientID,
			SupportedSigningAlgs: []string{oidc.RS256},
			// go-oidc compares exp with Now exactly; checking against a clock that is ClockSkew behind allows the skew.
			Now: func() time.Time { return time.Now().Add(-skew) },
		}),
		oauth2: oauth2.Config{
			ClientID:    c.clientID,
			Endpoint:    oauth2.Endpoint{AuthURL: discovery.Endpoint().AuthURL, TokenURL: discovery.Endpoint().TokenURL, AuthStyle: oauth2.AuthStyleInParams},
			RedirectURL: c.redirectURI,
			Scopes:      strings.Fields(c.scope),
		},
		userinfoEndpoint: metadata.UserinfoEndpoint,
	}
	return c.provider, nil
}

// clientAssertion is private_key_jwt (RFC 7523): a short-lived JWT signed with the app's private key. iss and sub are
// the client ID, aud the token endpoint, the kid the Signed JWT key's prefix, and the jti unique (Rante Login accepts
// each assertion once).
func (c *Client) clientAssertion(tokenURL string) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: c.algorithm, Key: jose.JSONWebKey{Key: c.signingKey.PrivateKey, KeyID: c.signingKey.KeyPrefix}},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return "", &Error{Code: "invalid_configuration", Message: "the client assertion could not be signed", Err: err}
	}
	now := time.Now()
	assertion, err := josejwt.Signed(signer).Claims(josejwt.Claims{
		Issuer:    c.clientID,
		Subject:   c.clientID,
		Audience:  josejwt.Audience{tokenURL},
		IssuedAt:  josejwt.NewNumericDate(now),
		NotBefore: josejwt.NewNumericDate(now),
		Expiry:    josejwt.NewNumericDate(now.Add(assertionLifetime)),
		ID:        randomToken(),
	}).Serialize()
	if err != nil {
		return "", &Error{Code: "invalid_configuration", Message: "the client assertion could not be signed", Err: err}
	}
	return assertion, nil
}

// normalizeRedirectURI: Rante Login matches redirect URIs exactly, and stores them with the scheme and host in lower
// case.
func normalizeRedirectURI(value string) (string, error) {
	uri := strings.TrimSpace(value)
	uri = schemeAndHost.ReplaceAllStringFunc(uri, strings.ToLower)
	parsed, err := url.Parse(uri)
	if err == nil && parsed.IsAbs() && parsed.Host != "" && !strings.Contains(uri, "#") && parsed.User == nil && len(uri) <= 512 &&
		(parsed.Scheme == "https" || (parsed.Scheme == "http" && isLoopback(parsed.Hostname()))) {
		return uri, nil
	}
	return "", newError("invalid_configuration",
		"RedirectURI must be the absolute https URI registered on the app (http only for localhost or 127.0.0.1), without a fragment")
}

func normalizeScope(value string) (string, error) {
	if strings.TrimSpace(value) == "" {
		value = "openid profile email"
	}
	var parts []string
	for _, part := range strings.Fields(value) {
		if !slices.Contains(scopes, part) {
			return "", newError("invalid_configuration", "Scope must include openid and only these scopes: "+strings.Join(scopes, ", "))
		}
		if !slices.Contains(parts, part) {
			parts = append(parts, part)
		}
	}
	if !slices.Contains(parts, "openid") {
		return "", newError("invalid_configuration", "Scope must include openid and only these scopes: "+strings.Join(scopes, ", "))
	}
	return strings.Join(parts, " "), nil
}

func normalizeIssuer(value string) (string, error) {
	if value == "" {
		return DefaultIssuer, nil
	}
	parsed, err := url.Parse(value)
	if err == nil && parsed.RawQuery == "" && parsed.Fragment == "" &&
		(parsed.Scheme == "https" || (parsed.Scheme == "http" && isLoopback(parsed.Hostname()))) {
		return strings.TrimRight(value, "/"), nil
	}
	return "", newError("invalid_configuration", "Issuer must be an https URL")
}

func checkPrompt(prompt string) (string, error) {
	parts := strings.Fields(prompt)
	if len(parts) == 0 {
		return "", nil
	}
	for _, part := range parts {
		if !slices.Contains(prompts, part) || (part == "none" && len(parts) > 1) {
			return "", newError("invalid_request", "Prompt must be "+strings.Join(prompts, ", ")+" (none alone)")
		}
	}
	return strings.Join(parts, " "), nil
}

func isLoopback(host string) bool { return host == "localhost" || host == "127.0.0.1" }

func randomToken() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return base64.RawURLEncoding.EncodeToString(bytes)
}

func safeEqual(a, b string) bool {
	return a != "" && b != "" && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func clean(value string) string {
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, value)
	if len(value) > 300 {
		value = value[:300]
	}
	return value
}
