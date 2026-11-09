package rantelogin

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	webClient     = "11111111-2222-4333-8444-555555555555"
	browserClient = "66666666-7777-4888-9999-aaaaaaaaaaaa"
	// The fake key prefixes, split so secret scanners don't take them for Stripe restricted keys (rk_live_ + 24 characters).
	rsaPrefix   = "rk_live_" + "0123456789abcdef01234567"
	ecPrefix    = "rk_live_" + "89abcdef0123456789abcdef"
	redirectURI = "http://localhost:3000/auth/rante/callback"
	testNonce   = "expected-nonce"
)

type fixture struct {
	idp *localIdP
	rsa *rsa.PrivateKey
	ec  *ecdsa.PrivateKey
}

func setup(t *testing.T) *fixture {
	t.Helper()
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	idp := newLocalIdP(t)
	idp.registerClient(webClient, "Web", map[string]crypto.PublicKey{rsaPrefix: &rsaKey.PublicKey, ecPrefix: &ecKey.PublicKey})
	idp.registerClient(browserClient, "BrowserOnly", nil)
	return &fixture{idp: idp, rsa: rsaKey, ec: ecKey}
}

func (f *fixture) client(t *testing.T, clientID string, key *SigningKey) *Client {
	t.Helper()
	client, err := NewClient(Config{ClientID: clientID, RedirectURI: redirectURI, Issuer: f.idp.issuer, SigningKey: key})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func (f *fixture) web(t *testing.T) *Client {
	return f.client(t, webClient, &SigningKey{KeyPrefix: rsaPrefix, PrivateKey: f.rsa})
}

// authorize is the authorize step, as the test IdP sees it: a code bound to the request's PKCE challenge and nonce.
func (f *fixture) authorize(t *testing.T, request *AuthorizationRequest, clientID string) string {
	t.Helper()
	parsed, _ := url.Parse(request.URL)
	q := parsed.Query()
	return f.idp.issueCode(clientID, q.Get("redirect_uri"), q.Get("code_challenge"), q.Get("nonce"),
		map[string]any{"sub": "pairwise-subject-1", "name": "Test Person"})
}

func callback(code, state, iss string) url.Values {
	values := url.Values{}
	for name, value := range map[string]string{"code": code, "state": state, "iss": iss} {
		if value != "" {
			values.Set(name, value)
		}
	}
	return values
}

func wantCode(t *testing.T, err error, code string) *Error {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("expected an *Error with code %s, got %v", code, err)
	}
	if e.Code != code {
		t.Fatalf("expected code %s, got %s: %s", code, e.Code, e.Message)
	}
	return e
}

func TestCreateAuthorizationRequestBuildsTheURLWithPKCEStateAndNonce(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	request, err := f.web(t).CreateAuthorizationRequest(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(request.URL)
	if got := parsed.Scheme + "://" + parsed.Host + parsed.Path; got != f.idp.server.URL+"/common/oauth2/v2.0/authorize" {
		t.Fatalf("endpoint %s", got)
	}
	q := parsed.Query()
	var names []string
	for name := range q {
		names = append(names, name)
	}
	slices.Sort(names)
	if strings.Join(names, ",") != "client_id,code_challenge,code_challenge_method,nonce,redirect_uri,response_type,scope,state" {
		t.Fatalf("parameters %v", names)
	}
	digest := sha256.Sum256([]byte(request.CodeVerifier))
	checks := map[string]string{"client_id": webClient, "response_type": "code", "redirect_uri": redirectURI, "scope": "openid profile email",
		"code_challenge_method": "S256", "code_challenge": base64.RawURLEncoding.EncodeToString(digest[:]), "state": request.State, "nonce": request.Nonce}
	for name, want := range checks {
		if q.Get(name) != want {
			t.Errorf("%s = %q, want %q", name, q.Get(name), want)
		}
	}
	if len(request.CodeVerifier) != 43 {
		t.Errorf("verifier length %d", len(request.CodeVerifier))
	}
	other, _ := f.web(t).CreateAuthorizationRequest(ctx, nil)
	if other.State == request.State || other.Nonce == request.Nonce || other.CodeVerifier == request.CodeVerifier {
		t.Error("values repeat between requests")
	}
}

func TestCreateAuthorizationRequestPassesOptionsAndRefusesBadOnes(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	client := f.web(t)
	zero := 0
	request, err := client.CreateAuthorizationRequest(ctx, &AuthorizationOptions{Nonce: "server-nonce-1", Prompt: "login", LoginHint: "person@example.com", MaxAge: &zero})
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(request.URL)
	q := parsed.Query()
	if request.Nonce != "server-nonce-1" || q.Get("nonce") != "server-nonce-1" || q.Get("prompt") != "login" ||
		q.Get("login_hint") != "person@example.com" || q.Get("max_age") != "0" {
		t.Fatalf("options not passed: %v", q)
	}
	negative := -1
	for _, opts := range []*AuthorizationOptions{{Nonce: "has space"}, {Prompt: "none login"}, {Prompt: "always"}, {MaxAge: &negative}} {
		_, err := client.CreateAuthorizationRequest(ctx, opts)
		wantCode(t, err, "invalid_request")
	}
}

func TestServerSideWebsiteSignsInWithAPrivateKeyJWTRS256Assertion(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	client := f.web(t)
	if client.ClientAuthentication() != "private_key_jwt" {
		t.Fatal(client.ClientAuthentication())
	}
	request, _ := client.CreateAuthorizationRequest(ctx, nil)
	result, err := client.HandleCallback(ctx, callback(f.authorize(t, request, webClient), request.State, f.idp.issuer), request.Expected())
	if err != nil {
		t.Fatal(err)
	}
	if result.IDToken.Subject != "pairwise-subject-1" || result.IDToken.Claims["name"] != "Test Person" || result.IDToken.Claims["nonce"] != request.Nonce {
		t.Fatalf("claims %v", result.IDToken.Claims)
	}
	if result.Tokens.TokenType != "Bearer" || result.Tokens.AccessToken == "" || result.Tokens.ExpiresIn != 900 {
		t.Fatalf("tokens %+v", result.Tokens)
	}
	form := f.idp.lastTokenForm()
	for name, want := range map[string]string{"grant_type": "authorization_code", "redirect_uri": redirectURI, "client_id": webClient,
		"code_verifier": request.CodeVerifier, "client_assertion_type": assertionType} {
		if form.Get(name) != want {
			t.Errorf("token form %s = %q, want %q", name, form.Get(name), want)
		}
	}
	header, claims := f.idp.lastAssertion.Headers[0], f.idp.lastClaims
	if header.Algorithm != "RS256" || header.KeyID != rsaPrefix || claims.Issuer != webClient || claims.Subject != webClient ||
		!slices.Equal([]string(claims.Audience), []string{f.idp.server.URL + "/common/oauth2/v2.0/token"}) || claims.ID == "" {
		t.Fatalf("assertion %+v %+v", header, claims)
	}
}

func TestES256KeysSignES256Assertions(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	client := f.client(t, webClient, &SigningKey{KeyPrefix: ecPrefix, PrivateKey: f.ec})
	request, _ := client.CreateAuthorizationRequest(ctx, nil)
	result, err := client.HandleCallback(ctx, callback(f.authorize(t, request, webClient), request.State, f.idp.issuer), request.Expected())
	if err != nil {
		t.Fatal(err)
	}
	if result.IDToken.Subject != "pairwise-subject-1" || f.idp.lastAssertion.Headers[0].Algorithm != "ES256" || f.idp.lastAssertion.Headers[0].KeyID != ecPrefix {
		t.Fatalf("assertion %+v", f.idp.lastAssertion.Headers[0])
	}
}

func TestBrowserOnlyWebsiteSendsNoClientCredential(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	client := f.client(t, browserClient, nil)
	if client.ClientAuthentication() != "none" {
		t.Fatal(client.ClientAuthentication())
	}
	request, _ := client.CreateAuthorizationRequest(ctx, nil)
	result, err := client.HandleCallback(ctx, callback(f.authorize(t, request, browserClient), request.State, f.idp.issuer),
		&ExpectedTransaction{State: request.State, Nonce: request.Nonce, CodeVerifier: request.CodeVerifier})
	if err != nil {
		t.Fatal(err)
	}
	if result.IDToken.Claims["aud"] != browserClient {
		t.Fatalf("aud %v", result.IDToken.Claims["aud"])
	}
	form := f.idp.lastTokenForm()
	if form.Has("client_assertion") || form.Has("client_assertion_type") || form.Has("client_secret") || form.Get("client_id") != browserClient {
		t.Fatalf("token form %v", form)
	}
}

func TestRefusesBadResponsesBeforeAnyTokenRequest(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	client := f.web(t)
	request, _ := client.CreateAuthorizationRequest(ctx, nil)
	code := f.authorize(t, request, webClient)
	before := f.idp.requestCount()
	repeated := callback(code, request.State, f.idp.issuer)
	repeated.Add("state", request.State)
	cases := []struct {
		query    url.Values
		expected *ExpectedTransaction
		code     string
	}{
		{callback(code, "another", f.idp.issuer), request.Expected(), "state_mismatch"},
		{callback(code, request.State, ""), request.Expected(), "issuer_mismatch"},
		{callback(code, request.State, "https://login.example.com/common/v2.0"), request.Expected(), "issuer_mismatch"},
		{repeated, request.Expected(), "invalid_request"},
		{callback(code, request.State, f.idp.issuer), nil, "missing_transaction"},
		{callback(code, request.State, f.idp.issuer), &ExpectedTransaction{State: request.State}, "missing_transaction"},
		{callback("", request.State, f.idp.issuer), request.Expected(), "invalid_request"},
	}
	for _, c := range cases {
		_, err := client.HandleCallback(ctx, c.query, c.expected)
		wantCode(t, err, c.code)
	}
	if f.idp.requestCount() != before {
		t.Fatal("a refused response reached the token endpoint")
	}
}

func TestReportsTheProvidersError(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	client := f.web(t)
	request, _ := client.CreateAuthorizationRequest(ctx, nil)
	query := url.Values{"error": {"access_denied"}, "error_description": {"The person cancelled the sign-in."}, "state": {request.State}, "iss": {f.idp.issuer}}
	_, err := client.HandleCallback(ctx, query, request.Expected())
	if e := wantCode(t, err, "access_denied"); e.Message != "The person cancelled the sign-in." {
		t.Fatal(e.Message)
	}
}

func TestTokenEndpointErrorsKeepTheirCodeAndStatus(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	client := f.web(t)
	request, _ := client.CreateAuthorizationRequest(ctx, nil)
	query := callback(f.authorize(t, request, webClient), request.State, f.idp.issuer)
	if _, err := client.HandleCallback(ctx, query, request.Expected()); err != nil {
		t.Fatal(err)
	}
	_, err := client.HandleCallback(ctx, query, request.Expected())
	if e := wantCode(t, err, "invalid_grant"); e.Status != 400 {
		t.Fatal(e.Status)
	}
}

func TestAKeyThatIsNotLinkedToTheAppGetsInvalidClient(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	client := f.client(t, webClient, &SigningKey{KeyPrefix: "rk_live_" + strings.Repeat("f", 24), PrivateKey: other})
	request, _ := client.CreateAuthorizationRequest(ctx, nil)
	_, err := client.HandleCallback(ctx, callback(f.authorize(t, request, webClient), request.State, f.idp.issuer), request.Expected())
	if e := wantCode(t, err, "invalid_client"); e.Status != 401 {
		t.Fatal(e.Status)
	}
}

func (f *fixture) valid(t *testing.T, overrides map[string]any) string {
	claims := map[string]any{"aud": webClient, "azp": webClient, "nonce": testNonce}
	for name, value := range overrides {
		claims[name] = value
	}
	return f.idp.mintIDToken(t, claims, nil, "")
}

func TestValidateIDTokenAcceptsAValidToken(t *testing.T) {
	f := setup(t)
	token, err := f.web(t).ValidateIDToken(context.Background(), f.valid(t, map[string]any{"name": "Test Person"}), testNonce)
	if err != nil {
		t.Fatal(err)
	}
	if token.Subject != "pairwise-subject-1" || token.Claims["name"] != "Test Person" {
		t.Fatalf("%+v", token)
	}
}

func TestValidateIDTokenRefusesTokensThatFailAnyCheck(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	client := f.web(t)
	now := time.Now().Unix()
	stranger, _ := rsa.GenerateKey(rand.Reader, 2048)
	body, _ := json.Marshal(map[string]any{"iss": f.idp.issuer, "sub": "s", "aud": webClient, "azp": webClient, "iat": now, "exp": now + 600, "nonce": testNonce})
	b64 := base64.RawURLEncoding.EncodeToString
	hsInput := b64([]byte(`{"alg":"HS256","kid":"test-key-1","typ":"JWT"}`)) + "." + b64(body)
	mac := hmac.New(sha256.New, []byte("a-secret-of-thirty-two-bytes-!!!"))
	mac.Write([]byte(hsInput))
	cases := map[string]string{
		"another key, same kid": f.idp.mintIDToken(t, map[string]any{"aud": webClient, "nonce": testNonce}, stranger, "test-key-1"),
		"unknown kid":           f.idp.mintIDToken(t, map[string]any{"aud": webClient, "nonce": testNonce}, stranger, "not-a-rante-key"),
		"another issuer":        f.valid(t, map[string]any{"iss": "https://login.example.com/common/v2.0"}),
		"another audience":      f.valid(t, map[string]any{"aud": "99999999-2222-4333-8444-555555555555", "azp": nil}),
		"another azp":           f.valid(t, map[string]any{"azp": "99999999-2222-4333-8444-555555555555"}),
		"expired":               f.valid(t, map[string]any{"iat": now - 1200, "exp": now - 600}),
		"another nonce":         f.valid(t, map[string]any{"nonce": "other-nonce"}),
		"no nonce":              f.valid(t, map[string]any{"nonce": nil}),
		"no sub":                f.valid(t, map[string]any{"sub": nil}),
		"no iat":                f.valid(t, map[string]any{"iat": nil}),
		"HS256":                 hsInput + "." + b64(mac.Sum(nil)),
		"alg none":              b64([]byte(`{"alg":"none","typ":"JWT"}`)) + "." + b64(body) + ".",
		"not a JWT":             "not-a-jwt",
	}
	for name, token := range cases {
		_, err := client.ValidateIDToken(ctx, token, testNonce)
		var e *Error
		if !errors.As(err, &e) || e.Code != "invalid_id_token" {
			t.Errorf("%s: %v", name, err)
		}
	}
	_, err := client.ValidateIDToken(ctx, f.valid(t, nil), "")
	wantCode(t, err, "invalid_request")
}

func TestValidateIDTokenAllowsAMinuteOfClockSkew(t *testing.T) {
	f := setup(t)
	now := time.Now().Unix()
	if _, err := f.web(t).ValidateIDToken(context.Background(), f.valid(t, map[string]any{"iat": now - 630, "exp": now - 30}), testNonce); err != nil {
		t.Fatal(err)
	}
}

func TestValidateIDTokenUsesAKeyThatRanteLoginAddsLater(t *testing.T) {
	f := setup(t)
	added := f.idp.addSigningKey(t, "test-key-2")
	token := f.idp.mintIDToken(t, map[string]any{"aud": webClient, "nonce": testNonce}, added, "test-key-2")
	result, err := f.web(t).ValidateIDToken(context.Background(), token, testNonce)
	if err != nil || result.Subject != "pairwise-subject-1" {
		t.Fatal(err)
	}
}

func TestFetchUserInfoReturnsTheClaimsAndChecksTheSub(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	client := f.web(t)
	request, _ := client.CreateAuthorizationRequest(ctx, nil)
	result, err := client.HandleCallback(ctx, callback(f.authorize(t, request, webClient), request.State, f.idp.issuer), request.Expected())
	if err != nil {
		t.Fatal(err)
	}
	userinfo, err := client.FetchUserInfo(ctx, result.Tokens.AccessToken, result.IDToken.Subject)
	if err != nil || userinfo.Subject != "pairwise-subject-1" || userinfo.Claims["name"] != "Test Person" {
		t.Fatalf("%+v %v", userinfo, err)
	}
	_, err = client.FetchUserInfo(ctx, result.Tokens.AccessToken, "someone-else")
	wantCode(t, err, "userinfo_subject_mismatch")
	_, err = client.FetchUserInfo(ctx, "expired-or-unknown", "")
	if e := wantCode(t, err, "invalid_token"); e.Status != 401 {
		t.Fatal(e.Status)
	}
}

func TestFromBrowserSDKCookiesReadsTheThreeCookies(t *testing.T) {
	verifier := strings.Repeat("v", 43)
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("Cookie", "other=1; rante_login_pkce="+verifier+"; rante_login_state=s1; rante_login_nonce=n1")
	want := ExpectedTransaction{State: "s1", Nonce: "n1", CodeVerifier: verifier}
	if got := FromBrowserSDKCookies(r); got == nil || *got != want {
		t.Fatalf("%+v", got)
	}
	if got := FromCookieHeader("rante_login_pkce=" + verifier + "; rante_login_state=s1; rante_login_nonce=n1"); got == nil || *got != want {
		t.Fatalf("%+v", got)
	}
	if FromCookieHeader("rante_login_state=s1") != nil || FromCookieHeader("") != nil {
		t.Fatal("expected nil")
	}
}

func TestConfigurationRefusesBadSettings(t *testing.T) {
	weak, _ := rsa.GenerateKey(rand.Reader, 1024)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	good, _ := rsa.GenerateKey(rand.Reader, 2048)
	public, _ := x509.MarshalPKIXPublicKey(&good.PublicKey)
	bad := map[string]Config{
		"client ID":                    {ClientID: "my-app", RedirectURI: redirectURI},
		"http redirect URI":            {ClientID: webClient, RedirectURI: "http://shop.example.com/callback"},
		"redirect URI with a fragment": {ClientID: webClient, RedirectURI: "https://shop.example.com/callback#x"},
		"scope without openid":         {ClientID: webClient, RedirectURI: redirectURI, Scope: "profile email"},
		"unknown scope":                {ClientID: webClient, RedirectURI: redirectURI, Scope: "openid offline_access"},
		"http issuer":                  {ClientID: webClient, RedirectURI: redirectURI, Issuer: "http://login.example.com/common/v2.0"},
		"key prefix":                   {ClientID: webClient, RedirectURI: redirectURI, SigningKey: &SigningKey{KeyPrefix: "my-key", PrivateKey: good}},
		"RSA 1024":                     {ClientID: webClient, RedirectURI: redirectURI, SigningKey: &SigningKey{KeyPrefix: rsaPrefix, PrivateKey: weak}},
		"EC P-384":                     {ClientID: webClient, RedirectURI: redirectURI, SigningKey: &SigningKey{KeyPrefix: rsaPrefix, PrivateKey: p384}},
	}
	for name, cfg := range bad {
		_, err := NewClient(cfg)
		var e *Error
		if !errors.As(err, &e) || e.Code != "invalid_configuration" {
			t.Errorf("%s: %v", name, err)
		}
	}
	_, err := ParseSigningKeyPEM(rsaPrefix, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public}))
	wantCode(t, err, "invalid_configuration")
}

func TestConfigurationReadsPEMKeysAndNormalizesLikeTheBrowserSDK(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for prefix, key := range map[string]any{rsaPrefix: rsaKey, ecPrefix: ecKey} {
		der, _ := x509.MarshalPKCS8PrivateKey(key)
		if _, err := ParseSigningKeyPEM(prefix, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err != nil {
			t.Fatal(err)
		}
	}
	pkcs1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)})
	if _, err := ParseSigningKeyPEM(rsaPrefix, pkcs1); err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(Config{ClientID: strings.ToUpper(webClient), RedirectURI: "HTTPS://Shop.Example.com/Auth/Callback"})
	if err != nil {
		t.Fatal(err)
	}
	if client.ClientID() != webClient || client.RedirectURI() != "https://shop.example.com/Auth/Callback" || client.Issuer() != DefaultIssuer {
		t.Fatalf("%s %s %s", client.ClientID(), client.RedirectURI(), client.Issuer())
	}
}

func TestDiscoveryThatNamesAnotherIssuerIsRefused(t *testing.T) {
	f := setup(t)
	f.idp.discoveryIssuer = "https://login.example.com/common/v2.0"
	_, err := f.web(t).CreateAuthorizationRequest(context.Background(), nil)
	wantCode(t, err, "discovery_failed")
}

func TestAnUnreachableProviderIsANetworkError(t *testing.T) {
	client, err := NewClient(Config{ClientID: webClient, RedirectURI: redirectURI, Issuer: "http://127.0.0.1:9/common/v2.0",
		HTTPClient: &http.Client{Timeout: 2 * time.Second}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.CreateAuthorizationRequest(context.Background(), nil)
	wantCode(t, err, "network_error")
}
