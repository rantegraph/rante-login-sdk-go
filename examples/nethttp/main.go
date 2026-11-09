// Sign in with Rante: a net/http website that signs people in with the Rante Login SDK for Go.
//
// Three ways in, all finished and checked on this server:
//   - "Sign in with Rante" button (public/signin.js): the browser SDK with serverSide: true. In Chrome and Edge it
//     uses FedCM and posts the ID token to /auth/rante/fedcm; elsewhere it redirects, and the code comes back to the
//     redirect URI with the SDK's rante_login_* cookies.
//   - "Sign in without JavaScript" link: /auth/rante/sign-in builds the authorize request here
//     (CreateAuthorizationRequest) and keeps its state, nonce and PKCE verifier in the session.
//   - Either redirect ends at the redirect URI, where HandleCallback exchanges the code (private_key_jwt or PKCE
//     alone) and validates the ID token.
package main

import (
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	rantelogin "github.com/rantegraph/rante-login-sdk-go"
)

const (
	sdkSrc        = "https://login.rante.com/sdk/v1/rante-login.js"
	sdkIntegrity  = "sha384-2W12/NktCjRqFuXWiUtHr1yEtdrjBlCRWnJ+//FZMiqd1KRX/K+YMWLoMgF9R7wf"
	sessionCookie = "rante_nethttp_session"
)

var csp = strings.Join([]string{
	"default-src 'self'",
	"script-src 'self' https://login.rante.com",  // the browser SDK, pinned by its integrity hash
	"connect-src 'self' https://login.rante.com", // FedCM fetches the identity provider's configuration
	"img-src 'self' data:",
	"style-src 'self'",
	"base-uri 'none'",
	"form-action 'self'",
	"frame-ancestors 'none'",
}, "; ")

//go:embed public
var public embed.FS

// session is one browser's server-side session.
type session struct {
	nonce       string
	started     *rantelogin.ExpectedTransaction
	claims      map[string]any
	accessToken string
	method      string
	signedInAt  time.Time
	newAccount  bool
	lastSeen    time.Time
}

// account is one account on this website. A person's first "Sign in with Rante" here is their sign-up: the account is
// created from the claims they agreed to share, and every later sign-in finds it by sub. A real website keeps accounts
// in its database; this example keeps them in memory, so they're gone when the server restarts.
type account struct {
	id, sub, name, email    string
	createdAt, lastSignInAt time.Time
}

type app struct {
	rante         *rantelogin.Client
	siteOrigin    string
	secureCookies bool
	mu            sync.Mutex
	sessions      map[string]*session
	accounts      map[string]*account // by sub
}

func main() {
	keyPrefix, keyFile := os.Getenv("RANTE_LOGIN_KEY_PREFIX"), os.Getenv("RANTE_LOGIN_PRIVATE_KEY_FILE")
	if (keyPrefix == "") != (keyFile == "") {
		log.Fatal("Set both RANTE_LOGIN_KEY_PREFIX and RANTE_LOGIN_PRIVATE_KEY_FILE (a server-side website), or neither (browser-only).")
	}
	cfg := rantelogin.Config{
		ClientID:    os.Getenv("RANTE_LOGIN_CLIENT_ID"),
		RedirectURI: envOr("RANTE_LOGIN_REDIRECT_URI", "http://localhost:3000/auth/rante/callback"),
		Scope:       os.Getenv("RANTE_LOGIN_SCOPE"),
	}
	if keyFile != "" {
		pemBytes, err := os.ReadFile(keyFile)
		if err != nil {
			log.Fatal(err)
		}
		if cfg.SigningKey, err = rantelogin.ParseSigningKeyPEM(keyPrefix, pemBytes); err != nil {
			log.Fatal(err)
		}
	}
	rante, err := rantelogin.NewClient(cfg)
	if err != nil {
		log.Fatal(err)
	}
	redirect, _ := url.Parse(rante.RedirectURI())
	a := &app{rante: rante, siteOrigin: redirect.Scheme + "://" + redirect.Host, secureCookies: redirect.Scheme == "https", sessions: map[string]*session{},
		accounts: map[string]*account{}}
	if slices.Contains([]string{"/", "/auth/rante/sign-in", "/auth/rante/fedcm", "/auth/sign-out", "/userinfo", "/signin.js", "/style.css"}, redirect.Path) {
		log.Fatal("Give RANTE_LOGIN_REDIRECT_URI a path of its own, for example /auth/rante/callback.")
	}

	mux := http.NewServeMux()
	assets, _ := fs.Sub(public, "public")
	mux.Handle("GET /signin.js", http.FileServerFS(assets))
	mux.Handle("GET /style.css", http.FileServerFS(assets))
	mux.HandleFunc("GET /{$}", a.home)
	mux.HandleFunc("GET /auth/rante/sign-in", a.signIn)
	mux.HandleFunc("GET "+redirect.EscapedPath(), a.callback)
	mux.HandleFunc("POST /auth/rante/fedcm", a.fedcm)
	mux.HandleFunc("GET /userinfo", a.userinfo)
	mux.HandleFunc("POST /auth/sign-out", a.signOut)

	port := envOr("PORT", redirect.Port())
	if port == "" {
		port = "3000"
	}
	address := envOr("HOST", "127.0.0.1") + ":" + port
	fmt.Printf("Sign in with Rante (net/http example): %s/ - client %s, %s\n", a.siteOrigin, rante.ClientID(), rante.ClientAuthentication())
	log.Fatal(http.ListenAndServe(address, securityHeaders(mux)))
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", csp)
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

func (a *app) home(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	s := a.session(w, r, true)
	if s.claims != nil {
		render(w, http.StatusOK, signedInPage, map[string]any{"Name": s.claims["name"], "Method": s.method,
			"SignedInAt": s.signedInAt.UTC().Format(time.RFC3339), "Claims": rows(s.claims),
			"Account": a.accountView(s.claims), "NewAccount": s.newAccount})
		return
	}
	// FedCM hands the ID token to the page, so its nonce must be one the page can't choose: issue it here and keep it
	// in the session. The browser SDK sends the same nonce in its redirect flow.
	a.mu.Lock()
	if s.nonce == "" {
		s.nonce = randomToken()
	}
	nonce := s.nonce
	a.mu.Unlock()
	render(w, http.StatusOK, signInPage, map[string]any{"ClientID": a.rante.ClientID(), "RedirectURI": a.rante.RedirectURI(),
		"Scope": a.rante.Scope(), "Nonce": nonce, "SDKSrc": sdkSrc, "SDKIntegrity": sdkIntegrity})
}

// signIn: the server starts the sign-in, no JavaScript needed.
func (a *app) signIn(w http.ResponseWriter, r *http.Request) {
	s := a.session(w, r, true)
	request, err := a.rante.CreateAuthorizationRequest(r.Context(), nil)
	if err != nil {
		a.fail(w, err)
		return
	}
	a.mu.Lock()
	s.started = request.Expected()
	a.mu.Unlock()
	http.Redirect(w, r, request.URL, http.StatusSeeOther)
}

// callback is the redirect URI: Rante Login comes back with ?code=...&state=...&iss=... (or ?error=...).
func (a *app) callback(w http.ResponseWriter, r *http.Request) {
	// A sign-in this server started is in the session; one the browser SDK started is in its cookies. Both are used once.
	s := a.session(w, r, true)
	a.mu.Lock()
	started := s.started
	s.started = nil
	a.mu.Unlock()
	fromBrowser := rantelogin.FromBrowserSDKCookies(r)
	rantelogin.ClearBrowserSDKCookies(w)
	query := r.URL.Query()
	byServer := started != nil && started.State == query.Get("state")
	expected := fromBrowser
	if byServer || fromBrowser == nil {
		expected = started
	}
	result, err := a.rante.HandleCallback(r.Context(), query, expected)
	if err != nil {
		a.fail(w, err)
		return
	}
	method := "Redirect started by the browser SDK"
	if byServer {
		method = "Redirect started by the server"
	}
	a.startSession(w, r, result.IDToken.Claims, result.Tokens.AccessToken, method+", "+a.rante.ClientAuthentication())
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// fedcm: the page posts the ID token the browser's account dialog returned.
func (a *app) fedcm(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Origin") != a.siteOrigin {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "origin_not_allowed"})
		return
	}
	s := a.session(w, r, false)
	nonce := ""
	if s != nil {
		a.mu.Lock()
		nonce = s.nonce
		a.mu.Unlock()
	}
	if nonce == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing_transaction"})
		return
	}
	var body struct {
		IDToken string `json:"idToken"`
	}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		_ = json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&body)
	}
	token, err := a.rante.ValidateIDToken(r.Context(), body.IDToken, nonce)
	if err != nil {
		log.Printf("FedCM sign-in failed: %v", err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": codeOf(err)})
		return
	}
	a.startSession(w, r, token.Claims, "", "FedCM")
	w.WriteHeader(http.StatusNoContent)
}

// userinfo: the person's claims from Rante Login's userinfo endpoint, with the access token from the code exchange.
func (a *app) userinfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	s := a.session(w, r, false)
	if s == nil || s.claims == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if s.accessToken == "" {
		render(w, http.StatusOK, messagePage, map[string]any{"Title": "Userinfo",
			"Message": "FedCM sign-ins return only an ID token, so there is no access token to call userinfo with."})
		return
	}
	subject, _ := s.claims["sub"].(string)
	info, err := a.rante.FetchUserInfo(r.Context(), s.accessToken, subject)
	if err != nil {
		a.fail(w, err)
		return
	}
	render(w, http.StatusOK, userinfoPage, map[string]any{"Claims": rows(info.Claims)})
}

func (a *app) signOut(w http.ResponseWriter, r *http.Request) {
	if origin := r.Header.Get("Origin"); origin != "" && origin != a.siteOrigin {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	// Signs out of this website only; the person stays signed in to Rante.
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		a.mu.Lock()
		delete(a.sessions, cookie.Value)
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: a.secureCookies})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// startSession gives the person who signed in a new session: its ID changes, so a session fixed before sign-in is
// worthless. The sign-in also creates or finds their account on this website.
func (a *app) startSession(w http.ResponseWriter, r *http.Request, claims map[string]any, accessToken, method string) {
	a.mu.Lock()
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		delete(a.sessions, cookie.Value)
	}
	created := a.registerOrFindLocked(claims)
	id := randomToken()
	a.sessions[id] = &session{claims: claims, accessToken: accessToken, method: method, signedInAt: time.Now(),
		newAccount: created, lastSeen: time.Now()}
	a.mu.Unlock()
	a.setSessionCookie(w, id)
}

// registerOrFindLocked creates the person's account on the first sign-in, or finds it by sub; true when it was created
// now. The caller holds a.mu.
func (a *app) registerOrFindLocked(claims map[string]any) bool {
	sub, _ := claims["sub"].(string)
	name, _ := claims["name"].(string)
	email, _ := claims["email"].(string)
	now := time.Now().UTC()
	acct, found := a.accounts[sub]
	if !found {
		acct = &account{id: randomID(), sub: sub, createdAt: now}
		a.accounts[sub] = acct
	}
	// Keep the details the person shares this time. Rante shares an email only once it's verified.
	if name != "" {
		acct.name = name
	}
	if email != "" {
		acct.email = email
	}
	acct.lastSignInAt = now
	return !found
}

// accountView copies the signed-in person's account for the page, or returns nil when it's gone (the example keeps
// accounts in memory).
func (a *app) accountView(claims map[string]any) map[string]string {
	sub, _ := claims["sub"].(string)
	a.mu.Lock()
	defer a.mu.Unlock()
	acct, found := a.accounts[sub]
	if !found {
		return nil
	}
	return map[string]string{"ID": acct.id, "Sub": acct.sub, "Name": acct.name, "Email": acct.email,
		"Created": acct.createdAt.Format(time.RFC3339), "LastSignIn": acct.lastSignInAt.Format(time.RFC3339)}
}

func (a *app) session(w http.ResponseWriter, r *http.Request, create bool) *session {
	a.mu.Lock()
	defer a.mu.Unlock()
	for id, s := range a.sessions {
		if time.Since(s.lastSeen) > 8*time.Hour {
			delete(a.sessions, id)
		}
	}
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		if s, ok := a.sessions[cookie.Value]; ok {
			s.lastSeen = time.Now()
			return s
		}
	}
	if !create {
		return nil
	}
	s := &session{lastSeen: time.Now()}
	id := randomToken()
	a.sessions[id] = s
	a.setSessionCookie(w, id)
	return s
}

func (a *app) setSessionCookie(w http.ResponseWriter, id string) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: id, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: a.secureCookies})
}

func (a *app) fail(w http.ResponseWriter, err error) {
	// Log the reason, never the code, the cookies or a token.
	log.Printf("Sign-in failed: %v", err)
	code, message := codeOf(err), "Something went wrong on this server. Its log has the details."
	var e *rantelogin.Error
	if errors.As(err, &e) {
		message = e.Message
	}
	if code == "access_denied" {
		message = "The sign-in was cancelled on the Rante Login page."
	}
	render(w, http.StatusBadRequest, errorPage, map[string]any{"Code": code, "Message": message})
}

func codeOf(err error) string {
	var e *rantelogin.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return "server_error"
}

type row struct{ Name, Value string }

func rows(claims map[string]any) []row {
	names := make([]string, 0, len(claims))
	for name := range claims {
		names = append(names, name)
	}
	slices.Sort(names)
	out := make([]row, 0, len(names))
	for _, name := range names {
		value := fmt.Sprint(claims[name])
		if _, isText := claims[name].(string); !isText {
			if encoded, err := json.Marshal(claims[name]); err == nil {
				value = string(encoded)
			}
		}
		out = append(out, row{name, value})
	}
	return out
}

func render(w http.ResponseWriter, status int, page *template.Template, data map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := page.Execute(w, data); err != nil {
		log.Printf("render: %v", err)
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func randomToken() string {
	bytes := make([]byte, 32)
	_, _ = rand.Read(bytes)
	return base64.RawURLEncoding.EncodeToString(bytes)
}

// randomID is a random version 4 UUID.
func randomID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

const layout = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{block "title" .}}{{end}} - net/http example</title>
  <link rel="stylesheet" href="/style.css">
</head>
<body>
  <main>
{{block "body" .}}{{end}}
  </main>
</body>
</html>
`

func page(content string) *template.Template {
	return template.Must(template.Must(template.New("layout").Parse(layout)).Parse(content))
}

var (
	signInPage = page(`{{define "title"}}Sign in with Rante{{end}}{{define "body"}}
    <h1>Sign in with Rante</h1>
    <p>net/http example of the Rante Login SDK for Go: the server finishes the sign-in and validates the ID token.</p>
    <div id="rante-signin" data-client-id="{{.ClientID}}" data-redirect-uri="{{.RedirectURI}}" data-scope="{{.Scope}}" data-nonce="{{.Nonce}}"></div>
    <p id="rante-signin-status" role="status"></p>
    <p><a href="/auth/rante/sign-in">Sign in without JavaScript</a> (the server starts the sign-in)</p>
    <script src="{{.SDKSrc}}" integrity="{{.SDKIntegrity}}" crossorigin="anonymous"></script>
    <script src="/signin.js"></script>{{end}}`)

	signedInPage = page(`{{define "title"}}Signed in{{end}}{{define "body"}}
    <h1>Signed in{{with .Name}} as {{.}}{{end}}</h1>
    <p>Signed in with: <strong>{{.Method}}</strong>, {{.SignedInAt}}</p>
    <h2>Your account on this website</h2>
    {{with .Account}}<p>{{if $.NewAccount}}Created at this sign-in from your Rante account: no separate sign-up form, and no
       password for this website.{{else}}Welcome back: this sign-in found your account by its Rante ID.{{end}}</p>
    <table><tbody>
      <tr><th>Account ID</th><td>{{.ID}}</td></tr>
      <tr><th>Linked Rante ID (<code>sub</code>)</th><td>{{.Sub}}</td></tr>
      <tr><th>Name</th><td>{{with .Name}}{{.}}{{else}}not shared{{end}}</td></tr>
      <tr><th>Email</th><td>{{with .Email}}{{.}}{{else}}not shared (Rante shares an email only once it's verified){{end}}</td></tr>
      <tr><th>Created</th><td>{{.Created}}</td></tr>
      <tr><th>Last sign-in</th><td>{{.LastSignIn}}</td></tr>
    </tbody></table>
    <p>This example keeps accounts in memory. A real website stores them in its database, keyed by <code>sub</code>.</p>
    {{else}}<p>Not found: this example keeps accounts in memory, and the server has restarted since you signed in. Sign out
       and in again.</p>{{end}}
    <h2>ID token</h2>
    <p>This server validated the ID token below. Use <code>sub</code> as the person's ID on this website: it is
       pairwise, so other organizations' apps see a different value.</p>
    <table><tbody>{{range .Claims}}<tr><th><code>{{.Name}}</code></th><td>{{.Value}}</td></tr>{{end}}</tbody></table>
    <p><a href="/userinfo">Show userinfo</a></p>
    <form method="post" action="/auth/sign-out"><button type="submit">Sign out</button></form>{{end}}`)

	userinfoPage = page(`{{define "title"}}Userinfo{{end}}{{define "body"}}
    <h1>Userinfo</h1>
    <p>From GET https://login.rante.com/common/oidc/v2.0/userinfo:</p>
    <table><tbody>{{range .Claims}}<tr><th><code>{{.Name}}</code></th><td>{{.Value}}</td></tr>{{end}}</tbody></table>
    <p><a href="/">Back</a></p>{{end}}`)

	messagePage = page(`{{define "title"}}{{.Title}}{{end}}{{define "body"}}
    <h1>{{.Title}}</h1>
    <p>{{.Message}}</p>
    <p><a href="/">Back</a></p>{{end}}`)

	errorPage = page(`{{define "title"}}Sign-in failed{{end}}{{define "body"}}
    <h1>Sign-in failed</h1>
    <p class="error"><code>{{.Code}}</code> {{.Message}}</p>
    <p><a href="/">Try again</a></p>{{end}}`)
)
