package rantelogin

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
)

// localIdP is a local OpenID provider for the tests, shaped like Rante Login: discovery, JWKS, token and userinfo
// endpoints on 127.0.0.1. It issues codes that the tests hand it (standing in for the authorize step), checks each
// token request (client_id, PKCE, redirect URI, client authentication, single-use assertions) and signs ID tokens
// with a key generated for the run.
type localIdP struct {
	server          *httptest.Server
	issuer          string
	discoveryIssuer string

	mu             sync.Mutex
	signingKeys    []signingKey
	clients        map[string]idpClient
	codes          map[string]issuedCode
	accessTokens   map[string]map[string]any
	usedAssertions map[string]bool
	requests       []recordedRequest
	lastAssertion  *josejwt.JSONWebToken
	lastClaims     josejwt.Claims
}

type signingKey struct {
	kid string
	key *rsa.PrivateKey
}

type idpClient struct {
	clientType string
	keys       map[string]crypto.PublicKey
}

type issuedCode struct {
	clientID, redirectURI, codeChallenge, nonce string
	claims                                      map[string]any
}

type recordedRequest struct {
	method, path, authorization string
	form                        url.Values
}

func newLocalIdP(t *testing.T) *localIdP {
	t.Helper()
	idp := &localIdP{clients: map[string]idpClient{}, codes: map[string]issuedCode{}, accessTokens: map[string]map[string]any{},
		usedAssertions: map[string]bool{}}
	idp.addSigningKey(t, "test-key-1")
	idp.server = httptest.NewServer(http.HandlerFunc(idp.handle))
	t.Cleanup(idp.server.Close)
	idp.issuer = idp.server.URL + "/common/v2.0"
	idp.discoveryIssuer = idp.issuer
	return idp
}

func (idp *localIdP) addSigningKey(t *testing.T, kid string) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.signingKeys = append(idp.signingKeys, signingKey{kid: kid, key: key})
	return key
}

func (idp *localIdP) registerClient(clientID, clientType string, keys map[string]crypto.PublicKey) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.clients[clientID] = idpClient{clientType: clientType, keys: keys}
}

// issueCode stands in for the authorize step: a code for these values.
func (idp *localIdP) issueCode(clientID, redirectURI, codeChallenge, nonce string, claims map[string]any) string {
	bytes := make([]byte, 32)
	_, _ = rand.Read(bytes)
	code := hex.EncodeToString(bytes)
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.codes[code] = issuedCode{clientID, redirectURI, codeChallenge, nonce, claims}
	return code
}

// mintIDToken is an ID token like Rante Login's. Override any claim (nil removes it), or sign with another key and kid.
func (idp *localIdP) mintIDToken(t *testing.T, claims map[string]any, key *rsa.PrivateKey, kid string) string {
	t.Helper()
	token, err := idp.sign(claims, key, kid)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func (idp *localIdP) sign(claims map[string]any, key *rsa.PrivateKey, kid string) (string, error) {
	if key == nil {
		idp.mu.Lock()
		key, kid = idp.signingKeys[0].key, idp.signingKeys[0].kid
		idp.mu.Unlock()
	}
	now := time.Now().Unix()
	payload := map[string]any{"iss": idp.issuer, "sub": "pairwise-subject-1", "iat": now, "exp": now + 600, "auth_time": now}
	for name, value := range claims {
		if value == nil {
			delete(payload, name)
		} else {
			payload[name] = value
		}
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: kid}}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return "", err
	}
	return josejwt.Signed(signer).Claims(payload).Serialize()
}

func (idp *localIdP) handle(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	idp.mu.Lock()
	idp.requests = append(idp.requests, recordedRequest{r.Method, r.URL.Path, r.Header.Get("Authorization"), r.PostForm})
	idp.mu.Unlock()
	switch r.Method + " " + r.URL.Path {
	case "GET /common/v2.0/.well-known/openid-configuration":
		origin := idp.server.URL
		send(w, 200, map[string]any{
			"issuer":                                         idp.discoveryIssuer,
			"authorization_endpoint":                         origin + "/common/oauth2/v2.0/authorize",
			"token_endpoint":                                 origin + "/common/oauth2/v2.0/token",
			"userinfo_endpoint":                              origin + "/common/oidc/v2.0/userinfo",
			"jwks_uri":                                       origin + "/common/discovery/v2.0/keys",
			"response_types_supported":                       []string{"code"},
			"id_token_signing_alg_values_supported":          []string{"RS256"},
			"token_endpoint_auth_methods_supported":          []string{"private_key_jwt", "none"},
			"code_challenge_methods_supported":               []string{"S256"},
			"authorization_response_iss_parameter_supported": true,
		})
	case "GET /common/discovery/v2.0/keys":
		idp.mu.Lock()
		keys := jose.JSONWebKeySet{}
		for _, key := range idp.signingKeys {
			keys.Keys = append(keys.Keys, jose.JSONWebKey{Key: &key.key.PublicKey, KeyID: key.kid, Algorithm: "RS256", Use: "sig"})
		}
		idp.mu.Unlock()
		send(w, 200, keys)
	case "POST /common/oauth2/v2.0/token":
		idp.token(w, r)
	case "GET /common/oidc/v2.0/userinfo":
		idp.mu.Lock()
		claims := idp.accessTokens[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		idp.mu.Unlock()
		if claims == nil {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			send(w, 401, map[string]any{})
			return
		}
		send(w, 200, claims)
	default:
		send(w, 404, map[string]any{})
	}
}

func (idp *localIdP) token(w http.ResponseWriter, r *http.Request) {
	refuse := func(status int, code string) {
		send(w, status, map[string]any{"error": code, "error_description": "test IdP: " + code})
	}
	form := r.PostForm
	clientID := form.Get("client_id")
	idp.mu.Lock()
	client, ok := idp.clients[clientID]
	idp.mu.Unlock()
	if !ok || form.Has("client_secret") || r.Header.Get("Authorization") != "" {
		refuse(401, "invalid_client")
		return
	}
	if client.clientType == "Web" {
		raw := form.Get("client_assertion")
		token, err := josejwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256, jose.ES256})
		if form.Get("client_assertion_type") != assertionType || err != nil || len(token.Headers) != 1 {
			refuse(401, "invalid_client")
			return
		}
		key, ok := client.keys[token.Headers[0].KeyID]
		var claims josejwt.Claims
		if !ok || token.Claims(key, &claims) != nil {
			refuse(401, "invalid_client")
			return
		}
		expected := josejwt.Expected{Issuer: clientID, Subject: clientID, AnyAudience: josejwt.Audience{idp.server.URL + "/common/oauth2/v2.0/token"}}
		idp.mu.Lock()
		used := idp.usedAssertions[claims.ID]
		idp.usedAssertions[claims.ID] = true
		idp.mu.Unlock()
		if claims.Validate(expected) != nil || claims.ID == "" || used || claims.Expiry == nil || claims.IssuedAt == nil ||
			claims.Expiry.Time().Sub(claims.IssuedAt.Time()) > 5*time.Minute {
			refuse(401, "invalid_client")
			return
		}
		idp.mu.Lock()
		idp.lastAssertion, idp.lastClaims = token, claims
		idp.mu.Unlock()
	} else if form.Has("client_assertion") || form.Has("client_assertion_type") {
		refuse(401, "invalid_client")
		return
	}
	idp.mu.Lock()
	issued, ok := idp.codes[form.Get("code")]
	delete(idp.codes, form.Get("code"))
	idp.mu.Unlock()
	digest := sha256.Sum256([]byte(form.Get("code_verifier")))
	if !ok || issued.clientID != clientID || issued.redirectURI != form.Get("redirect_uri") ||
		issued.codeChallenge != base64.RawURLEncoding.EncodeToString(digest[:]) {
		refuse(400, "invalid_grant")
		return
	}
	claims := map[string]any{"aud": clientID, "azp": clientID, "nonce": issued.nonce}
	for name, value := range issued.claims {
		claims[name] = value
	}
	idToken, err := idp.sign(claims, nil, "")
	if err != nil {
		refuse(500, "server_error")
		return
	}
	accessToken := fmt.Sprintf("at-%d", time.Now().UnixNano())
	idp.mu.Lock()
	idp.accessTokens[accessToken] = map[string]any{"sub": issued.claims["sub"], "name": issued.claims["name"]}
	idp.mu.Unlock()
	send(w, 200, map[string]any{"access_token": accessToken, "token_type": "Bearer", "expires_in": 900,
		"id_token": idToken, "scope": "openid profile email"})
}

func (idp *localIdP) lastTokenForm() url.Values {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	for i := len(idp.requests) - 1; i >= 0; i-- {
		if strings.HasSuffix(idp.requests[i].path, "/token") {
			return idp.requests[i].form
		}
	}
	return nil
}

func (idp *localIdP) requestCount() int {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	return len(idp.requests)
}

func send(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
