// Package ssotest provides a fake OpenID Connect provider for testing relying
// parties.
//
// ─────────────────────────────────────────────────────────────────────────────
// WHY A FAKE IdP AND NOT A MOCK ADAPTER
//
// A mocked Adapter asserts that the code calls the functions the code calls. It
// cannot catch the defects that actually shipped in the implementations this
// package replaced, because every one of them was a MISSING PROTOCOL STEP that a
// mock has no opinion about:
//
//   - a PKCE challenge sent and never answered — a mock has no token endpoint to
//     notice the missing verifier;
//   - a nonce never verified — a mock has no id_token to put a wrong nonce in;
//   - a UserInfo `sub` that disagrees with the id_token — a mock returns one
//     identity, not two that can conflict.
//
// This fake speaks the real protocol over a real httptest server: discovery,
// JWKS, authorize, token, userinfo, introspection. That makes the NEGATIVE tests
// possible, and the negative tests are the point. A conformance suite always
// sends a correct verifier; it never tries omitting one.
//
// ⚠️ TEST ONLY. It signs with a key generated per instance, accepts any client
// secret, and will happily mint a token for anyone. Never import it outside a
// test binary.
// ─────────────────────────────────────────────────────────────────────────────
package ssotest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// FakeIDP is a minimal but protocol-correct OIDC provider.
type FakeIDP struct {
	Server *httptest.Server

	// Subject, Email, EmailVerified and Name are what the next login will assert.
	// Mutate them between requests to drive different cases.
	Subject       string
	Email         string
	EmailVerified bool
	Name          string

	// ─── Failure injection. Each field makes the IdP misbehave in ONE specific
	// way, so a test can assert the relying party notices. ───

	// OmitIDToken drops the id_token from the token response.
	OmitIDToken bool

	// WrongNonce stamps this nonce on the id_token instead of the requested one.
	// Non-empty enables it.
	WrongNonce string

	// WrongAudience stamps this `aud` instead of the client_id.
	WrongAudience string

	// WrongIssuer stamps this `iss` instead of the server's own URL.
	WrongIssuer string

	// ExpiredIDToken backdates `exp` so the token is already expired.
	ExpiredIDToken bool

	// UnsignedIDToken emits an `alg: none` token.
	UnsignedIDToken bool

	// UnknownKID stamps a `kid` that is not in the published JWKS.
	UnknownKID bool

	// UserInfoSubject overrides the `sub` the UserInfo endpoint returns, so a test
	// can drive the OIDC Core §5.3.2 mismatch. Empty means "match the id_token".
	UserInfoSubject string

	// IgnorePKCE makes the token endpoint accept an exchange with no or wrong
	// code_verifier.
	//
	// ⚠️ THIS IS THE MOST IMPORTANT FAILURE MODE HERE, because it models a REAL
	// authorization server that does not enforce PKCE — which is the only condition
	// under which a client's dropped verifier goes unnoticed. A test that only ever
	// talks to a strict server cannot tell "the client sent the verifier" from "the
	// server rejected the client", so it cannot prove the client sends it.
	IgnorePKCE bool

	// Introspection controls what the introspection endpoint reports. Default:
	// active.
	IntrospectActive bool

	// IntrospectStatus, when non-zero, makes introspection return that HTTP status
	// instead of a JSON body — for testing the "no answer" path distinctly from
	// active:false.
	IntrospectStatus int

	// IntrospectDelay, when non-zero, makes the introspection endpoint sleep
	// before answering. It exists so a test can hold a call OPEN while other
	// callers arrive — which is the only way to observe whether concurrent
	// checkpoints collapse into one request or stampede.
	IntrospectDelay time.Duration

	introspectCalls atomic.Int64

	key   *rsa.PrivateKey
	kid   string
	mu    sync.Mutex
	codes map[string]issuedCode

	// TokenRequests records every form posted to the token endpoint, so a test can
	// assert what the client actually sent rather than only what came back.
	TokenRequests []url.Values
}

type issuedCode struct {
	challenge string
	method    string
	nonce     string
	clientID  string
}

// NewFakeIDP starts a fake provider and registers cleanup.
func NewFakeIDP(t *testing.T) *FakeIDP {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("ssotest: generate key: %v", err)
	}

	f := &FakeIDP{
		Subject:          "fake-subject-1",
		Email:            "user@example.test",
		EmailVerified:    true,
		Name:             "Fake User",
		IntrospectActive: true,
		key:              key,
		kid:              "fake-kid-1",
		codes:            map[string]issuedCode{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", f.handleDiscovery)
	mux.HandleFunc("/jwks", f.handleJWKS)
	mux.HandleFunc("/authorize", f.handleAuthorize)
	mux.HandleFunc("/token", f.handleToken)
	mux.HandleFunc("/userinfo", f.handleUserInfo)
	mux.HandleFunc("/introspect", f.handleIntrospect)

	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Server.Close)
	return f
}

// Issuer is the fake provider's issuer URL.
func (f *FakeIDP) Issuer() string { return f.Server.URL }

func (f *FakeIDP) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	doc := map[string]any{
		"issuer":                                f.Server.URL,
		"authorization_endpoint":                f.Server.URL + "/authorize",
		"token_endpoint":                        f.Server.URL + "/token",
		"userinfo_endpoint":                     f.Server.URL + "/userinfo",
		"jwks_uri":                              f.Server.URL + "/jwks",
		"introspection_endpoint":                f.Server.URL + "/introspect",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported":      []string{"S256"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
	}
	writeJSON(w, http.StatusOK, doc)
}

func (f *FakeIDP) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	pub := &f.key.PublicKey
	writeJSON(w, http.StatusOK, map[string]any{
		"keys": []map[string]string{{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": f.kid,
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}},
	})
}

// handleAuthorize records the request and redirects with a code, exactly as a
// real provider would. It does NOT render a login page — the user is assumed to
// have authenticated.
func (f *FakeIDP) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	redirectURI := q.Get("redirect_uri")
	if redirectURI == "" {
		http.Error(w, "missing redirect_uri", http.StatusBadRequest)
		return
	}

	code := fmt.Sprintf("fake-code-%d", time.Now().UnixNano())

	f.mu.Lock()
	f.codes[code] = issuedCode{
		challenge: q.Get("code_challenge"),
		method:    q.Get("code_challenge_method"),
		nonce:     q.Get("nonce"),
		clientID:  q.Get("client_id"),
	}
	f.mu.Unlock()

	target, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	rq := target.Query()
	rq.Set("code", code)
	rq.Set("state", q.Get("state"))
	// RFC 9207, as a real provider should.
	rq.Set("iss", f.Server.URL)
	target.RawQuery = rq.Encode()

	http.Redirect(w, r, target.String(), http.StatusFound)
}

// handleToken redeems a code, enforcing PKCE unless IgnorePKCE is set.
func (f *FakeIDP) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}

	f.mu.Lock()
	f.TokenRequests = append(f.TokenRequests, r.Form)
	f.mu.Unlock()

	if r.FormValue("grant_type") == "refresh_token" {
		f.issueTokens(w, "", "")
		return
	}

	code := r.FormValue("code")

	f.mu.Lock()
	issued, ok := f.codes[code]
	// Single use, like a real provider.
	delete(f.codes, code)
	f.mu.Unlock()

	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}

	// ── PKCE enforcement ─────────────────────────────────────────────────────
	//
	// This is what makes a client's dropped verifier a TEST FAILURE rather than a
	// silent success. The check mirrors RFC 7636 §4.6: recompute S256 over the
	// presented verifier and compare with the registered challenge.
	if !f.IgnorePKCE && issued.challenge != "" {
		verifier := r.FormValue("code_verifier")
		if verifier == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error":             "invalid_grant",
				"error_description": "code_challenge was registered but no code_verifier was presented",
			})
			return
		}
		if issued.method != "S256" {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error":             "invalid_request",
				"error_description": "only S256 is supported",
			})
			return
		}
		sum := sha256.Sum256([]byte(verifier))
		if base64.RawURLEncoding.EncodeToString(sum[:]) != issued.challenge {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error":             "invalid_grant",
				"error_description": "code_verifier does not match code_challenge",
			})
			return
		}
	}

	f.issueTokens(w, issued.nonce, issued.clientID)
}

func (f *FakeIDP) issueTokens(w http.ResponseWriter, nonce, clientID string) {
	body := map[string]any{
		"access_token":  "fake-access-token",
		"refresh_token": "fake-refresh-token",
		"token_type":    "Bearer",
		"expires_in":    600,
	}

	if !f.OmitIDToken {
		idToken, err := f.mintIDToken(nonce, clientID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			return
		}
		body["id_token"] = idToken
	}

	writeJSON(w, http.StatusOK, body)
}

func (f *FakeIDP) mintIDToken(nonce, clientID string) (string, error) {
	if f.WrongNonce != "" {
		nonce = f.WrongNonce
	}

	aud := clientID
	if f.WrongAudience != "" {
		aud = f.WrongAudience
	}
	if aud == "" {
		aud = "fake-client"
	}

	iss := f.Server.URL
	if f.WrongIssuer != "" {
		iss = f.WrongIssuer
	}

	exp := time.Now().Add(10 * time.Minute)
	if f.ExpiredIDToken {
		exp = time.Now().Add(-10 * time.Minute)
	}

	claims := jwt.MapClaims{
		"iss":            iss,
		"sub":            f.Subject,
		"aud":            aud,
		"exp":            exp.Unix(),
		"iat":            time.Now().Unix(),
		"email":          f.Email,
		"email_verified": f.EmailVerified,
		"name":           f.Name,
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}

	if f.UnsignedIDToken {
		tok := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
		return tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	kid := f.kid
	if f.UnknownKID {
		kid = "kid-that-is-not-published"
	}
	tok.Header["kid"] = kid
	return tok.SignedString(f.key)
}

func (f *FakeIDP) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}

	sub := f.Subject
	if f.UserInfoSubject != "" {
		sub = f.UserInfoSubject
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"sub":            sub,
		"email":          f.Email,
		"email_verified": f.EmailVerified,
		"name":           f.Name,
	})
}

func (f *FakeIDP) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	f.introspectCalls.Add(1)
	if f.IntrospectDelay > 0 {
		time.Sleep(f.IntrospectDelay)
	}
	if f.IntrospectStatus != 0 {
		w.WriteHeader(f.IntrospectStatus)
		_, _ = w.Write([]byte("introspection is unavailable"))
		return
	}
	if _, _, ok := r.BasicAuth(); !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"active": f.IntrospectActive,
		"sub":    f.Subject,
		"scope":  "openid email profile",
	})
}

// IntrospectCalls reports how many times the introspection endpoint was hit.
//
// The COUNT is the assertion in the stampede test: a checkpoint that answers
// correctly while issuing one upstream request per concurrent HTTP request is
// still wrong, and the returned CheckpointResult cannot tell you that.
func (f *FakeIDP) IntrospectCalls() int { return int(f.introspectCalls.Load()) }

// LastTokenRequest returns the most recent form posted to the token endpoint.
func (f *FakeIDP) LastTokenRequest() url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.TokenRequests) == 0 {
		return nil
	}
	return f.TokenRequests[len(f.TokenRequests)-1]
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// LogoutTokenOptions shapes a minted logout token, including the ways a
// malicious or broken provider might get it wrong.
//
// ⚠️ THE FAILURE-INJECTION FIELDS ARE THE POINT OF THIS TYPE. A receiver that
// accepts a well-formed logout token proves very little; what matters is that it
// REFUSES the malformed ones, and each field here corresponds to a specific
// attack the spec's rules exist to prevent.
type LogoutTokenOptions struct {
	Subject string
	SID     string

	// WithNonce adds a `nonce` claim, which §2.4 FORBIDS. A logout token
	// carrying one can be replayed into the id_token position and accepted as
	// proof the user just authenticated — a sign-out turned into a sign-in.
	// A conforming receiver must reject the token outright.
	WithNonce string

	// OmitEvents drops the `events` claim, without which a receiver cannot tell
	// this is a logout token at all.
	OmitEvents bool

	// WrongAudience addresses the token to a different client — the check that
	// stops one relying party acting on another's logout notification.
	WrongAudience string

	// WrongIssuer forges the issuer.
	WrongIssuer string

	// Expired backdates `exp`.
	Expired bool

	// Unsigned emits `alg: none`.
	Unsigned bool
}

// MintLogoutToken produces a Back-Channel Logout 1.0 §2.4 logout token signed by
// this IdP.
func (f *FakeIDP) MintLogoutToken(clientID string, opts LogoutTokenOptions) (string, error) {
	aud := clientID
	if opts.WrongAudience != "" {
		aud = opts.WrongAudience
	}
	iss := f.Server.URL
	if opts.WrongIssuer != "" {
		iss = opts.WrongIssuer
	}
	exp := time.Now().Add(2 * time.Minute)
	if opts.Expired {
		exp = time.Now().Add(-2 * time.Minute)
	}

	claims := jwt.MapClaims{
		"iss": iss,
		"aud": aud,
		"iat": time.Now().Unix(),
		"exp": exp.Unix(),
		"jti": fmt.Sprintf("jti-%d-%s", time.Now().UnixNano(), opts.SID),
	}
	if opts.Subject != "" {
		claims["sub"] = opts.Subject
	}
	if opts.SID != "" {
		claims["sid"] = opts.SID
	}
	if !opts.OmitEvents {
		claims["events"] = map[string]any{
			"http://schemas.openid.net/event/backchannel-logout": map[string]any{},
		}
	}
	if opts.WithNonce != "" {
		claims["nonce"] = opts.WithNonce
	}

	if opts.Unsigned {
		return jwt.NewWithClaims(jwt.SigningMethodNone, claims).
			SignedString(jwt.UnsafeAllowNoneSignatureType)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = f.kid
	tok.Header["typ"] = "logout+jwt"
	return tok.SignedString(f.key)
}
