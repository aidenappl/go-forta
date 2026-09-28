package forta

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ── fixtures ────────────────────────────────────────────────────────────────

const (
	obsRequestID     = "0123456789abcdef"
	obsTraceUUID     = "4bf92f35-77b3-4da6-a3ce-929d0e0e4736"
	obsTraceHex      = "4bf92f3577b34da6a3ce929d0e0e4736"
	obsUpstreamReqID = "f0f0f0f0f0f0f0f0"
	obsFreshToken    = "fresh.access.token"
	obsGoodToken     = "good.access.token"
	obsRefreshCookie = "valid-refresh-token"
)

var obsTraceparentRe = regexp.MustCompile(`^00-([0-9a-f]{32})-[0-9a-f]{16}-01$`)

// obsStub is a Forta API stand-in that records the headers of every request
// it receives, per path, and echoes an X-Request-ID the way forta-api does.
type obsStub struct {
	srv *httptest.Server

	mu      sync.Mutex
	headers map[string][]http.Header

	// Status overrides; zero means "behave normally".
	selfStatus    int
	refreshStatus int
	grantStatus   int
	jwks          []byte
}

func newObsStub(t *testing.T) *obsStub {
	t.Helper()
	s := &obsStub{headers: map[string][]http.Header{}}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.headers[r.URL.Path] = append(s.headers[r.URL.Path], r.Header.Clone())
		s.mu.Unlock()
		w.Header().Set("X-Request-ID", obsUpstreamReqID)

		switch r.URL.Path {
		case "/auth/self":
			if s.selfStatus != 0 {
				w.WriteHeader(s.selfStatus)
				return
			}
			auth := r.Header.Get("Authorization")
			if auth != "Bearer "+obsGoodToken && auth != "Bearer "+obsFreshToken && auth != "Bearer frt_good" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			writeStubJSON(t, w, fortaEnvelope[User]{Success: true, Data: User{ID: 42}})
		case "/auth/refresh":
			if s.refreshStatus != 0 {
				w.WriteHeader(s.refreshStatus)
				return
			}
			if r.Header.Get("Authorization") != "Bearer "+obsRefreshCookie {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			writeStubJSON(t, w, fortaEnvelope[AuthResponse]{Success: true, Data: AuthResponse{
				User: User{ID: 42},
				Authorization: TokenPair{
					AccessToken:  obsFreshToken,
					RefreshToken: "rotated-refresh-token",
					ExpiresAt:    time.Now().Add(time.Hour),
				},
			}})
		case "/auth/exchange":
			writeStubJSON(t, w, fortaEnvelope[AuthResponse]{Success: true, Data: AuthResponse{
				User:          User{ID: 42},
				Authorization: TokenPair{AccessToken: obsFreshToken, RefreshToken: "r", ExpiresAt: time.Now().Add(time.Hour)},
			}})
		case "/internal/grants/check":
			if s.grantStatus != 0 {
				w.WriteHeader(s.grantStatus)
				return
			}
			w.WriteHeader(http.StatusOK)
		case "/oauth/jwks":
			_, _ = w.Write(s.jwks)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *obsStub) seen(path string) []http.Header {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.headers[path]
}

// failingTransport fails every request whose path is in fail, and forwards the
// rest — a transport-level outage of one endpoint.
type failingTransport struct {
	fail map[string]bool
}

func (f failingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if f.fail[r.URL.Path] {
		return nil, errors.New("simulated connection refused")
	}
	return http.DefaultTransport.RoundTrip(r)
}

type hostCtxKey struct{}

type hostIDs struct{ requestID, traceID string }

// ── outbound correlation ────────────────────────────────────────────────────

// TestOutboundCorrelation proves every outbound call — /auth/refresh,
// /auth/self, the grant check and the JWKS fetch — carries the request's ids,
// whichever way the host supplies them, and that nothing is forwarded when
// there are no valid ids.
func TestOutboundCorrelation(t *testing.T) {
	cases := []struct {
		name string
		// hook, when set, becomes Config.Correlation.
		hook func(ctx context.Context) (string, string)
		// prepare mutates the inbound request / response before Protected runs.
		prepare func(w http.ResponseWriter, r *http.Request) *http.Request
		wantRID string
		wantTID string
	}{
		{
			name: "ids on the context",
			prepare: func(w http.ResponseWriter, r *http.Request) *http.Request {
				return r.WithContext(WithCorrelation(r.Context(), obsRequestID, obsTraceUUID))
			},
			wantRID: obsRequestID,
			wantTID: obsTraceUUID,
		},
		{
			name: "Correlation hook reading a host context key",
			hook: func(ctx context.Context) (string, string) {
				ids, _ := ctx.Value(hostCtxKey{}).(hostIDs)
				return ids.requestID, ids.traceID
			},
			prepare: func(w http.ResponseWriter, r *http.Request) *http.Request {
				// The hook wins over ids the inbound headers would supply.
				r.Header.Set("X-Request-ID", "aaaaaaaaaaaaaaaa")
				return r.WithContext(context.WithValue(r.Context(), hostCtxKey{}, hostIDs{obsRequestID, obsTraceUUID}))
			},
			wantRID: obsRequestID,
			wantTID: obsTraceUUID,
		},
		{
			name: "response header set by host middleware",
			prepare: func(w http.ResponseWriter, r *http.Request) *http.Request {
				w.Header().Set("X-Request-ID", obsRequestID)
				w.Header().Set("X-Trace-ID", obsTraceUUID)
				r.Header.Set("X-Request-ID", "bbbbbbbbbbbbbbbb") // response header wins
				return r
			},
			wantRID: obsRequestID,
			wantTID: obsTraceUUID,
		},
		{
			name: "inbound request headers, traceparent",
			prepare: func(w http.ResponseWriter, r *http.Request) *http.Request {
				r.Header.Set("X-Request-ID", obsRequestID)
				r.Header.Set("traceparent", "00-"+obsTraceHex+"-00f067aa0ba902b7-01")
				return r
			},
			wantRID: obsRequestID,
			wantTID: obsTraceHex,
		},
		{
			name:    "no ids",
			prepare: func(w http.ResponseWriter, r *http.Request) *http.Request { return r },
		},
		{
			name: "invalid ids are never forwarded",
			hook: func(ctx context.Context) (string, string) { return "req-1\r\nX-Evil: 1", "not-a-trace" },
			prepare: func(w http.ResponseWriter, r *http.Request) *http.Request {
				w.Header().Set("X-Request-ID", "<script>")
				r.Header.Set("X-Trace-ID", "zzzz")
				return r.WithContext(WithCorrelation(r.Context(), "short", "also bad"))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := newObsStub(t)
			key := newRSAKey(t)
			stub.jwks = jwksJSON(t, map[string]*rsa.PublicKey{"k1": &key.PublicKey})

			// Remote validation + grants: a refresh-only request hits
			// /auth/refresh, /auth/self and /internal/grants/check.
			remote := testClient(t, func(cfg *Config) {
				cfg.APIDomain = stub.srv.URL
				cfg.EnforceGrants = true
				cfg.Correlation = tc.hook
				cfg.Logf = t.Logf
			})
			// RS256-only: an RS256 token hits /oauth/jwks.
			local := testClient(t, func(cfg *Config) {
				cfg.APIDomain = stub.srv.URL
				cfg.EnableJWKS = true
				cfg.Correlation = tc.hook
				cfg.Logf = t.Logf
			})

			var nextCtx context.Context
			ok := func(w http.ResponseWriter, r *http.Request) { nextCtx = r.Context() }

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/x", nil)
			req.AddCookie(&http.Cookie{Name: cookieRefreshToken, Value: obsRefreshCookie})
			req = tc.prepare(rec, req)
			remote.Protected(ok)(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("remote: status %d: %s", rec.Code, rec.Body.String())
			}
			if nextCtx == nil {
				t.Fatal("remote: next not called")
			}

			rec = httptest.NewRecorder()
			req = httptest.NewRequest(http.MethodGet, "/x", nil)
			req.Header.Set("Authorization", "Bearer "+signRS256(t, newTestClaims("42"), key, "k1"))
			req = tc.prepare(rec, req)
			local.Protected(ok)(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("local: status %d: %s", rec.Code, rec.Body.String())
			}

			for _, path := range []string{"/auth/refresh", "/auth/self", "/internal/grants/check", "/oauth/jwks"} {
				hs := stub.seen(path)
				if len(hs) == 0 {
					t.Fatalf("%s was never called", path)
				}
				for _, h := range hs {
					assertCorrelationHeaders(t, path, h, tc.wantRID, tc.wantTID)
				}
			}
		})
	}
}

func assertCorrelationHeaders(t *testing.T, path string, h http.Header, wantRID, wantTID string) {
	t.Helper()
	if got := h.Get("X-Request-ID"); got != wantRID {
		t.Errorf("%s: X-Request-ID = %q, want %q", path, got, wantRID)
	}
	if got := h.Get("X-Trace-ID"); got != wantTID {
		t.Errorf("%s: X-Trace-ID = %q, want %q", path, got, wantTID)
	}
	if got := h.Get("User-Agent"); got != "go-forta/"+Version {
		t.Errorf("%s: User-Agent = %q, want go-forta/%s", path, got, Version)
	}
	tp := h.Get("traceparent")
	if wantTID == "" {
		if tp != "" {
			t.Errorf("%s: traceparent = %q, want absent", path, tp)
		}
		return
	}
	m := obsTraceparentRe.FindStringSubmatch(tp)
	if m == nil {
		t.Errorf("%s: traceparent = %q, not W3C-shaped", path, tp)
		return
	}
	if m[1] != strings.ReplaceAll(wantTID, "-", "") {
		t.Errorf("%s: traceparent trace id = %q, want %q", path, m[1], wantTID)
	}
}

// TestOutboundCorrelation_ExchangeAndPing covers the two calls not on the
// Protected path: the code exchange in CallbackHandler, and PingContext.
func TestOutboundCorrelation_ExchangeAndPing(t *testing.T) {
	stub := newObsStub(t)
	c := testClient(t, func(cfg *Config) { cfg.APIDomain = stub.srv.URL })

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/forta/callback?code=abc&state=s1", nil)
	req.AddCookie(&http.Cookie{Name: cookieOAuthState, Value: "s1"})
	req.Header.Set("X-Request-ID", obsRequestID)
	c.CallbackHandler(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("callback status %d: %s", rec.Code, rec.Body.String())
	}
	hs := stub.seen("/auth/exchange")
	if len(hs) != 1 {
		t.Fatalf("expected one exchange, got %d", len(hs))
	}
	assertCorrelationHeaders(t, "/auth/exchange", hs[0], obsRequestID, "")

	if err := c.PingContext(WithCorrelation(context.Background(), obsRequestID, obsTraceUUID)); err == nil {
		t.Fatal("stub has no /healthcheck; expected an error")
	} else {
		var ue *UpstreamError
		if !errors.As(err, &ue) || ue.Status != http.StatusNotFound || ue.RequestID != obsUpstreamReqID {
			t.Fatalf("ping error not an UpstreamError carrying the echoed id: %#v", err)
		}
		if err.Error() != "go-forta: ping: unexpected status 404" {
			t.Fatalf("ping error text changed: %q", err.Error())
		}
	}
	assertCorrelationHeaders(t, "/healthcheck", stub.seen("/healthcheck")[0], obsRequestID, obsTraceUUID)
}

// ── OnAuthFailure ───────────────────────────────────────────────────────────

// TestOnAuthFailure asserts the reported reason for every failure path, AND
// that the HTTP response is byte-for-byte what previous releases wrote — the
// hook is additive and must never change what a client sees.
func TestOnAuthFailure(t *testing.T) {
	expired := newTestClaims("42")
	expired.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Minute))

	type setup struct {
		stub *obsStub
		cfg  *Config
		req  *http.Request
	}
	cases := []struct {
		name  string
		setup func(t *testing.T, s *setup)

		wantStatus       int
		wantBody         string
		wantReason       string
		wantUpstreamID   string
		wantRefreshCalls int
	}{
		{
			name:       "missing credential",
			setup:      func(t *testing.T, s *setup) {},
			wantStatus: 401, wantBody: "missing or invalid authorization",
			wantReason: ReasonMissingCredential,
		},
		{
			name: "missing credential, refresh rejected",
			setup: func(t *testing.T, s *setup) {
				s.req.AddCookie(&http.Cookie{Name: cookieRefreshToken, Value: "revoked"})
			},
			wantStatus: 401, wantBody: "missing or invalid authorization",
			wantReason: ReasonRefreshFailed, wantUpstreamID: obsUpstreamReqID, wantRefreshCalls: 1,
		},
		{
			name: "local: expired, no refresh cookie",
			setup: func(t *testing.T, s *setup) {
				s.cfg.JWTSigningKey = testHMACKey
				s.req.Header.Set("Authorization", "Bearer "+signHS512(t, expired, []byte(testHMACKey)))
			},
			wantStatus: 401, wantBody: "session expired, please log in again",
			wantReason: ReasonTokenExpired,
		},
		{
			name: "local: expired, auto-refresh disabled",
			setup: func(t *testing.T, s *setup) {
				s.cfg.JWTSigningKey = testHMACKey
				s.cfg.DisableAutoRefresh = true
				s.req.Header.Set("Authorization", "Bearer "+signHS512(t, expired, []byte(testHMACKey)))
			},
			wantStatus: 401, wantBody: "invalid or expired access token",
			wantReason: ReasonTokenExpired,
		},
		{
			name: "local: invalid signature",
			setup: func(t *testing.T, s *setup) {
				s.cfg.JWTSigningKey = testHMACKey
				s.req.Header.Set("Authorization", "Bearer "+signHS512(t, newTestClaims("42"), []byte("wrong-key")))
			},
			wantStatus: 401, wantBody: "invalid or expired access token",
			wantReason: ReasonTokenInvalid,
		},
		{
			name: "local: JWKS unreachable",
			setup: func(t *testing.T, s *setup) {
				s.cfg.EnableJWKS = true
				s.cfg.HTTPClient = &http.Client{Transport: failingTransport{fail: map[string]bool{"/oauth/jwks": true}}}
				s.req.Header.Set("Authorization", "Bearer "+signRS256(t, newTestClaims("42"), newRSAKey(t), "k1"))
			},
			wantStatus: 401, wantBody: "invalid or expired access token",
			wantReason: ReasonUpstreamUnavailable,
		},
		{
			name: "remote: /auth/self 401, no refresh cookie",
			setup: func(t *testing.T, s *setup) {
				s.req.Header.Set("Authorization", "Bearer bad.access.token")
			},
			wantStatus: 401, wantBody: "session expired, please log in again",
			wantReason: ReasonTokenExpired, wantUpstreamID: obsUpstreamReqID,
		},
		{
			name: "remote: /auth/self 401, refresh rejected",
			setup: func(t *testing.T, s *setup) {
				s.req.Header.Set("Authorization", "Bearer bad.access.token")
				s.req.AddCookie(&http.Cookie{Name: cookieRefreshToken, Value: "revoked"})
			},
			wantStatus: 401, wantBody: "session expired, please log in again",
			wantReason: ReasonRefreshFailed, wantUpstreamID: obsUpstreamReqID, wantRefreshCalls: 1,
		},
		{
			// The outage case. Response and refresh behaviour are exactly what
			// they were — including the refresh attempt — only the reported
			// reason differs.
			name: "remote: /auth/self 503, refresh also fails",
			setup: func(t *testing.T, s *setup) {
				s.stub.selfStatus = http.StatusServiceUnavailable
				s.stub.refreshStatus = http.StatusServiceUnavailable
				s.req.Header.Set("Authorization", "Bearer "+obsGoodToken)
				s.req.AddCookie(&http.Cookie{Name: cookieRefreshToken, Value: obsRefreshCookie})
			},
			wantStatus: 401, wantBody: "session expired, please log in again",
			wantReason: ReasonUpstreamUnavailable, wantUpstreamID: obsUpstreamReqID, wantRefreshCalls: 1,
		},
		{
			name: "remote: /auth/self 502, no refresh cookie",
			setup: func(t *testing.T, s *setup) {
				s.stub.selfStatus = http.StatusBadGateway
				s.req.Header.Set("Authorization", "Bearer "+obsGoodToken)
			},
			wantStatus: 401, wantBody: "session expired, please log in again",
			wantReason: ReasonUpstreamUnavailable, wantUpstreamID: obsUpstreamReqID,
		},
		{
			name: "remote: /auth/self 500, auto-refresh disabled",
			setup: func(t *testing.T, s *setup) {
				s.stub.selfStatus = http.StatusInternalServerError
				s.cfg.DisableAutoRefresh = true
				s.req.Header.Set("Authorization", "Bearer "+obsGoodToken)
			},
			wantStatus: 401, wantBody: "invalid or expired access token",
			wantReason: ReasonUpstreamUnavailable, wantUpstreamID: obsUpstreamReqID,
		},
		{
			name: "remote: /auth/self unreachable",
			setup: func(t *testing.T, s *setup) {
				s.cfg.HTTPClient = &http.Client{Transport: failingTransport{fail: map[string]bool{"/auth/self": true}}}
				s.req.Header.Set("Authorization", "Bearer "+obsGoodToken)
			},
			wantStatus: 401, wantBody: "session expired, please log in again",
			wantReason: ReasonUpstreamUnavailable,
		},
		{
			name: "api token rejected",
			setup: func(t *testing.T, s *setup) {
				s.req.Header.Set("Authorization", "Bearer frt_bad")
			},
			wantStatus: 401, wantBody: "invalid or expired api token",
			wantReason: ReasonAPITokenInvalid, wantUpstreamID: obsUpstreamReqID,
		},
		{
			name: "api token, forta down",
			setup: func(t *testing.T, s *setup) {
				s.stub.selfStatus = http.StatusServiceUnavailable
				s.req.Header.Set("Authorization", "Bearer frt_good")
			},
			wantStatus: 401, wantBody: "invalid or expired api token",
			wantReason: ReasonUpstreamUnavailable, wantUpstreamID: obsUpstreamReqID,
		},
		{
			name: "grant denied",
			setup: func(t *testing.T, s *setup) {
				s.stub.grantStatus = http.StatusForbidden
				s.cfg.EnforceGrants = true
				s.req.Header.Set("Authorization", "Bearer "+obsGoodToken)
			},
			wantStatus: 403, wantBody: "grant required",
			wantReason: ReasonGrantDenied,
		},
		{
			name: "grant check returned 500",
			setup: func(t *testing.T, s *setup) {
				s.stub.grantStatus = http.StatusInternalServerError
				s.cfg.EnforceGrants = true
				s.req.Header.Set("Authorization", "Bearer "+obsGoodToken)
			},
			wantStatus: 403, wantBody: "grant required",
			wantReason: ReasonGrantCheckFailed, wantUpstreamID: obsUpstreamReqID,
		},
		{
			name: "grant check transport failure",
			setup: func(t *testing.T, s *setup) {
				s.cfg.EnforceGrants = true
				s.cfg.HTTPClient = &http.Client{Transport: failingTransport{fail: map[string]bool{"/internal/grants/check": true}}}
				s.req.Header.Set("Authorization", "Bearer "+obsGoodToken)
			},
			wantStatus: 403, wantBody: "grant required",
			wantReason: ReasonGrantCheckFailed,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := newObsStub(t)
			s := &setup{
				stub: stub,
				cfg:  &Config{},
				req:  httptest.NewRequest(http.MethodGet, "/x", nil),
			}
			tc.setup(t, s)

			// Run the identical request twice: once with no hooks at all (the
			// pre-v1.11 behaviour) and once with OnAuthFailure set. The two
			// responses must be identical.
			run := func(withHook bool) (*httptest.ResponseRecorder, []AuthFailure) {
				var got []AuthFailure
				c := testClient(t, func(cfg *Config) {
					base := *s.cfg
					base.APIDomain = stub.srv.URL
					base.LoginDomain = cfg.LoginDomain
					base.ClientID = cfg.ClientID
					base.ClientSecret = cfg.ClientSecret
					if withHook {
						base.OnAuthFailure = func(r *http.Request, f AuthFailure) { got = append(got, f) }
						base.Logf = t.Logf
					}
					*cfg = base
				})
				rec := httptest.NewRecorder()
				c.Protected(func(w http.ResponseWriter, r *http.Request) {
					t.Error("next must not run")
				})(rec, s.req.Clone(s.req.Context()))
				return rec, got
			}

			plain, _ := run(false)
			refreshAfterPlain := len(stub.seen("/auth/refresh"))
			hooked, failures := run(true)
			refreshAfterHooked := len(stub.seen("/auth/refresh")) - refreshAfterPlain

			if plain.Code != hooked.Code || plain.Body.String() != hooked.Body.String() {
				t.Fatalf("OnAuthFailure changed the response:\n plain  %d %s\n hooked %d %s",
					plain.Code, plain.Body.String(), hooked.Code, hooked.Body.String())
			}
			if refreshAfterPlain != refreshAfterHooked {
				t.Fatalf("OnAuthFailure changed refresh behaviour: %d vs %d calls", refreshAfterPlain, refreshAfterHooked)
			}
			if refreshAfterHooked != tc.wantRefreshCalls {
				t.Errorf("refresh calls = %d, want %d", refreshAfterHooked, tc.wantRefreshCalls)
			}

			if hooked.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (%s)", hooked.Code, tc.wantStatus, hooked.Body.String())
			}
			var body codedErrorResponse
			if err := json.Unmarshal(hooked.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			if body.ErrorMessage != tc.wantBody {
				t.Errorf("error_message = %q, want %q", body.ErrorMessage, tc.wantBody)
			}
			if tc.wantStatus == http.StatusForbidden && body.ErrorCode != ErrCodeGrantRequired {
				t.Errorf("error_code = %d, want %d", body.ErrorCode, ErrCodeGrantRequired)
			}

			if len(failures) != 1 {
				t.Fatalf("OnAuthFailure called %d times, want 1: %+v", len(failures), failures)
			}
			f := failures[0]
			if f.Reason != tc.wantReason {
				t.Errorf("Reason = %q, want %q (err: %v)", f.Reason, tc.wantReason, f.Err)
			}
			if f.Status != tc.wantStatus {
				t.Errorf("Status = %d, want %d", f.Status, tc.wantStatus)
			}
			if f.UpstreamRequestID != tc.wantUpstreamID {
				t.Errorf("UpstreamRequestID = %q, want %q", f.UpstreamRequestID, tc.wantUpstreamID)
			}
			if f.Err != nil && strings.Contains(f.Err.Error(), "Bearer") {
				t.Errorf("Err leaks a credential: %v", f.Err)
			}
		})
	}
}

// TestOnAuthFailure_Callback covers the handler paths.
func TestOnAuthFailure_Callback(t *testing.T) {
	stub := newObsStub(t)
	var got []AuthFailure
	c := testClient(t, func(cfg *Config) {
		cfg.APIDomain = stub.srv.URL
		cfg.OnAuthFailure = func(r *http.Request, f AuthFailure) { got = append(got, f) }
		cfg.Logf = t.Logf
		cfg.HTTPClient = &http.Client{Transport: failingTransport{fail: map[string]bool{"/auth/exchange": true}}}
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/forta/callback?code=abc&state=s1", nil)
	req.AddCookie(&http.Cookie{Name: cookieOAuthState, Value: "s1"})
	c.CallbackHandler(rec, req)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "failed to exchange authorization code") {
		t.Fatalf("unexpected response %d %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/forta/callback?code=abc&state=s1", nil)
	req.AddCookie(&http.Cookie{Name: cookieOAuthState, Value: "other"})
	c.CallbackHandler(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("state mismatch: status %d", rec.Code)
	}

	if len(got) != 2 || got[0].Reason != ReasonExchangeFailed || got[1].Reason != ReasonCallbackInvalid {
		t.Fatalf("unexpected failures: %+v", got)
	}
}

// TestZeroValueObservability confirms a Config with none of the new fields set
// makes the same calls it always did and does not panic on any failure path.
func TestZeroValueObservability(t *testing.T) {
	stub := newObsStub(t)
	c := testClient(t, func(cfg *Config) { cfg.APIDomain = stub.srv.URL; cfg.EnforceGrants = true })
	stub.grantStatus = http.StatusForbidden

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+obsGoodToken)
	c.Protected(func(http.ResponseWriter, *http.Request) {})(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d", rec.Code)
	}
	for _, path := range []string{"/auth/self", "/internal/grants/check"} {
		for _, h := range stub.seen(path) {
			if h.Get("X-Request-ID") != "" || h.Get("traceparent") != "" || h.Get("X-Trace-ID") != "" {
				t.Errorf("%s: correlation headers sent with no ids: %v", path, h)
			}
		}
	}
}
