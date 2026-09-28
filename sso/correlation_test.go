package sso_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	sso "github.com/aidenappl/go-forta/sso"
	"github.com/aidenappl/go-forta/sso/ssotest"
	"golang.org/x/oauth2"
)

const (
	corrRequestID = "0123456789abcdef"
	corrTraceID   = "4bf92f35-77b3-4da6-a3ce-929d0e0e4736"
)

var corrTraceparentRe = regexp.MustCompile(`^00-4bf92f3577b34da6a3ce929d0e0e4736-[0-9a-f]{16}-01$`)

// headerLog records request headers per path.
type headerLog struct {
	mu   sync.Mutex
	seen map[string][]http.Header
}

func (l *headerLog) add(path string, h http.Header) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.seen == nil {
		l.seen = map[string][]http.Header{}
	}
	l.seen[path] = append(l.seen[path], h.Clone())
}

func (l *headerLog) get(path string) []http.Header {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.seen[path]
}

// recordingProxy fronts the fake IdP and records what arrives, so assertions
// are on the wire rather than on what the client believes it sent.
func recordingProxy(t *testing.T, idp *ssotest.FakeIDP) (string, *headerLog) {
	t.Helper()
	target, _ := url.Parse(idp.Issuer())
	rp := httputil.NewSingleHostReverseProxy(target)
	log := &headerLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.add(r.URL.Path, r.Header)
		rp.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, log
}

// recordingTransport records headers at the client side, as the caller's own
// transport. Used for the OIDC adapter, whose issuer must match the fake IdP's
// URL exactly and so cannot sit behind a proxy.
type recordingTransport struct{ log *headerLog }

func (rt recordingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	rt.log.add(r.URL.Path, r.Header)
	return http.DefaultTransport.RoundTrip(r)
}

func assertIDs(t *testing.T, path string, h http.Header, want bool) {
	t.Helper()
	rid, tid, tp := h.Get("X-Request-ID"), h.Get("X-Trace-ID"), h.Get("traceparent")
	if !want {
		if rid != "" || tid != "" || tp != "" {
			t.Errorf("%s: correlation headers sent without valid ids: rid=%q tid=%q traceparent=%q", path, rid, tid, tp)
		}
		return
	}
	if rid != corrRequestID {
		t.Errorf("%s: X-Request-ID = %q, want %q", path, rid, corrRequestID)
	}
	if tid != corrTraceID {
		t.Errorf("%s: X-Trace-ID = %q, want %q", path, tid, corrTraceID)
	}
	if !corrTraceparentRe.MatchString(tp) {
		t.Errorf("%s: traceparent = %q", path, tp)
	}
}

type hostKey struct{}

// TestCorrelation_Checkpoint covers the 5-minute introspection traffic: ids on
// the ctx, ids from the Correlation hook, none, and invalid ones.
func TestCorrelation_Checkpoint(t *testing.T) {
	cases := []struct {
		name string
		ctx  func() context.Context
		hook func(ctx context.Context) (string, string)
		want bool
	}{
		{
			name: "ids on the context",
			ctx: func() context.Context {
				return sso.WithCorrelation(context.Background(), corrRequestID, corrTraceID)
			},
			want: true,
		},
		{
			name: "Correlation hook",
			ctx: func() context.Context {
				return context.WithValue(context.Background(), hostKey{}, [2]string{corrRequestID, corrTraceID})
			},
			hook: func(ctx context.Context) (string, string) {
				v, _ := ctx.Value(hostKey{}).([2]string)
				return v[0], v[1]
			},
			want: true,
		},
		{
			name: "no ids",
			ctx:  context.Background,
		},
		{
			name: "invalid ids",
			ctx: func() context.Context {
				return sso.WithCorrelation(context.Background(), "not-an-id", "nope\r\nX: y")
			},
			hook: func(context.Context) (string, string) { return "short", "<b>" },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			idp := ssotest.NewFakeIDP(t)
			proxyURL, log := recordingProxy(t, idp)

			var results []sso.CheckpointResult
			c, _ := newCheckpointer(t, idp, longPast(), func(c *sso.Checkpointer) {
				inner := c.Providers
				c.Providers = func(ctx context.Context, slug string) (*sso.Provider, error) {
					p, err := inner(ctx, slug)
					if p != nil {
						p.IntrospectURL = proxyURL + "/introspect"
					}
					return p, err
				}
				c.Correlation = tc.hook
				c.OnResult = func(_ context.Context, userID int64, r sso.CheckpointResult, cause error) {
					if userID != 1 || cause != nil {
						t.Errorf("OnResult(user=%d, cause=%v)", userID, cause)
					}
					results = append(results, r)
				}
			})

			if got := c.Check(tc.ctx(), 1); got != sso.CheckpointOK {
				t.Fatalf("Check = %v, want ok", got)
			}
			hs := log.get("/introspect")
			if len(hs) != 1 {
				t.Fatalf("introspect calls = %d, want 1", len(hs))
			}
			assertIDs(t, "/introspect", hs[0], tc.want)
			if len(results) != 1 || results[0] != sso.CheckpointOK {
				t.Errorf("OnResult results = %v, want [ok]", results)
			}
		})
	}
}

// TestCheckpoint_OnResultAndLogfCtx asserts the failure path is reported with
// its cause, and that LogfCtx wins over Logf and sees the request's ids.
func TestCheckpoint_OnResultAndLogfCtx(t *testing.T) {
	idp := ssotest.NewFakeIDP(t)
	idp.IntrospectStatus = http.StatusInternalServerError

	var plainLogs int
	var ctxLogIDs []string
	var gotResult sso.CheckpointResult
	var gotCause error
	c, _ := newCheckpointer(t, idp, time.Time{}, func(c *sso.Checkpointer) {
		c.Logf = func(string, ...any) { plainLogs++ }
		c.LogfCtx = func(ctx context.Context, format string, args ...any) {
			// A host reads its own request ids from ctx here.
			v, _ := ctx.Value(hostKey{}).(string)
			ctxLogIDs = append(ctxLogIDs, v)
		}
		c.OnResult = func(_ context.Context, _ int64, r sso.CheckpointResult, cause error) {
			gotResult, gotCause = r, cause
		}
	})

	ctx := context.WithValue(context.Background(), hostKey{}, "req-ctx")
	if got := c.Check(ctx, 1); got != sso.CheckpointUnavailable {
		t.Fatalf("Check = %v, want unavailable (never checked, IdP failing)", got)
	}
	if gotResult != sso.CheckpointUnavailable || gotCause == nil || !strings.Contains(gotCause.Error(), "introspect status 500") {
		t.Fatalf("OnResult = (%v, %v)", gotResult, gotCause)
	}
	if plainLogs != 0 {
		t.Errorf("Logf called %d times although LogfCtx is set", plainLogs)
	}
	if len(ctxLogIDs) == 0 || ctxLogIDs[0] != "req-ctx" {
		t.Errorf("LogfCtx did not receive the Check ctx: %v", ctxLogIDs)
	}
}

// TestCheckpoint_ZeroValueHooks: a Checkpointer with none of the new fields
// behaves exactly as before and sends no correlation headers.
func TestCheckpoint_ZeroValueHooks(t *testing.T) {
	idp := ssotest.NewFakeIDP(t)
	proxyURL, log := recordingProxy(t, idp)
	c, _ := newCheckpointer(t, idp, longPast(), func(c *sso.Checkpointer) {
		inner := c.Providers
		c.Providers = func(ctx context.Context, slug string) (*sso.Provider, error) {
			p, err := inner(ctx, slug)
			if p != nil {
				p.IntrospectURL = proxyURL + "/introspect"
			}
			return p, err
		}
	})
	if got := c.Check(context.Background(), 1); got != sso.CheckpointOK {
		t.Fatalf("Check = %v", got)
	}
	assertIDs(t, "/introspect", log.get("/introspect")[0], false)
}

// TestCorrelation_OAuth2Adapter covers the token exchange (x/oauth2) and the
// hand-rolled userinfo call.
func TestCorrelation_OAuth2Adapter(t *testing.T) {
	for _, withIDs := range []bool{true, false} {
		t.Run(map[bool]string{true: "with ids", false: "without ids"}[withIDs], func(t *testing.T) {
			idp := ssotest.NewFakeIDP(t)
			proxyURL, log := recordingProxy(t, idp)
			ctx := context.Background()
			if withIDs {
				ctx = sso.WithCorrelation(ctx, corrRequestID, corrTraceID)
			}

			p := &sso.Provider{
				Slug:         "fake-oauth2",
				Kind:         sso.KindOAuth2,
				AuthorizeURL: idp.Issuer() + "/authorize",
				TokenURL:     proxyURL + "/token",
				UserInfoURL:  proxyURL + "/userinfo",
				ClientID:     testClientID,
				ClientSecret: "test-secret",
				RedirectURL:  "https://rp.test/auth/sso/callback",
			}
			adapter, err := sso.NewAdapter(ctx, p)
			if err != nil {
				t.Fatalf("NewAdapter: %v", err)
			}
			store := ssotest.NewMemoryStateStore()
			state, nonce, verifier, err := sso.GenerateState(ctx, store, p.Slug, "/")
			if err != nil {
				t.Fatalf("GenerateState: %v", err)
			}
			authURL, err := adapter.AuthCodeURL(state, nonce, verifier)
			if err != nil {
				t.Fatalf("AuthCodeURL: %v", err)
			}
			code := codeFromAuthorize(t, authURL)

			if _, _, err := adapter.Exchange(ctx, code, verifier, nonce); err != nil {
				t.Fatalf("Exchange: %v", err)
			}
			for _, path := range []string{"/token", "/userinfo"} {
				hs := log.get(path)
				if len(hs) != 1 {
					t.Fatalf("%s calls = %d, want 1", path, len(hs))
				}
				assertIDs(t, path, hs[0], withIDs)
			}
		})
	}
}

// TestCorrelation_OIDCExchange covers the OIDC adapter's exchange and UserInfo,
// both made by x/oauth2 / go-oidc through the oauth2.HTTPClient context value.
// The caller's own client is placed there to prove it is wrapped, not replaced.
func TestCorrelation_OIDCExchange(t *testing.T) {
	for _, withIDs := range []bool{true, false} {
		t.Run(map[bool]string{true: "with ids", false: "without ids"}[withIDs], func(t *testing.T) {
			idp := ssotest.NewFakeIDP(t)
			p := newOIDCProvider(t, idp, func(p *sso.Provider) {
				p.FetchUserInfo = true
				p.UserInfoURL = idp.Issuer() + "/userinfo"
			})

			log := &headerLog{}
			ctx := context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{Transport: recordingTransport{log: log}})
			if withIDs {
				ctx = sso.WithCorrelation(ctx, corrRequestID, corrTraceID)
			}

			adapter, err := sso.NewAdapter(context.Background(), p)
			if err != nil {
				t.Fatalf("NewAdapter: %v", err)
			}
			store := ssotest.NewMemoryStateStore()
			state, nonce, verifier, err := sso.GenerateState(ctx, store, p.Slug, "/")
			if err != nil {
				t.Fatalf("GenerateState: %v", err)
			}
			authURL, err := adapter.AuthCodeURL(state, nonce, verifier)
			if err != nil {
				t.Fatalf("AuthCodeURL: %v", err)
			}
			code := codeFromAuthorize(t, authURL)

			if _, _, err := adapter.Exchange(ctx, code, verifier, nonce); err != nil {
				t.Fatalf("Exchange: %v", err)
			}
			for _, path := range []string{"/token", "/userinfo"} {
				hs := log.get(path)
				if len(hs) != 1 {
					t.Fatalf("%s calls through the caller's client = %d, want 1", path, len(hs))
				}
				assertIDs(t, path, hs[0], withIDs)
			}
		})
	}
}
