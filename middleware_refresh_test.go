package forta

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// fortaStub stands in for the Forta API, serving the two endpoints the
// no-credential refresh path touches. refreshCalls counts hits on
// /auth/refresh so a test can assert the call was skipped entirely.
type fortaStub struct {
	srv          *httptest.Server
	refreshCalls int
}

func newFortaStub(t *testing.T, userID int64, newAccessToken string) *fortaStub {
	t.Helper()
	stub := &fortaStub{}
	stub.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/refresh":
			stub.refreshCalls++
			if r.Header.Get("Authorization") != "Bearer valid-refresh-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			writeStubJSON(t, w, fortaEnvelope[AuthResponse]{
				Success: true,
				Data: AuthResponse{
					User: User{ID: userID},
					Authorization: TokenPair{
						AccessToken:  newAccessToken,
						RefreshToken: "rotated-refresh-token",
						ExpiresAt:    time.Now().Add(time.Hour),
					},
				},
			})
		case "/auth/self":
			if r.Header.Get("Authorization") != "Bearer "+newAccessToken {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			writeStubJSON(t, w, fortaEnvelope[User]{Success: true, Data: User{ID: userID}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(stub.srv.Close)
	return stub
}

func writeStubJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Fatalf("encode stub response: %v", err)
	}
}

// TestProtected_RefreshesWhenAccessCookieIsGone is the regression test for the
// bug where an expired browser session could not recover without a manual page
// reload. setAuthCookies gives the access cookie a hard Expires equal to the
// token's own lifetime, so the browser deletes it the moment the token expires
// — leaving only the seven-day refresh cookie. Protected used to see an empty
// credential and 401 immediately, never spending the refresh cookie sitting
// right there on the request.
func TestProtected_RefreshesWhenAccessCookieIsGone(t *testing.T) {
	stub := newFortaStub(t, 42, "fresh-access-token")
	c := testClient(t, func(cfg *Config) { cfg.APIDomain = stub.srv.URL })

	var gotID int64
	handler := c.Protected(func(w http.ResponseWriter, r *http.Request) {
		id, _ := GetFortaIDFromContext(r.Context())
		gotID = id
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/secrets", nil)
	// Only the refresh cookie survives — exactly what the browser sends once
	// the access cookie's Expires has passed.
	req.AddCookie(&http.Cookie{Name: cookieRefreshToken, Value: "valid-refresh-token"})
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected the request to proceed after a transparent refresh, got %d: %s",
			rec.Code, rec.Body.String())
	}
	if gotID != 42 {
		t.Errorf("expected the refreshed user ID 42 in context, got %d", gotID)
	}
	if stub.refreshCalls != 1 {
		t.Errorf("expected exactly 1 call to /auth/refresh, got %d", stub.refreshCalls)
	}

	// The rotated pair must be written back, or the next request repeats the
	// whole dance and the fix only papers over the symptom.
	var sawAccess, sawRefresh bool
	for _, ck := range rec.Result().Cookies() {
		switch ck.Name {
		case cookieAccessToken:
			sawAccess = ck.Value == "fresh-access-token"
		case cookieRefreshToken:
			sawRefresh = ck.Value == "rotated-refresh-token"
		}
	}
	if !sawAccess {
		t.Error("expected a refreshed forta-access-token cookie on the response")
	}
	if !sawRefresh {
		t.Error("expected a rotated forta-refresh-token cookie on the response")
	}
}

// TestProtected_NoCredentialAtAll confirms the fix did not turn a genuinely
// unauthenticated request into anything other than a 401.
func TestProtected_NoCredentialAtAll(t *testing.T) {
	stub := newFortaStub(t, 42, "fresh-access-token")
	c := testClient(t, func(cfg *Config) { cfg.APIDomain = stub.srv.URL })

	called := false
	handler := c.Protected(func(w http.ResponseWriter, r *http.Request) { called = true })

	rec := httptest.NewRecorder()
	handler(rec, httptest.NewRequest(http.MethodGet, "/admin/secrets", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	if called {
		t.Error("handler must not run without a credential")
	}
	if stub.refreshCalls != 0 {
		t.Errorf("expected no refresh attempt without a refresh cookie, got %d", stub.refreshCalls)
	}
}

// TestProtected_MissingTokenHonoursDisableAutoRefresh keeps the new path behind
// the same opt-out as every other refresh in this middleware.
func TestProtected_MissingTokenHonoursDisableAutoRefresh(t *testing.T) {
	stub := newFortaStub(t, 42, "fresh-access-token")
	c := testClient(t, func(cfg *Config) {
		cfg.APIDomain = stub.srv.URL
		cfg.DisableAutoRefresh = true
	})

	handler := c.Protected(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler must not run when auto-refresh is disabled")
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/secrets", nil)
	req.AddCookie(&http.Cookie{Name: cookieRefreshToken, Value: "valid-refresh-token"})
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	if stub.refreshCalls != 0 {
		t.Errorf("expected no refresh attempt when DisableAutoRefresh is set, got %d", stub.refreshCalls)
	}
}
