package sso_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	sso "github.com/aidenappl/go-forta/sso"
	"github.com/aidenappl/go-forta/sso/ssotest"
)

func farFuture() time.Time { return time.Now().Add(time.Hour) }
func longPast() time.Time  { return time.Now().Add(-time.Hour) }

// newCheckpointer wires a Checkpointer at a fake IdP with a session already
// established for user 1.
func newCheckpointer(t *testing.T, idp *ssotest.FakeIDP, lastChecked time.Time, mutate func(*sso.Checkpointer)) (*sso.Checkpointer, *ssotest.MemorySessionStore) {
	t.Helper()
	ctx := context.Background()

	sessions := ssotest.NewMemorySessionStore()
	if err := sessions.SaveSession(ctx, 1, sso.Session{
		Provider:      "fake",
		Subject:       idp.Subject,
		Tokens:        sso.TokenSet{AccessToken: "a", RefreshToken: "r"},
		LastCheckedAt: lastChecked,
	}); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}

	c := &sso.Checkpointer{
		Sessions: sessions,
		Providers: func(_ context.Context, slug string) (*sso.Provider, error) {
			if slug != "fake" {
				return nil, fmt.Errorf("no such provider %q", slug)
			}
			return &sso.Provider{
				Slug:          "fake",
				Kind:          sso.KindOIDC,
				IssuerURL:     idp.Issuer(),
				IntrospectURL: idp.Issuer() + "/introspect",
				ClientID:      testClientID,
				ClientSecret:  "test-secret",
				RedirectURL:   "https://rp.test/cb",
			}, nil
		},
		// Silence the logs during tests; the assertions are on results.
		Logf: func(string, ...any) {},
	}
	if mutate != nil {
		mutate(c)
	}
	return c, sessions
}

// TestCheckpoint_NonSSOSessionPasses is the single most dangerous case to get
// wrong.
//
// A native password login has no session row. If (nil, nil) were treated as an
// error or as a revocation, the checkpoint would log out every non-SSO user on the
// platform — a total outage caused by a feature that only concerns SSO users.
func TestCheckpoint_NonSSOSessionPasses(t *testing.T) {
	idp := ssotest.NewFakeIDP(t)
	c, _ := newCheckpointer(t, idp, time.Now(), nil)

	// User 999 has no session row at all.
	if got := c.Check(context.Background(), 999); got != sso.CheckpointOK {
		t.Fatalf("Check = %v, want ok. A user with no SSO session is a NATIVE login, and denying them logs out everyone who never used SSO.", got)
	}
}

func TestCheckpoint_RecentlyCheckedSkipsTheNetwork(t *testing.T) {
	idp := ssotest.NewFakeIDP(t)
	// Introspection would return active:false, so a result of OK proves no call was
	// made rather than proving the call succeeded.
	idp.IntrospectActive = false

	c, _ := newCheckpointer(t, idp, time.Now(), nil)

	if got := c.Check(context.Background(), 1); got != sso.CheckpointOK {
		t.Fatalf("Check = %v, want ok — a session checked seconds ago must not be re-introspected", got)
	}
}

func TestCheckpoint_ActiveGrantPasses(t *testing.T) {
	idp := ssotest.NewFakeIDP(t)
	c, sessions := newCheckpointer(t, idp, longPast(), nil)

	if got := c.Check(context.Background(), 1); got != sso.CheckpointOK {
		t.Fatalf("Check = %v, want ok", got)
	}

	sess, err := sessions.LoadSession(context.Background(), 1)
	if err != nil || sess == nil {
		t.Fatalf("session should survive an active check: %v", err)
	}
	if time.Since(sess.LastCheckedAt) > time.Minute {
		t.Fatal("LastCheckedAt was not updated, so every subsequent request will re-introspect")
	}
}

// TestCheckpoint_InactiveGrantRevokesImmediately covers the one unambiguous
// signal in the whole mechanism.
func TestCheckpoint_InactiveGrantRevokesImmediately(t *testing.T) {
	idp := ssotest.NewFakeIDP(t)
	idp.IntrospectActive = false

	// LastCheckedAt is recent enough to be INSIDE the grace window — proving grace
	// does not apply to a definitive negative.
	c, sessions := newCheckpointer(t, idp, time.Now().Add(-10*time.Minute), func(c *sso.Checkpointer) {
		c.Interval = time.Nanosecond // force a check
	})

	if got := c.Check(context.Background(), 1); got != sso.CheckpointRevoked {
		t.Fatalf("Check = %v, want revoked. active:false is definitive and the grace window must NOT apply to it — grace exists for 'no answer', not for 'the answer was no'.", got)
	}

	sess, err := sessions.LoadSession(context.Background(), 1)
	if err != nil {
		t.Fatalf("LoadSession: %v", err)
	}
	if sess != nil {
		t.Fatal("the session survived a definitive revocation")
	}
	if sessions.RevokedCount() != 1 {
		t.Fatalf("RevokeLocalTokens called %d times, want 1. Without it, an application that issues its own tokens keeps honouring them after the upstream grant is gone.", sessions.RevokedCount())
	}
}

// TestCheckpoint_MissingRevokerIsTolerated covers an application that does not
// implement the optional hook.
func TestCheckpoint_MissingRevokerIsTolerated(t *testing.T) {
	idp := ssotest.NewFakeIDP(t)
	idp.IntrospectActive = false

	c, sessions := newCheckpointer(t, idp, longPast(), nil)
	c.Sessions = ssotest.WithoutRevoker(sessions)

	if got := c.Check(context.Background(), 1); got != sso.CheckpointRevoked {
		t.Fatalf("Check = %v, want revoked", got)
	}
	if sessions.RevokedCount() != 0 {
		t.Fatal("RevokeLocalTokens was called on a store that does not implement it")
	}
}

// TestCheckpoint_BoundedFailOpen is the core of the design: an unreachable IdP is
// survivable, but not forever.
func TestCheckpoint_BoundedFailOpen(t *testing.T) {
	tests := []struct {
		name        string
		lastChecked time.Duration // how long ago
		want        sso.CheckpointResult
		why         string
	}{
		{
			name:        "inside_the_grace_window_passes",
			lastChecked: 5 * time.Minute,
			want:        sso.CheckpointOK,
			why:         "an IdP blip must not log everyone out; fail-closed makes this service strictly less available than the IdP and hands anyone who can disrupt that link a logout button",
		},
		{
			name:        "just_inside_the_boundary_passes",
			lastChecked: sso.CheckpointGrace - time.Minute,
			want:        sso.CheckpointOK,
			why:         "still within the window",
		},
		{
			name:        "past_the_grace_window_is_unavailable",
			lastChecked: sso.CheckpointGrace + time.Minute,
			want:        sso.CheckpointUnavailable,
			why:         "unbounded fail-open makes revocation unenforceable exactly when it matters — an attacker who degrades introspection keeps their session forever",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idp := ssotest.NewFakeIDP(t)
			// A 503 from introspection is "no answer", NOT active:false.
			idp.IntrospectStatus = http.StatusServiceUnavailable

			c, _ := newCheckpointer(t, idp, time.Now().Add(-tt.lastChecked), func(c *sso.Checkpointer) {
				c.Interval = time.Nanosecond
			})

			if got := c.Check(context.Background(), 1); got != tt.want {
				t.Fatalf("Check = %v, want %v. %s", got, tt.want, tt.why)
			}
		})
	}
}

// TestCheckpoint_TransportErrorIsNotARevocation is the distinction the whole
// design rests on.
func TestCheckpoint_TransportErrorIsNotARevocation(t *testing.T) {
	idp := ssotest.NewFakeIDP(t)
	// A 500 is our problem or theirs, but it is NOT the user's grant being revoked.
	idp.IntrospectStatus = http.StatusInternalServerError

	c, sessions := newCheckpointer(t, idp, time.Now().Add(-6*time.Minute), func(c *sso.Checkpointer) {
		c.Interval = time.Nanosecond
	})

	got := c.Check(context.Background(), 1)
	if got == sso.CheckpointRevoked {
		t.Fatal("a 5xx from introspection was read as a revocation. Our own misconfiguration — or the IdP's bad day — would log out every user on the platform.")
	}

	sess, err := sessions.LoadSession(context.Background(), 1)
	if err != nil {
		t.Fatalf("LoadSession: %v", err)
	}
	if sess == nil {
		t.Fatal("the session was deleted on a transport error")
	}
}

// TestCheckpoint_NeverCheckedIsUnavailable covers the session with no
// last-known-good.
func TestCheckpoint_NeverCheckedIsUnavailable(t *testing.T) {
	idp := ssotest.NewFakeIDP(t)
	idp.IntrospectStatus = http.StatusServiceUnavailable

	// Zero LastCheckedAt.
	c, _ := newCheckpointer(t, idp, time.Time{}, nil)

	if got := c.Check(context.Background(), 1); got != sso.CheckpointUnavailable {
		t.Fatalf("Check = %v, want unavailable. There is no last-known-good to fail open ONTO — the session has never been confirmed against the IdP at all.", got)
	}
}

// TestCheckpoint_ProviderWithoutIntrospectionPasses covers the honest gap.
func TestCheckpoint_ProviderWithoutIntrospectionPasses(t *testing.T) {
	idp := ssotest.NewFakeIDP(t)
	c, _ := newCheckpointer(t, idp, longPast(), func(c *sso.Checkpointer) {
		inner := c.Providers
		c.Providers = func(ctx context.Context, slug string) (*sso.Provider, error) {
			p, err := inner(ctx, slug)
			if err != nil {
				return nil, err
			}
			p.IntrospectURL = ""
			return p, nil
		}
	})

	if got := c.Check(context.Background(), 1); got != sso.CheckpointOK {
		t.Fatalf("Check = %v, want ok. A provider that cannot be introspected cannot be checked; denying every session using it would be a self-inflicted outage.", got)
	}
}

func TestCheckpointResult_String(t *testing.T) {
	// The string form appears in logs, so a wrong mapping makes an incident report
	// say the opposite of what happened.
	for _, tt := range []struct {
		r    sso.CheckpointResult
		want string
	}{
		{sso.CheckpointOK, "ok"},
		{sso.CheckpointRevoked, "revoked"},
		{sso.CheckpointUnavailable, "unavailable"},
	} {
		if got := tt.r.String(); got != tt.want {
			t.Errorf("String() = %q, want %q", got, tt.want)
		}
	}
}
