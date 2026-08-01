package sso

import (
	"context"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// BackchannelLogoutTarget is an OPTIONAL extra interface a SessionStore may
// implement to receive back-channel logout notifications.
//
// ─────────────────────────────────────────────────────────────────────────────
// ⚠️ IT IS A SEPARATE, OPTIONAL INTERFACE RATHER THAN METHODS ON SessionStore,
// AND THAT IS DELIBERATE.
//
// Every consumer in the estate already implements SessionStore. Adding methods
// to it would break all of them at once and force each to ship a logout receiver
// before it could take any other update — coupling an opt-in capability to an
// unrelated upgrade. Same reasoning as LocalTokenRevoker.
//
// A store that does not implement this simply does not accept push logout:
// Handler answers 501 and logs why, rather than answering 200 and discarding the
// notification. Such a consumer stays on the introspection checkpoint, which is
// slower but correct.
// ─────────────────────────────────────────────────────────────────────────────
type BackchannelLogoutTarget interface {
	// DeleteSessionsBySID ends the single session with this OIDC session id.
	//
	// Return (0, nil) when there is no such session. That is the NORMAL outcome
	// of a duplicate delivery or a session that already ended, and must not be
	// an error — the spec requires a 200 for a logout that had nothing to do.
	DeleteSessionsBySID(ctx context.Context, provider, sid string) (int, error)

	// DeleteSessionsBySubject ends EVERY session this subject holds with the
	// provider. Used when the notification names no `sid`, which is the correct
	// shape for a subject-wide event such as an administrator revoking a grant.
	DeleteSessionsBySubject(ctx context.Context, provider, subject string) (int, error)
}

// replayWindow is how long a processed `jti` is remembered.
//
// It only has to outlive the sender's retry schedule — a duplicate arriving
// after every retry has been exhausted is not a duplicate, it is a new event
// that happens to share an id, which cannot occur because ids are random. Forta
// gives its logout tokens a two-minute life and retries within it; fifteen
// minutes is generous margin against clock skew between the two servers.
const replayWindow = 15 * time.Minute

// replayCache remembers processed token ids.
//
// ⚠️ IN-MEMORY, THEREFORE PER-PROCESS. Two replicas do not share it, so a
// duplicate delivered to a different replica is processed twice. That is
// ACCEPTABLE HERE and would not be for most caches: processing a logout twice
// deletes an already-deleted session, which is idempotent. The cache exists to
// avoid pointless work and to satisfy the spec's "should detect replay", not to
// prevent a harmful outcome.
type replayCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func newReplayCache() *replayCache {
	return &replayCache{seen: make(map[string]time.Time)}
}

// observe records id and reports whether it had already been seen.
func (c *replayCache) observe(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	// Swept inline rather than by a goroutine: the map only grows on logout
	// events, which are rare, and a background ticker for this would be a
	// lifecycle to own for no benefit.
	for k, t := range c.seen {
		if now.Sub(t) > replayWindow {
			delete(c.seen, k)
		}
	}

	if _, dup := c.seen[id]; dup {
		return true
	}
	c.seen[id] = now
	return false
}

// logoutVerifierSource is implemented by the OIDC adapter only.
type logoutVerifierSource interface {
	LogoutVerifier() *oidc.IDTokenVerifier
}

// BackchannelLogout is the receiving half of OIDC Back-Channel Logout 1.0.
//
// Construct one per application and mount Handler() at the URL registered with
// the provider as `backchannel_logout_uri`.
//
// Shaped like Checkpointer — a struct with a Providers lookup rather than a
// constructor — for the same reason: a provider whose client secret rotates is
// re-resolved rather than cached here forever.
type BackchannelLogout struct {
	Sessions  SessionStore
	Providers func(ctx context.Context, slug string) (*Provider, error)

	// Logf defaults to log.Printf.
	//
	// ⚠️ Nothing here logs a token or a claim value beyond the `jti` and `sid`,
	// which are opaque identifiers and not credentials.
	Logf func(format string, args ...any)

	once  sync.Once
	cache *replayCache
}

func (b *BackchannelLogout) logf(format string, args ...any) {
	if b.Logf != nil {
		b.Logf(format, args...)
		return
	}
	log.Printf(format, args...)
}

// Handler returns the endpoint for one provider.
//
// ⚠️ THIS ENDPOINT IS UNAUTHENTICATED IN THE ORDINARY SENSE — there is no cookie
// and no bearer token. Its authentication IS the signature on the logout token:
// issued by the provider, signed with a key from its JWKS, and addressed to this
// client_id. That is why nothing below acts on a single field before
// VerifyLogout has returned.
func (b *BackchannelLogout) Handler(providerSlug string) http.Handler {
	b.once.Do(func() { b.cache = newReplayCache() })
	cache := b.cache

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		if r.Method != http.MethodPost {
			// §2.5 is form-encoded POST only. A GET here is a misconfiguration
			// or a probe; either way it must not be treated as a logout.
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}

		target, ok := b.Sessions.(BackchannelLogoutTarget)
		if !ok {
			// Said plainly rather than pretending to succeed. A 200 here would
			// tell the provider its notifications are landing while every one is
			// discarded, and the resulting "revocation does not work" would be
			// invisible from both ends.
			b.logf("WARN SSO_BACKCHANNEL_UNSUPPORTED: a logout notification arrived for provider %q "+
				"but the SessionStore does not implement BackchannelLogoutTarget, so it cannot be acted on. "+
				"Sessions will end only when the introspection checkpoint next runs.", providerSlug)
			http.Error(w, "back-channel logout is not implemented by this deployment", http.StatusNotImplemented)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "malformed form body", http.StatusBadRequest)
			return
		}
		raw := r.PostFormValue("logout_token")
		if raw == "" {
			http.Error(w, "logout_token is required", http.StatusBadRequest)
			return
		}

		p, err := b.Providers(ctx, providerSlug)
		if err != nil {
			b.logf("WARN SSO_BACKCHANNEL_PROVIDER_FAILED: provider %q: %v", providerSlug, err)
			http.Error(w, "provider unavailable", http.StatusServiceUnavailable)
			return
		}

		adapter, err := NewAdapter(ctx, p)
		if err != nil {
			b.logf("WARN SSO_BACKCHANNEL_ADAPTER_FAILED: provider %q: %v", providerSlug, err)
			http.Error(w, "provider unavailable", http.StatusServiceUnavailable)
			return
		}

		// ⚠️ OAUTH2 PROVIDERS CANNOT SUPPORT THIS AT ALL. Back-channel logout is
		// an OIDC mechanism: the notification's only authentication is a
		// signature verified against the issuer's JWKS, and a plain OAuth2
		// provider publishes neither. Accepting an unverifiable POST here would
		// hand anyone who can reach this URL the ability to log out any user by
		// guessing a subject.
		src, ok := adapter.(logoutVerifierSource)
		if !ok {
			b.logf("WARN SSO_BACKCHANNEL_NOT_OIDC: provider %q is not an OIDC provider, so a logout "+
				"token cannot be verified and will not be acted on", providerSlug)
			http.Error(w, "back-channel logout requires an OIDC provider", http.StatusNotImplemented)
			return
		}

		// VerifyLogout enforces the §2.4 rules that matter: signature against the
		// issuer's JWKS, `iss`, `aud` against our client_id, `exp`, the required
		// `events` member, and — critically — THAT NO `nonce` IS PRESENT. A logout
		// token carrying a nonce could otherwise be replayed into the id_token
		// position and accepted as a fresh authentication.
		token, err := src.LogoutVerifier().VerifyLogout(ctx, raw)
		if err != nil {
			b.logf("WARN SSO_BACKCHANNEL_REJECTED: provider %q sent an unverifiable logout token: %v", providerSlug, err)
			http.Error(w, "invalid logout_token", http.StatusBadRequest)
			return
		}

		// A duplicate is a SUCCESS, not an error. The sender re-sends the
		// identical token when it cannot record an acknowledgement, and answering
		// 400 would make it retry until exhausted and then report the receiver as
		// broken — for a message it had already delivered.
		if cache.observe(token.TokenID) {
			b.logf("SSO_BACKCHANNEL_DUPLICATE: provider %q re-sent jti=%s; already processed", providerSlug, token.TokenID)
			logoutOK(w)
			return
		}

		// ⚠️ `sid` FIRST, `sub` ONLY AS A FALLBACK, and the order is the whole
		// semantics. A token naming a session means "end THAT session"; falling
		// through to the subject would sign the user out of every other session
		// they hold — turning a targeted revocation into a global one and
		// producing surprise logouts nobody asked for.
		var ended int
		switch {
		case token.SessionID != "":
			ended, err = target.DeleteSessionsBySID(ctx, providerSlug, token.SessionID)
		case token.Subject != "":
			ended, err = target.DeleteSessionsBySubject(ctx, providerSlug, token.Subject)
		default:
			// VerifyLogout already requires one of them, so this is unreachable
			// unless that guarantee changes.
			http.Error(w, "logout_token names neither a subject nor a session", http.StatusBadRequest)
			return
		}

		if err != nil {
			// A real failure. 500 so the sender RETRIES — this is the one case
			// where retrying is what we want, because the session is still live.
			b.logf("WARN SSO_BACKCHANNEL_APPLY_FAILED: provider %q, jti=%s: %v", providerSlug, token.TokenID, err)
			http.Error(w, "could not end the session", http.StatusInternalServerError)
			return
		}

		// Zero sessions ended is NORMAL: the session may have expired, been
		// logged out locally, or never existed on this node. Logged, not failed —
		// there is nothing for a retry to achieve.
		b.logf("SSO_BACKCHANNEL_APPLIED: provider %q ended %d session(s) (jti=%s, sid=%q)",
			providerSlug, ended, token.TokenID, token.SessionID)
		logoutOK(w)
	})
}

// logoutOK writes the §2.7 success response.
//
// The no-store headers are required by the spec and are not decoration: a cached
// 200 on this URL would let an intermediary answer a future logout notification
// without it ever reaching this server.
func logoutOK(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
}
