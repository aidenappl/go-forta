# AGENTS.md — go-forta

> `go-forta` is the **Go SDK for integrating Forta as an authentication provider**. It handles
> the full OAuth2 lifecycle — login redirect, callback, token validation, auto-refresh, logout —
> so a consuming service registers three handlers and wraps protected routes with one
> middleware call. It also exports the shared types that `forta-api` itself imports, so client
> and server cannot drift. This file orients any agent/worker before touching code in this repo.
>
> **⚠️ Golden rule — keep this file current:** any change to `Config`, the middleware
> behaviour, the exported types, or the validation strategy MUST update this AGENTS.md in the
> SAME change. Stale context here misleads every future agent.
>
> **⚠️ Blast radius:** this is a **shared library consumed by every Go service in the
> `appleby.cloud` ecosystem**. Consumers pin versions in `go.mod`, so a change is opt-in — but a
> bad tagged release that services then upgrade to breaks authentication everywhere.

---

## What this repo is

A Go module (`module github.com/aidenappl/go-forta`, `go 1.25`) published by git tag and
consumed via the Go module proxy. It is **not a service** — no `main`, no Docker image, no
deployment.

⚠️ **It contains TWO packages that answer DIFFERENT questions. Do not conflate them.**

| Package | Question it answers | Runs | Works with |
|---------|--------------------|------|-----------|
| `forta` (root) | "Is this Forta token valid, and whose is it?" | Every authenticated request | Forta only |
| `forta/sso` | "Log this person in through an identity provider" | Once at login, plus a periodic checkpoint | **Any** OIDC provider |

Use the ROOT package when your service has fully delegated identity to Forta: no local user
table, just "here is a token, tell me who it is."

Use **`sso/`** when your service has **its own user accounts** and wants SSO as a way to sign
into them. `monitor-core` is the example — native email/password accounts *and* pluggable SSO,
so it needs to run a login flow and map the result onto its own users.

A service may legitimately import both. Most import only one.

Three audiences:

1. **Consuming services (token validation)** — call `forta.Setup(...)` once, then use
   `forta.LoginHandler`, `forta.CallbackHandler`, `forta.LogoutHandler`, `forta.Protected(next)`.
2. **Consuming services (SSO login)** — implement the three interfaces in `sso/seams.go`, then
   drive `sso.GenerateState` → `sso.NewAdapter` → `Exchange` → your own session.
3. **`forta-api` itself** — imports the shared types (`FortaClaims`, `TokenPair`, `User`,
   `AuthResponse`, `OAuthUserInfoResponse`) so the wire format has exactly one definition.

## Stack & dependencies

- **Go 1.25+**
- Root `forta` package: standard library plus `github.com/golang-jwt/jwt/v5`. Two signature
  algorithms are accepted: **RS256** (issuer public key from the published JWKS — what
  `forta-api` signs with) and **HS512** (shared secret, pre-cut-over tokens only).
- `sso` package: `github.com/coreos/go-oidc/v3` (discovery, JWKS, id_token verification) and
  `golang.org/x/oauth2` (the code flow, `GenerateVerifier`, `S256ChallengeOption`,
  `VerifierOption`). `go-jose/go-jose/v4` arrives indirectly through `go-oidc`.
- `sso/ssotest`: `golang-jwt/jwt/v5` only, and **test-only**.
- No router, no SQL, no HTTP framework, no logger. Handlers are plain `http.HandlerFunc`.

⚠️ **The `sso` dependencies are module-wide, and that is the cost of keeping one repo.** A
service importing only the root package for token validation still gets `go-oidc`,
`x/oauth2` and `go-jose` in its `go.sum` and dependency graph. It does not get them in its
binary — Go links per package — and `govulncheck` is call-graph aware, so an advisory in code a
service cannot reach is not reported for it. What it does mean: a change confined to `sso/`
still produces a new module version, so token-only consumers see a version bump they did not
need. That was the accepted trade when `go-sso` was folded in rather than kept separate.

## Project structure

| Path | Role |
|------|------|
| `main.go` | Package-level `Setup()`, the default client singleton, and the package-level handler wrappers (`LoginHandler`, `Protected`, `GetUserFromContext`, …). |
| `client.go` | `Client` struct and `newClient()`; `url()`; the outbound calls `exchangeCode`, `getUserInfo` (`GET /auth/self`), `refreshTokens` (`POST /auth/refresh`). |
| `config.go` | `Config` struct — every knob a consumer can set — plus `validate()` and a secret-redacting `String()`. |
| `middleware.go` | `Protected`, `resolveAPIToken`, `tryRefresh`, `extractToken`. **The heart of the SDK.** |
| `context.go` | Unexported context keys and setters (`contextWithFortaID`, `contextWithUser`) with exported getters. |
| `api_token.go` | `APITokenPrefix`, `IsAPIToken`, and the TTL-bounded `apiTokenCache`. |
| `grant_cache.go` | `grantCache` — TTL cache for grant-check results. |
| `cookies.go` | Auth cookie read/write helpers, cookie name constants. |
| `handlers.go` | The OAuth flow handlers. |
| `token.go` | Local JWT validation. The algorithm allowlist (`allowedSigningAlgs`), the issuer allowlist (`LegacyIssuer`/`Issuer`/`DefaultAcceptedIssuers`), the HS512/RS256 dispatch in `Client.validateAccessToken`, and the legacy `validateAccessTokenLocal`. |
| `jwks.go` | `jwksCache` — lazy, in-memory JWKS client for RS256 public keys, with a rate-limited unknown-`kid` re-fetch and an independent max-age refresh. |
| `token_test.go` | The test suite. Mostly security regression tests; read the comments before changing an assertion. |
| `types.go` | Shared wire types + the `fortaEnvelope[T]` generic response wrapper. |
| `errors.go` | Error helpers, `writeJSONError`, `writeGrantDenied`. |
| `docs/implementation.md` | Full integration guide for consumers. |
| `docs/server.md` | Type-mapping guide for `forta-api`. |

### `sso/` — the SSO login flow

| Path | Role |
|------|------|
| `sso/provider.go` | `Provider` (a plain struct, **not** a schema), `Kind`, `Validate()`. The package doc lives here and states the five invariants. |
| `sso/identity.go` | `Identity`, `TokenSet`, the `Adapter` interface, `NewAdapter`. |
| `sso/seams.go` | **The three interfaces.** `StateStore`, `UserResolver`, `SessionStore`, plus the optional `LocalTokenRevoker`. Read this first. |
| `sso/state.go` | `GenerateState`, `GenerateLinkState`, `ConsumeState`, `StateData`. |
| `sso/oidc.go` | The OIDC adapter, discovery cache, claim readers, shared HTTP client and byte limits. |
| `sso/oauth2.go` | The plain-OAuth2 adapter. Strictly weaker; read its type comment before using it. |
| `sso/introspect.go` | RFC 7662 client. Distinguishes `active:false` from "no answer". |
| `sso/checkpoint.go` | `Checkpointer`, `CheckpointResult`, the interval and the bounded grace window. |
| `sso/ssotest/fakeidp.go` | A protocol-correct fake OIDC provider with per-defect failure injection. **Test-only.** |
| `sso/ssotest/store.go` | In-memory `StateStore` and `SessionStore` for tests. |

## Running, building & testing

```bash
dev build    # go build ./...
dev vet      # go vet ./...
dev test     # go test ./...
dev fmt      # gofmt -w -s .
dev tidy     # go mod tidy
```

**`token_test.go` is the only test file, and it exists to protect the JWT verification path.**
Everything else in this repo (cookies, handlers, caches) is still untested — verification there
is still "it compiles, it vets, consumers exercise it in production". Treat any behavioural
change outside `token.go`/`jwks.go` as higher-risk than the line count suggests.

The token tests are deliberately adversarial. In particular:

| Test | What it protects |
|------|------------------|
| `TestAlgConfusion_RSAPublicKeyAsHMACSecret` | The RS256→HMAC key-confusion forgery. Signs HS512 tokens with the RSA public key in five encodings (PEM, trimmed PEM, DER, raw modulus, base64 modulus) against a *primed* JWKS cache — the exact state in which a naive verifier accepts them. |
| `TestHMACAlgorithmIsHS512` | That the HMAC algorithm is **HS512**, not HS256. Narrowing the allowlist to HS256 rejects every real Forta token — a platform-wide auth outage. HS256/HS384 must be rejected even when signed with the correct secret. |
| `TestAlgNone_Rejected` | Unsigned tokens, in every config. |
| `TestUnknownKID_TriggersRefetch_ThenSucceeds` | OIDC key rotation is actually discovered. |
| `TestUnknownKID_RefetchIsRateLimited` | 25 random `kid`s produce exactly **one** JWKS fetch. |
| `TestHS512_StillVerifies_NoJWKSRequest` | An unchanged HS512 consumer makes **zero** JWKS requests — the `httptest` handler fails the test if it is hit at all. |
| `TestJWKSMaxAge_WithdrawnKeyStopsVerifying` | **Revocation propagates.** A key the issuer withdraws (empty published set, or replaced by another key) stops verifying once the max age passes. Time is injected via the cache's unexported `now` field — never sleep here. |
| `TestJWKSMaxAge_HonoursCacheControl` | `Cache-Control: max-age` wins over `JWKSMaxAge`, and is clamped to 5m–24h. |
| `TestJWKSMaxAge_RefreshFailureKeepsServingCachedKeys` | A failed refresh serves the stale keys (no platform-wide outage) but does **not** extend the entry's age. |
| `TestJWKSMaxAge_IndependentOfUnknownKIDRateLimit` | The two refresh triggers are independent: with `JWKSMinRefreshInterval` at 24h the age refresh still fires, and it does **not** reset the rate limit — 25 unknown `kid`s afterwards drive zero extra fetches. |
| `TestAcceptedIssuers` | Both issuers verify, unrelated/empty/trailing-slash/lookalike issuers are rejected, and an explicit `AcceptedIssuers` list is honoured exactly. |

Never "fix" a failing test here by relaxing an assertion. Each one encodes an attack.

## How code is written here

- **Package-level API over a singleton.** `Setup()` builds a default `Client`; the exported
  package functions delegate to it. Methods also hang off `*Client` for multi-tenant use.
- **Context keys are unexported**, with exported getters only (`GetFortaIDFromContext`,
  `GetUserFromContext`). This is deliberate: **a consuming service cannot inject its own
  identity into the context**. That constraint is why adding API-token support had to happen
  here rather than in `keyring-api` — no downstream service could have done it alone.
- **Caches are `sync.Map` + TTL**, following the `grantCache` shape. No eviction goroutine;
  entries are checked lazily on read and deleted when stale.
- **Failure posture is explicit per path.** Grant-check *network* errors deny the request
  (`checkGrant` error → `writeGrantDenied`), while a stale cache entry simply triggers a
  re-check. Do not change a fail-closed path to fail-open without saying so loudly.
- **Never log token values.** `Config.String()` deliberately redacts; keep it that way.

## Domain & architecture

### `Protected` — the decision tree

`extractToken` reads the `Authorization: Bearer` header (accepting an `frt_`-prefixed opaque
token, or a string with exactly two dots — guarding against literal `"Bearer undefined"` from
browsers), falling back to the `forta-access-token` cookie. Then:

| Credential | Path | Notes |
|-----------|------|-------|
| **`frt_` API token** | Always **remote** — `resolveAPIToken` → `GET /auth/self`, memoized in `apiTokenCache` | Carries no claims, so it *cannot* be validated locally. Never auto-refreshed — long-lived by design. |
| **Access JWT, `JWTSigningKey` set (or `EnableJWKS`)** | **Local** verify, dispatching on the JWS `alg` header | HS512 → shared `JWTSigningKey`, no network. RS256 → issuer public key by `kid` from the JWKS. On expiry, `tryRefresh` uses the refresh cookie unless `DisableAutoRefresh`. |
| **Access JWT, no `JWTSigningKey`, `EnableJWKS` false** | **Remote** — `getUserInfo` | Full `User` profile lands in context. Unchanged. |

Then optional grant enforcement (`EnforceGrants`), then `contextWithFortaID` / `contextWithUser`.

**API-token support (v1.3.0) is checked first, before the `JWTSigningKey` branch.** This matters:
services like `keyring-api` set `JWTSigningKey` and therefore take the local path for JWTs, but
still resolve `frt_` tokens remotely. No configuration is needed to enable it — upgrading the
module is sufficient.

### JWT verification — algorithm dispatch (v1.4.0)

`Client.validateAccessToken` parses the token **once**, with an explicit algorithm allowlist,
and selects key material from the *verified* method type:

| `alg` | Key material | Network |
|-------|--------------|---------|
| `HS512` | `Config.JWTSigningKey` (shared secret) | none |
| `RS256` | Issuer public key, looked up by the token's `kid` in the cached JWKS | lazy fetch on first RS256 token / unknown `kid` |
| anything else, incl. `none` | — rejected before the keyfunc runs — | none |

Two independent controls make this safe, and **both must stay**:

1. `jwt.WithValidMethods(allowedSigningAlgs)` on every `ParseWithClaims` call. The parser
   rejects a token whose `alg` is not in the list *before* any key is selected, which kills
   `alg: none` and any future downgrade.
2. A **type switch on `t.Method`** inside the keyfunc — `*jwt.SigningMethodHMAC` returns only
   the shared secret, `*jwt.SigningMethodRSA` returns only a JWKS public key. An RSA public key
   can therefore never reach an HMAC verifier. Without this, an attacker signs an HS512 token
   using the published RSA public key as the HMAC secret and it validates as genuine.

**`allowedSigningAlgs` is a security boundary, not a config knob. Do not widen it.** It is
`{"RS256", "HS512"}` — HS512 because that is literally what `forta-api` signs with
(`forta/jwt.forta.go`: `jwt.SigningMethodHS512`). Adding HS256 "for compatibility" adds attack
surface for an algorithm the issuer never emits. Narrowing it to HS256 by mistake rejects every
real token in production.

### The JWKS cache

`jwks.go`. Fetches `{APIDomain}/oauth/jwks` (override with `Config.JWKSURL`), caches
`kid → *rsa.PublicKey` in memory.

- **Lazy.** The cache is constructed in `newClient` but performs **no I/O** until the first
  RS256 token is actually presented. `Setup()` never gains a network dependency on `forta-api`,
  and an HS512-only consumer never makes a single JWKS request. This is deliberate and load
  bearing — `keyring-api` is the boot-time secret source for the whole platform, so the SDK
  must not add a startup dependency in either direction.
There are **two independent re-fetch triggers**, and they must stay independent. Merging them, or
letting one reset the other's clock, reintroduces either a DoS amplifier or an unrevocable key.

- **Trigger 1 — unknown `kid` (rotation).** An unknown `kid` triggers a re-fetch, which is how
  OIDC Core §10.1.1 rotation is meant to work: the OP publishes a new key and RPs discover it on
  first use. **Rate-limited** to at most one fetch per `JWKSMinRefreshInterval` (default **5
  minutes**) across the whole key set. This is a security control: without it an attacker sending
  tokens with random `kid` values turns every relying party into a DoS amplifier against the JWKS
  endpoint. The cost is that a rotated key is discovered up to that long after publication — so
  `forta-api` must overlap old and new keys for longer than this interval. Guarded by
  `lastAttempt`, which **only** this trigger reads or writes.
- **Trigger 2 — max age (revocation).** A cached key set older than its max age is re-fetched
  before use. **Not** rate-limited by `JWKSMinRefreshInterval`: the trigger is the clock, not
  attacker input, so it cannot amplify anything, and it never touches `lastAttempt`.
  - The max age is `Config.JWKSMaxAge` (default `DefaultJWKSMaxAge`, **1 hour**), overridden by
    the response's `Cache-Control: max-age` when present and clamped to **5 minutes – 24 hours**
    (`forta-api` serves `public, max-age=3600`).
  - **Why it exists:** before it, a `kid` already in the cache was *never* revalidated — no TTL,
    no `Cache-Control` handling — so a signing key the issuer had withdrawn kept verifying tokens,
    making no further network request, for the life of the process. Planned rotation was fine
    (long overlap); **emergency revocation had no propagation mechanism at all.** Key removal now
    propagates within the max age.
  - **Failure posture is fail-open, without an age extension.** A failed refresh keeps serving the
    cached keys — an unreachable JWKS endpoint must not become a platform-wide outage — and does
    **not** update `fetchedAt`, so the entry stays stale and a later request retries. A short
    backoff (`lastFailure`, its own clock, `minRefresh` long) stops a downed endpoint from costing
    every request a fetch timeout.
  - **An empty published key set is honoured when a set is already cached.** `{"keys":[]}` is how
    the issuer performs an emergency revocation; ignoring it would defeat the entire mechanism.
    It is still an error on the *first* fetch, so a misconfigured endpoint fails loudly at first
    use rather than silently reporting every `kid` as unknown.
- **Bounded.** 5s timeout, 1 MiB body limit, non-200 is an error. A single malformed key entry is
  skipped rather than discarding the whole set.
- A token with **no `kid`** is rejected without any fetch.
- Concurrent misses for the same `kid` collapse into one fetch (`fetchMu`).
- **The clock is injectable.** `jwksCache.now` (unexported, defaults to `time.Now`) exists so the
  age tests advance time instead of sleeping. Do not add `time.Sleep` to these tests.

### Token issuer — migration COMPLETE (v1.5.0)

`parseAccessToken` checks `iss` against an allowlist rather than a single constant.

| `iss` | Exported as | Status |
|-------|-------------|--------|
| `https://auth.appleby.cloud` | `Issuer` | **The only default.** The `issuer` in `forta-api`'s OIDC discovery document. |
| `forta:auth-service` | `LegacyIssuer` | **Retired in v1.5.0** — no longer accepted by default. Constant retained; must be named explicitly. |

Comparison is exact — no normalisation of scheme, case, or trailing slash, because OIDC Core
§3.1.3.7 requires an exact match. `Config.AcceptedIssuers` overrides the default **exactly**,
with no defaults merged in.

**The dual-acceptance window ran from v1.4.0 to v1.5.0.** v1.4.0 accepted both so the fleet
needed exactly one redeploy; `forta-api` has minted the URL form on every token since
2026-07-28; v1.5.0 narrows the default to that value alone.

⚠️ **What narrowing costs, stated plainly.** A *refresh* token minted before the cut-over lives
seven days, so one could still be presented until 2026-08-04. Presenting it now fails and the
user logs in again. That is the entire cost — a forced re-login for a session idle since before
the cut-over, **not** a service outage. An active session re-mints both tokens on every refresh,
so anyone who has used the platform since 2026-07-28 rolled over automatically.

A service that cannot absorb even that can opt back in explicitly:

```go
cfg.AcceptedIssuers = []string{forta.LegacyIssuer, forta.Issuer}
```

That escape hatch is covered by a test, so it cannot rot. Nothing in the fleet uses it.

### RS256 + issuer migration — ordering matters

`forta-api` is moving from HS512-with-a-shared-secret to RS256-with-a-published-JWKS, **and**
from the `forta:auth-service` issuer to `https://auth.appleby.cloud`.

> **⚠️ This SDK version must reach EVERY consumer BEFORE `forta-api` either flips to RS256 or
> changes its token issuer.** A consumer still on an older go-forta sees an RS256 token, fails
> the `*jwt.SigningMethodHMAC` check, and rejects every request; it also hard-compares `iss`
> against `forta:auth-service` and rejects the URL form outright. **Upgrade `keyring-api`
> first** — it is the boot-time secret source for the entire platform, so if it cannot validate a
> Forta token, nothing starts.

Rollout order:

1. Tag this SDK; bump **every** consumer's `go.mod` and redeploy, `keyring-api` first. Nothing
   changes behaviourally — the change is strictly additive, tokens are still HS512 and still
   carry the legacy issuer. **This is the single fleet-wide redeploy; both migrations depend on
   it, which is why they ship together.**
2. `forta-api` publishes `/oauth/jwks` while still signing HS512.
3. `forta-api` flips to RS256. Consumers pick up the key on the first RS256 token.
4. `forta-api` changes `iss` to `https://auth.appleby.cloud`. Consumers already accept it.
5. Only once all consumers are on RS256, drop the shared secret from deployments and set
   `EnableJWKS: true` (which enables local validation with no `JWTSigningKey` at all).
6. ~~Once no live token carries `forta:auth-service`, drop `LegacyIssuer` from the defaults.~~
   **Done in v1.5.0.**

Do not reorder these steps.

⚠️ **Step 5 has a trap on the `forta-api` side, and it is not this SDK's to fix.** `forta-api`
cannot drop `JWT_SIGNING_KEY` when its consumers do: that variable is `getEnvRequired` there
*and* still signs the internal OAuth request token, so removing it stops the server booting and
breaks `/oauth/authorize`. Consumers dropping `FORTA_JWT_SIGNING_KEY` is a separate, safe action.
Do not read "drop the shared secret from deployments" as including the identity provider's own
copy.

### Scope — this is not a generic OIDC client

`jwks.go` is deliberately **Forta-specific** and deliberately **not** a general-purpose OIDC/JWKS
library. There is no discovery document (`/.well-known/openid-configuration`) support, no `aud`
negotiation, no EC or symmetric JWK handling, no `x5c` chain validation — the issuer is a single
known service, `typ: access` is hardcoded, and the `iss` allowlist is a fixed two-entry default
(overridable, but not discovered). If you need generic OIDC, use a generic library; do not grow
this one into one.

### Cache TTLs and revocation latency

| Cache | Config | Default | What the TTL bounds |
|-------|--------|---------|--------------------|
| `apiTokenCache` | `APITokenCacheTTL` | 60s | How long a **revoked API token keeps working** in this service |
| `grantCache` | `GrantCacheTTL` | 30s | How long a **revoked grant keeps working** |
| `jwksCache` | `JWKSMinRefreshInterval` | 5m | How long after a **signing-key rotation** the new key is still unknown here (and the floor on JWKS request rate under `kid` flooding) |
| `jwksCache` | `JWKSMaxAge` | 1h (or the response's `Cache-Control: max-age`, clamped 5m–24h) | How long a **withdrawn signing key keeps verifying tokens** here — i.e. emergency revocation latency |

These are all the same trade: lower TTL = tighter revocation, more round-trips to Forta. State the
number when discussing revocation — "immediate" is only true at `forta-api` itself.

### Versioning

Tagged releases consumed via the Go module proxy, which caches immutably.

**`v1.2.0` was already published, pointing at a commit predating API-token support.** Because
proxy entries cannot be rewritten, that feature shipped as **v1.3.0**. Never retag a published
version — cut a new one.

**RS256/JWKS support plus dual-issuer acceptance is a minor bump — `v1.4.0`.** It adds exported
surface (`Config.JWKSURL`, `Config.JWKSMinRefreshInterval`, `Config.JWKSMaxAge`,
`Config.AcceptedIssuers`, `Config.EnableJWKS`, `DefaultJWKSMinRefreshInterval`,
`DefaultJWKSMaxAge`, `DefaultAcceptedIssuers`, `LegacyIssuer`, `Issuer`, `ErrUnknownKeyID`) with
zero-value-means-previous-behaviour defaults. Nothing is renamed or removed, and an HS512 consumer
that upgrades and changes no configuration behaves identically — including making **zero** JWKS
requests. The only behavioural widening is that `https://auth.appleby.cloud` is now also an
accepted `iss`, which no token carries yet.

## The `sso` package — SSO login

### Why it exists

Three services each grew their own SSO flow, and the copies drifted in ways a working login does
not reveal:

| Defect found | Consequence |
|---|---|
| A PKCE verifier generated, then dropped at the token exchange | PKCE configured, visible in logs, defending nothing |
| Identity keyed on **email** rather than `(provider, subject)` | Account takeover as soon as an address is reassigned |
| `nonce` never verified — `go-oidc`'s `Verify()` does not check it | id_token injection across sessions |
| No bound on trusting a stale introspection result | Revocation unenforceable whenever the IdP path can be degraded |

Every one is silent. The fix is not more review; it is one implementation where the defended path
is the only path.

### The five invariants — not configurable, by design

1. Identity is `(Provider, Subject)`. **Never email.**
2. PKCE S256 is always generated and always sent.
3. `nonce` is always verified on an id_token.
4. `state` is single-use, server-side, never derived from a cookie.
5. A UserInfo `sub` that differs from the id_token `sub` **discards the whole response**
   (OIDC Core §5.3.2).

Each was found missing in something already in production. There is no option to switch any off.

### The flow

```
GenerateState ──▶ AuthCodeURL ──▶ [browser → IdP] ──▶ callback
                                                         │
                                    ConsumeState ◀────────┘
                                          │
                                     Exchange ──▶ Identity
                                                     │
                                            UserResolver.ResolveUser
                                                     │
                                             your session
```

Then, on subsequent requests: `Checkpointer.Check`.

### The three seams

The package knows nothing about users, sessions or schemas — deliberately, because the three
adopting services have three different ones and one has no provider table at all.

| Interface | You provide | The hazard if you get it wrong |
|---|---|---|
| `StateStore` | Atomic single-use storage for in-flight logins | **A non-atomic `ConsumeState` lets a replayed state authenticate alongside the real callback.** `SELECT` then `DELETE` does *not* satisfy it — use one conditional statement and let the row lock arbitrate. |
| `UserResolver` | identity → your user, provisioning, linking | Linking without **both** sides' emails verified is pre-account-takeover: an attacker plants an unverified native account on the victim's address, and the victim's later SSO login binds onto it. |
| `SessionStore` | Cached IdP tokens for the checkpoint | Returning an error instead of `(nil, nil)` for a native login **logs out every non-SSO user**. |

`LocalTokenRevoker` is optional. Implement it if your app issues tokens that outlive the session
row — otherwise the checkpoint detects revocation and changes nothing.

`Provider` is a plain struct, not a schema: each application maps its own storage onto it, which
is what lets a service with no provider table use this at all. `ClientSecret` is the RESOLVED
secret, because every service resolves it differently (Keyring reference, AES-GCM column, plain
env var) and a library owning that would need to know all three.

### The checkpoint: why neither fail-open nor fail-closed

| Introspection says | Result | Reasoning |
|---|---|---|
| `active: false` | **Revoked, immediately** | The IdP was reachable, authenticated us, and said the grant is gone. The one unambiguous signal. **No grace.** |
| No answer, inside grace | **OK** | Fail-closed makes this service less available than the IdP and hands anyone who can disrupt that link a logout button. |
| No answer, past grace | **Unavailable** | Unbounded fail-open makes revocation unenforceable exactly when it matters. |
| Non-2xx from introspection | **Not a revocation** | A 401 means *our* credentials are wrong; a 500 means the IdP is broken. Reading either as revocation logs out the platform in response to our own misconfiguration. |

Defaults: `CheckpointInterval` 5 min, `CheckpointGrace` 30 min. The grace clock runs from
`LastCheckedAt` — the last time an answer was actually obtained — never from now, because
measuring from now restarts the window on every failed attempt and a permanently unreachable IdP
would grant permanent access.

⚠️ **`CheckpointUnavailable` maps to HTTP 503, not 401.** A 401 tells clients to discard
credentials and re-authenticate — against the IdP that is already down. Ten thousand clients
doing that is a thundering herd arriving when the IdP can least absorb it, and the users are
logged out for a problem that was never theirs.

### Testing: why the fixture is a server

`sso/ssotest.FakeIDP` speaks the real protocol over `httptest`. A mocked `Adapter` would assert
that the code calls the functions the code calls — and every defect above was a **missing
protocol step** a mock has no opinion about. A mock has no token endpoint to notice an absent
verifier, no id_token to put a wrong nonce in, and no second identity to conflict with the first.

`FakeIDP` injects one specific misbehaviour per field: `OmitIDToken`, `WrongNonce`,
`WrongAudience`, `WrongIssuer`, `ExpiredIDToken`, `UnsignedIDToken`, `UnknownKID`,
`UserInfoSubject`, `IgnorePKCE`, `IntrospectActive`, `IntrospectStatus`.

⚠️ **`IgnorePKCE` is the most important one.** It models a real authorization server that does
not enforce PKCE — the only condition under which a client's dropped verifier goes unnoticed. A
suite that only ever talks to a strict server cannot distinguish "the client sent the verifier"
from "the server rejected the client", so it cannot prove the client sends it.

#### The suite is mutation-tested, and that is the acceptance criterion

Assertions that cannot fail are worse than absent ones. Each defence was removed in turn and the
corresponding test confirmed to fail:

| Mutation | Test that caught it |
|---|---|
| `oauth2.VerifierOption` dropped from `Exchange` | `TestPKCE_VerifierIsActuallySent` |
| nonce comparison deleted | `TestNonce_MismatchIsRejected` |
| UserInfo `sub` comparison disabled | `TestUserInfo_SubjectMustMatchIDToken` |
| grace window removed (unbounded fail-open) | `TestCheckpoint_BoundedFailOpen` |

**Re-run that check when you change a defence.** A green suite is necessary and not sufficient;
the question is whether it would go red.

## Ecosystem & related repos

| Repo | Relationship |
|------|--------------|
| [`forta-api`](https://github.com/aidenappl/forta-api) | The server. **Imports this module** for shared types — changes to `types.go` affect both sides. |
| [`forta-js`](https://github.com/aidenappl/forta-js) | The Node/React equivalent; keep behaviour conceptually aligned. |
| `keyring-api` | Consumer. Delegates **all** `/admin` auth to `forta.Protected`; gained API-token support purely by bumping to v1.3.0. |
| `lattice-api`, `monitor-core` | Consumers via their own SSO wiring. |
| `openbucket-api` | **Not** a consumer of `Protected` — it has its own user table and JWT key, and treats Forta as a generic OIDC provider. |

## Operations

- **Not deployed.** Released by tag:
  ```bash
  git tag -a v1.x.y -m "..." && git push origin v1.x.y
  ```
  then confirm the proxy has it: `curl https://proxy.golang.org/github.com/aidenappl/go-forta/@v/list`
- **The sumdb lags a freshly pushed tag by seconds to minutes.** A `go get` immediately after
  tagging can fail with a 500 from `sum.golang.org` — retry rather than reaching for
  `GONOSUMDB`.
- **Rollout is opt-in.** Nothing changes for a consumer until it bumps `go.mod`.

## Rules & guardrails

- **Never retag or move a published version.** The module proxy caches immutably; consumers
  may already have the old bytes.
- **Never export the context setters.** Keeping them unexported is a deliberate boundary.
- **Never log or print token values**, and keep `Config.String()` redacting.
- **Never change a fail-closed auth path to fail-open** without an explicit decision recorded
  here.
- **Changing `types.go` is a two-repo change** — `forta-api` imports these types and will fail
  to compile if a field moves.
- **Adding a `Config` field must stay backward compatible** — zero value means "previous
  behaviour". `APITokenCacheTTL <= 0` falling back to the default is the pattern to copy.
- **Never widen `allowedSigningAlgs`.** It is `{"RS256", "HS512"}` and it is a security
  boundary. Adding an algorithm the issuer does not emit is pure attack surface; removing HS512
  is a platform-wide outage.
- **Never return a key from the keyfunc without switching on `t.Method`**, and never make the
  JWKS fetch eager (at package init or in `Setup`) — both are documented above with the reason.
- **Never merge the two JWKS refresh triggers**, and never let one write the other's clock. The
  unknown-`kid` limit (`lastAttempt`) is the DoS control; the max age (`fetchedAt`) is the
  revocation control. Gating the age refresh behind the rate limit makes a compromised key
  unrevocable; gating the rate limit on the age makes the SDK a traffic amplifier.
- **Never fail closed on a JWKS refresh error**, and never update `fetchedAt` on a failed
  attempt — the first turns an endpoint blip into a platform outage, the second silently grants a
  withdrawn key another full max age.
- **Do not "normalise" the `iss` comparison** (trailing slash, case, scheme). OIDC Core §3.1.3.7
  requires an exact match; loosening it accepts lookalike issuers.
- **No tests exist outside `token_test.go`.** If you touch `middleware.go`, say so plainly in
  the handoff; there is no safety net for the cookie/handler/cache paths.

### `sso` package guardrails

- **Do not add a configuration flag that weakens one of the five invariants.** Not "allow plain
  PKCE", not "skip nonce for provider X", not "merge UserInfo anyway". Each was already missing
  somewhere and each was a real vulnerability.
- **Do not key identity on anything reassignable.** `Provider.SubjectClaim` exists for providers
  with a non-standard *stable* claim name. Pointing it at an email or username is the takeover
  bug with extra steps.
- **Do not import a database driver, HTTP framework, or logger into `sso/`.** The seams exist so
  this stays true, and the root package's leanness is the reason consumers tolerate the module.
- **Do not weaken `StateStore.ConsumeState`'s atomicity requirement**, or implement it as
  `SELECT` then `DELETE` in an adopting service.
- **Do not collapse "no answer" into `active: false`.** Different facts, different correct
  responses; conflating them is a platform-wide logout.
- **Do not make `CheckpointUnavailable` a 401.**
- **`sso/ssotest` is test-only.** It signs with a per-instance key and accepts any client secret.
  Never import it outside a test binary.

## Verification — always before "done"

```bash
gofmt -w .
go build ./...
go vet ./...
go test ./...
go test -race ./...
```

Then verify against a **real consumer**, because compiling proves very little for this module:

```bash
cd ../keyring-api && go get github.com/aidenappl/go-forta@<version> && go build ./... && go vet ./...
```

For auth-path changes, exercise the deployed consumer end-to-end. The definitive check for
API-token support is that a bogus `frt_` token returns the *specific* error string from this
SDK's path:

```bash
curl -H "Authorization: Bearer frt_notarealtoken" https://keys.appleby.cloud/admin/secrets
# {"success":false,"error_message":"invalid or expired api token"}
```

**Never report work complete on a compile alone.**

## Keeping this file updated

Update this AGENTS.md in the same change when you:
- **Change the algorithm allowlist, the issuer allowlist, the keyfunc dispatch, or either JWKS
  refresh trigger** → update *JWT verification*, *The JWKS cache*, *Token issuer*, and the TTL
  table. These are the sections an agent reads before touching auth.
- **Add/change a `Config` field** → update *Domain & architecture* and the TTL table.
- **Change `Protected`'s decision tree or `extractToken`** → update the credential table.
- **Add or change a cache** → update the TTL/revocation table; those numbers get quoted in
  incident discussions.
- **Change anything in `types.go`** → note the `forta-api` co-change requirement.
- **Cut a release** → record the version and what changed, including any tag-numbering
  irregularity (as with the v1.2.0/v1.3.0 skip).
- Also keep `README.md` and `docs/implementation.md` in sync — they are what consumers read.
