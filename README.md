# go-forta

Go SDK for the Forta identity platform: **token validation** for services that delegate auth to
Forta, and a **complete SSO login flow** for services that keep their own user accounts.

> **appleby.cloud platform** · Go SDK · `github.com/aidenappl/go-forta`

---

⚠️ **Two packages, two different jobs.** Pick the one that matches your question:

| Package | Question it answers | Runs | Works with |
|---------|--------------------|------|-----------|
| `forta` (root) | "Is this Forta token valid, and whose is it?" | Every authenticated request | Forta only |
| [`forta/sso`](sso) | "Log this person in through an identity provider" | Once at login, plus a periodic checkpoint | **Any** OIDC provider |

Use the **root** package when your service has fully delegated identity to Forta — no local user
table, just "here is a token, tell me who it is."

Use **`sso`** when your service has **its own** user accounts and wants SSO as a way to sign into
them. A service may import both; most import one.

## Installation

```sh
go get github.com/aidenappl/go-forta
```

**Requires Go 1.22+**

---

## Quick start

```go
import forta "github.com/aidenappl/go-forta"

func main() {
    err := forta.Setup(forta.Config{
        APIDomain:    "https://auth.appleby.cloud",
        LoginDomain:  "https://forta.appleby.cloud",
        ClientID:     "my-client-id",
        ClientSecret: "my-client-secret",
        CallbackURL:  "https://myapp.example.com/forta/callback",
    })
    if err != nil {
        log.Fatal(err)
    }

    mux := http.NewServeMux()
    mux.HandleFunc("/forta/login",    forta.LoginHandler)
    mux.HandleFunc("/forta/callback", forta.CallbackHandler)
    mux.HandleFunc("/forta/logout",   forta.LogoutHandler)

    mux.HandleFunc("/api/me", forta.Protected(handleMe))

    log.Fatal(http.ListenAndServe(":8080", mux))
}

func handleMe(w http.ResponseWriter, r *http.Request) {
    id, _ := forta.GetFortaIDFromContext(r.Context())
    fmt.Fprintf(w, "Hello, user %d", id)
}
```

---

## SSO login (`forta/sso`)

Runs the relying-party half of an OAuth2/OIDC login against **any** compliant provider, and hands
you a normalized identity. It knows nothing about your users: three interfaces in
[`sso/seams.go`](sso/seams.go) are the whole contract, so you keep your own schema and session
model.

```go
import sso "github.com/aidenappl/go-forta/sso"

p := &sso.Provider{
    Slug:         "forta",
    DisplayName:  "Appleby Cloud",
    Kind:         sso.KindOIDC,
    IssuerURL:    "https://auth.appleby.cloud",
    ClientID:     clientID,
    ClientSecret: clientSecret,
    RedirectURL:  "https://app.example/auth/sso/callback",

    AllowAutoLink: true, // verified-both-sides only
    AutoProvision: true, // creates a pending account
}

// 1. Start a login.
state, nonce, verifier, err := sso.GenerateState(ctx, stateStore, p.Slug, returnURL)
adapter, err := sso.NewAdapter(ctx, p)
url, err := adapter.AuthCodeURL(state, nonce, verifier)

// 2. Handle the callback.
sd, err := sso.ConsumeState(ctx, stateStore, r.URL.Query().Get("state"))
id, tokens, err := adapter.Exchange(ctx, r.URL.Query().Get("code"), sd.Verifier, sd.Nonce)
userID, err := resolver.ResolveUser(ctx, p, *id)

// 3. On subsequent requests.
switch checkpointer.Check(ctx, userID) {
case sso.CheckpointOK:          // proceed
case sso.CheckpointRevoked:     // 401, end the session
case sso.CheckpointUnavailable: // 503 + Retry-After — NOT 401
}
```

### Five invariants, none configurable

1. Identity is `(Provider, Subject)` — **never email**.
2. PKCE S256 is always generated and always sent.
3. `nonce` is always verified on an id_token.
4. `state` is single-use and server-side.
5. A UserInfo `sub` that disagrees with the id_token discards the whole response
   (OIDC Core §5.3.2).

Each was found missing in an implementation already running in production, where a working login
revealed nothing. That is the argument for a shared package here.

⚠️ **`returnURL` must already be sanitised** — this package stores and returns it verbatim and
cannot tell a same-site path from an attacker's host. An unsanitised value is an open redirect at
the end of an authenticated flow.

⚠️ **`CheckpointUnavailable` is a 503, not a 401.** A 401 sends every client to re-authenticate
against the identity provider that is already down.

Full details — the seams, the checkpoint decision table, and why the test fixture is a real
server rather than a mock — in [`AGENTS.md`](AGENTS.md).

### Back-channel logout (optional, and the checkpoint is not enough without it)

The checkpoint above re-introspects every 5 minutes, so a revoked grant keeps working for up to
5 minutes. **OIDC Back-Channel Logout 1.0** closes that window: the provider pushes a signed
`logout_token` the moment the grant is revoked.

```go
// 1. Implement the OPTIONAL interface on your existing SessionStore.
func (s *SessionStore) DeleteSessionsBySID(ctx context.Context, provider, sid string) (int, error)
func (s *SessionStore) DeleteSessionsBySubject(ctx context.Context, provider, sub string) (int, error)

// 2. Mount the handler and register its URL with the provider.
bcl := &sso.BackchannelLogout{Sessions: store, Providers: lookup}
r.Handle("/auth/sso/backchannel-logout", bcl.Handler("forta"))
```

It is a **separate optional interface** rather than methods on `SessionStore` so adopting it is
not forced on every consumer at once. A store that does not implement it gets a **501** — said
plainly, because a silent 200 would tell the provider its notifications are landing while every
one is discarded.

⚠️ Do not hand-roll the receiver. It is an endpoint with no cookie and no bearer token, whose only
authentication is the signature, and the rule most implementations miss is that §2.4 **forbids
`nonce`** — a logout token carrying one can be replayed into the id_token position and accepted as
a fresh authentication. `sso/backchannel_test.go` asserts refusal of that and five other attacks.

## Documentation

| Document                                         | Description                                                                                                                                                   |
| ------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [docs/implementation.md](docs/implementation.md) | Complete integration guide — all `Config` options, cookie strategies, bearer tokens, local vs remote validation, and testing patterns.                        |
| [docs/server.md](docs/server.md)                 | Server-side migration guide for `forta-api` — how shared types (`FortaClaims`, `TokenPair`, `User`, etc.) map from the old structs to `go-forta` equivalents. |
| [forta-api `docs/onboarding-a-consumer.md`](https://github.com/aidenappl/forta-api/blob/main/docs/onboarding-a-consumer.md) | **What the provider requires of you** — registering a platform, mandatory PKCE, `aud` checking, opaque refresh handles, and the four mechanisms that end a session. Read it before writing an integration; this README covers the SDK, that one covers the contract. |

---

## How it works

1. **`forta.LoginHandler`** — Redirects the browser to the Forta OAuth2 authorisation endpoint. Stores a CSRF state token in a short-lived HttpOnly cookie.
2. **`forta.CallbackHandler`** — Validates the CSRF state, exchanges the authorisation code for a token pair via `POST /auth/exchange`, and writes `forta-access-token` / `forta-refresh-token` HttpOnly cookies.
3. **`forta.Protected(next)`** — Middleware that reads the token from the `Authorization: Bearer` header or the `forta-access-token` cookie. Validates locally (no network) when `JWTSigningKey` is set, otherwise calls `/oauth/userinfo`. Transparently refreshes expired tokens.
4. **`forta.LogoutHandler`** — Clears auth cookies and redirects.

---

## API tokens

Since **v1.3.0**, `Protected` also accepts long-lived opaque Forta API tokens — the `frt_`-prefixed credentials minted by `POST /admin/api-tokens`. These are what CLIs, CI jobs and MCP servers use in place of the 10-minute access JWT.

They carry no claims, so they cannot be validated locally. `Protected` resolves them against `/auth/self` and caches the result:

```go
forta.Setup(forta.Config{
    // …
    APITokenCacheTTL: 60 * time.Second, // default
})
```

The TTL bounds revocation latency: a token revoked in Forta keeps working here for at most that long. Set it lower for tighter revocation at the cost of more round-trips. API tokens are never auto-refreshed — they are long-lived by design.

No configuration is required to enable this; a service on v1.3.0+ accepts both credential forms automatically. `forta.IsAPIToken(s)` reports whether a given credential is one.

---

## Token verification: HS512 and RS256

Since **v1.4.0**, local validation dispatches on the token's JWS `alg` header:

| `alg` | Verified with | Network |
| ----- | ------------- | ------- |
| `HS512` | `Config.JWTSigningKey` — the shared secret | none |
| `RS256` | The issuer's public key, looked up by `kid` in the JWKS at `{APIDomain}/oauth/jwks` | lazy fetch, cached |
| anything else, including `none` | rejected | none |

**This is additive.** A service that upgrades and changes no configuration behaves exactly as
before: Forta issues HS512 tokens today, so the HS512 path runs and **no JWKS request is ever
made**. The key set is fetched lazily on the first RS256 token — never at `Setup()`.

```go
forta.Setup(forta.Config{
    // …
    JWTSigningKey: os.Getenv("FORTA_JWT_SIGNING_KEY"),

    // All optional — the defaults are correct for every real deployment.
    JWKSURL:                "",              // default: {APIDomain}/oauth/jwks
    JWKSMinRefreshInterval: 5 * time.Minute, // default
    JWKSMaxAge:             1 * time.Hour,   // default
    EnableJWKS:             false,           // set true only once the shared secret is gone
})
```

### Rotation

An unknown `kid` triggers one re-fetch of the key set — this is how signing-key rotation is
picked up — and that re-fetch is rate-limited to once per `JWKSMinRefreshInterval` so a flood of
forged `kid` values cannot turn your service into a DoS amplifier against Forta.

### Revocation

**Previously, a `kid` already in the cache was never revalidated** — there was no TTL and no
`Cache-Control` handling — so a signing key the issuer had *withdrawn* kept verifying tokens,
with no further network request, for the life of the process. Rotation worked; emergency
revocation had no propagation mechanism.

Cached key sets now have a max age (`JWKSMaxAge`, default **1 hour**, overridden by the JWKS
response's `Cache-Control: max-age` when present, clamped to 5 minutes–24 hours). Once the entry
ages out, the next RS256 token re-fetches before verifying, so **a key removed from the published
set stops verifying within the max age**.

The age trigger is independent of the unknown-`kid` rate limit and does not weaken it. If a
refresh fails, the cached keys keep being served — an unreachable JWKS endpoint must not become a
platform-wide outage — and the failed attempt does not extend the entry's age, so it retries.

---

## Token issuer

One issuer value is accepted by default, as of v1.5.0:

| `iss` | Status |
| ----- | ------ |
| `https://auth.appleby.cloud` | **The only default** — the `issuer` in `forta-api`'s OIDC discovery document. |
| `forta:auth-service` | **Retired in v1.5.0** — no longer accepted by default. Name it in `Config.AcceptedIssuers` to accept it. |

`forta:auth-service` was never an https URL, so it could never be an OIDC discovery issuer, and
OIDC Core §3.1.3.7 requires an id_token's `iss` to equal the discovery issuer exactly. v1.4.0
accepted both so the fleet redeployed once; `forta-api` has minted the URL form since
2026-07-28, and v1.5.0 drops the old value.

A refresh token minted before that cut-over could still be presented until 2026-08-04; it now
fails and the user logs in again. That is a forced re-login for an idle session, not an outage —
an active session rolled over automatically on its first refresh.

`forta.DefaultAcceptedIssuers()` returns the default list. `Config.AcceptedIssuers` overrides it
exactly — no defaults are merged in.

> **⚠️ Upgrade before the server changes anything.** `forta-api` will flip to RS256 **and** move
> its token issuer to `https://auth.appleby.cloud`. Every consumer must be on v1.4.0+ **before**
> either change lands; an older SDK rejects RS256 tokens and the URL issuer outright. Upgrade
> `keyring-api` first — it is the boot-time secret source for the whole platform, so if it cannot
> validate a Forta token, nothing starts.

---

## Shared types

The following types are exported for use by both client services and the Forta auth server itself:

| Type                          | Description                                                                          |
| ----------------------------- | ------------------------------------------------------------------------------------ |
| `forta.User`                  | Public user profile as returned by `/oauth/userinfo` and `/auth/exchange`            |
| `forta.UserMetadata`          | Supplementary profile fields (username, phone)                                       |
| `forta.TokenPair`             | Access + refresh token pair with expiry metadata                                     |
| `forta.AuthResponse`          | Full response from `/auth/exchange` and `/auth/refresh` (user + token pair)          |
| `forta.FortaClaims`           | JWT claims payload — used for both signing (server) and local validation (client)    |
| `forta.OAuthUserInfoResponse` | OIDC userinfo response body — used by the server to write and by the client to parse |

---

## License

MIT
