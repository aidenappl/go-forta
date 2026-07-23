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

A small, dependency-light Go module (`module github.com/aidenappl/go-forta`, `go 1.22`)
published by git tag and consumed via the Go module proxy. It is **not a service** — there is
no `main`, no Docker image, no deployment.

Two audiences:

1. **Consuming services** — call `forta.Setup(...)` once, then use `forta.LoginHandler`,
   `forta.CallbackHandler`, `forta.LogoutHandler`, and `forta.Protected(next)`.
2. **`forta-api` itself** — imports the shared types (`FortaClaims`, `TokenPair`, `User`,
   `AuthResponse`, `OAuthUserInfoResponse`) so the wire format has exactly one definition.

## Stack & dependencies

- **Go 1.22+**, standard library plus a single direct dependency:
  `github.com/golang-jwt/jwt/v5` v5.2.2 (HMAC-SHA512).
- No router, no SQL, no HTTP framework. Handlers are plain `http.HandlerFunc`.

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
| `token.go` | Local JWT validation helpers. |
| `types.go` | Shared wire types + the `fortaEnvelope[T]` generic response wrapper. |
| `errors.go` | Error helpers, `writeJSONError`, `writeGrantDenied`. |
| `docs/implementation.md` | Full integration guide for consumers. |
| `docs/server.md` | Type-mapping guide for `forta-api`. |

## Running, building & testing

```bash
dev build    # go build ./...
dev vet      # go vet ./...
dev test     # go test ./...   (currently: no test files)
dev fmt      # gofmt -w -s .
dev tidy     # go mod tidy
```

**There are no tests in this repo.** That is a real gap for a library that gates authentication
everywhere. Verification today is: it compiles, it vets, and consumers exercise it in
production. Treat any behavioural change here as higher-risk than the line count suggests.

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
| **Access JWT, `JWTSigningKey` set** | **Local** HMAC-SHA512 verify, no network | Fast path. On expiry, `tryRefresh` uses the refresh cookie unless `DisableAutoRefresh`. |
| **Access JWT, no `JWTSigningKey`** | **Remote** — `getUserInfo` | Full `User` profile lands in context. |

Then optional grant enforcement (`EnforceGrants`), then `contextWithFortaID` / `contextWithUser`.

**API-token support (v1.3.0) is checked first, before the `JWTSigningKey` branch.** This matters:
services like `keyring-api` set `JWTSigningKey` and therefore take the local path for JWTs, but
still resolve `frt_` tokens remotely. No configuration is needed to enable it — upgrading the
module is sufficient.

### Cache TTLs and revocation latency

| Cache | Config | Default | What the TTL bounds |
|-------|--------|---------|--------------------|
| `apiTokenCache` | `APITokenCacheTTL` | 60s | How long a **revoked API token keeps working** in this service |
| `grantCache` | `GrantCacheTTL` | 30s | How long a **revoked grant keeps working** |

Both are the same trade: lower TTL = tighter revocation, more round-trips to Forta. State the
number when discussing revocation — "immediate" is only true at `forta-api` itself.

### Versioning

Tagged releases consumed via the Go module proxy, which caches immutably.

**`v1.2.0` was already published, pointing at a commit predating API-token support.** Because
proxy entries cannot be rewritten, that feature shipped as **v1.3.0**. Never retag a published
version — cut a new one.

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
- **No tests exist.** If you touch `middleware.go`, say so plainly in the handoff; there is no
  safety net.

## Verification — always before "done"

```bash
gofmt -w .
go build ./...
go vet ./...
go test ./...   # no test files today, but must stay green
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
- **Add/change a `Config` field** → update *Domain & architecture* and the TTL table.
- **Change `Protected`'s decision tree or `extractToken`** → update the credential table.
- **Add or change a cache** → update the TTL/revocation table; those numbers get quoted in
  incident discussions.
- **Change anything in `types.go`** → note the `forta-api` co-change requirement.
- **Cut a release** → record the version and what changed, including any tag-numbering
  irregularity (as with the v1.2.0/v1.3.0 skip).
- Also keep `README.md` and `docs/implementation.md` in sync — they are what consumers read.
