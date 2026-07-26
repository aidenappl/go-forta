# go-forta — Implementation Guide

This document covers everything a client service needs to integrate Forta as its authentication provider using `go-forta`.

---

## Table of contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Setup](#setup)
4. [Config reference](#config-reference)
5. [Registering handlers](#registering-handlers)
6. [Protecting routes](#protecting-routes)
7. [Reading identity from context](#reading-identity-from-context)
8. [Token validation strategies](#token-validation-strategies)
9. [Cookie configuration](#cookie-configuration)
10. [Using multi-service instances](#using-multi-service-instances)
11. [Fetching the user profile on demand](#fetching-the-user-profile-on-demand)
12. [Optional Forta authentication](#optional-forta-authentication)
13. [Error responses](#error-responses)

---

## Prerequisites

- A **platform** registered in the Forta admin panel with a `client_id`, `client_secret`, and an allowed redirect URI matching your `CallbackURL`.
- Go **1.22** or later.

---

## Installation

```sh
go get github.com/aidenappl/go-forta
```

---

## Setup

Call `forta.Setup` once at application startup, before any HTTP handlers are registered.

```go
import forta "github.com/aidenappl/go-forta"

func main() {
    if err := forta.Setup(forta.Config{
        APIDomain:    os.Getenv("FORTA_API_DOMAIN"),   // e.g. "https://auth.appleby.cloud"
        LoginDomain:  os.Getenv("FORTA_LOGIN_DOMAIN"), // e.g. "https://forta.appleby.cloud"
        ClientID:     os.Getenv("FORTA_CLIENT_ID"),
        ClientSecret: os.Getenv("FORTA_CLIENT_SECRET"),
        CallbackURL:  "https://myapp.example.com/forta/callback",
    }); err != nil {
        log.Fatal("forta setup:", err)
    }

    // Optional: verify the Forta API is reachable before accepting traffic.
    if err := forta.Ping(); err != nil {
        log.Fatal("forta unreachable:", err)
    }
}
```

`Setup` validates that `APIDomain`, `LoginDomain`, `ClientID`, and `ClientSecret` are non-empty. It returns an error without panicking so you can handle it as part of your normal startup sequence.

---

## Config reference

```go
forta.Config{
    // --- Required ---

    // Base URL of the Forta API server — used for token exchange, validation, and user info.
    APIDomain: "https://auth.appleby.cloud",

    // Base URL of the Forta login UI — used to build the OAuth2 authorization redirect.
    LoginDomain: "https://forta.appleby.cloud",

    // OAuth2 client credentials issued when registering your platform.
    ClientID:     "...",
    ClientSecret: "...",

    // Full URL Forta redirects to after login. Must match the registered redirect URI.
    // Required for external (non-first-party) services that use the code flow.
    CallbackURL: "https://myapp.example.com/forta/callback",

    // --- Optional ---

    // Where to redirect the user after CallbackHandler completes. Default: "/"
    PostLoginRedirect: "/dashboard",

    // Where to redirect the user after LogoutHandler completes. Default: "/"
    PostLogoutRedirect: "/",

    // Base URL of the application using go-forta (e.g. "https://myapp.appleby.cloud").
    // When set, it is used as the origin for all redirect URIs constructed by the library,
    // preventing open-redirect attacks via manipulated Host headers. Recommended in production.
    AppDomain: "https://myapp.appleby.cloud",

    // Domain attribute for auth cookies.
    // Use ".appleby.cloud" on first-party services to share the session across subdomains.
    // Leave empty for site-scoped cookies (default behaviour).
    CookieDomain: ".appleby.cloud",

    // Set to true only for local HTTP development. Disables the Secure flag on cookies.
    CookieInsecure: false,

    // HMAC-SHA512 key shared with forta-api.
    // When set, tokens are validated in-process with no network call.
    // When empty (default), each Protected request calls /auth/self.
    JWTSigningKey: os.Getenv("FORTA_JWT_SIGNING_KEY"),

    // When JWTSigningKey is set, also call /auth/self to populate
    // the full User in context (at the cost of a network call per request).
    FetchUserOnProtect: false,

    // Prevents automatic transparent token refresh on expiry. Default: false (refresh enabled).
    DisableAutoRefresh: false,

    // --- RS256 / JWKS (v1.4.0+, all optional) ---

    // Where the issuer's public JSON Web Key Set is fetched from.
    // Default: "{APIDomain}/oauth/jwks" — correct for every real deployment.
    JWKSURL: "",

    // Minimum time between two JWKS fetches triggered by an unknown key id.
    // Default: 5 minutes. This is a rate limit, not a cache TTL — see below.
    JWKSMinRefreshInterval: 5 * time.Minute,

    // How long a cached key set is served before it is re-fetched.
    // Default: 1 hour, overridden by the response's Cache-Control max-age when
    // present (clamped to 5m–24h). This bounds how long a REVOKED signing key
    // keeps verifying tokens here. Independent of JWKSMinRefreshInterval.
    JWKSMaxAge: time.Hour,

    // Enables local validation with NO shared secret at all (RS256 only).
    // Leave false until forta-api has flipped to RS256 and you have removed
    // JWTSigningKey from the deployment. Not needed to accept RS256 tokens.
    EnableJWKS: false,

    // --- Issuer acceptance (v1.4.0+, optional) ---

    // Overrides the accepted "iss" claim values. Empty (the default) accepts
    // BOTH "forta:auth-service" (legacy, what tokens carry today) and
    // "https://auth.appleby.cloud" (the OIDC discovery issuer, the target).
    // A non-empty list is used exactly as given — no defaults are merged in.
    AcceptedIssuers: nil,
}
```

---

## Local validation: HS512 and RS256

When `JWTSigningKey` is set (or `EnableJWKS` is true), `Protected` verifies the JWT in-process
and dispatches on the token's `alg` header:

| `alg` | Verified with | Network |
| ----- | ------------- | ------- |
| `HS512` | `JWTSigningKey`, the shared secret | none |
| `RS256` | Issuer public key, by `kid`, from the JWKS | lazy fetch, then cached in memory |
| anything else, including `none` | rejected | none |

Nothing changes for an existing service. Forta issues HS512 tokens today, so the HS512 path
runs and **the JWKS endpoint is never contacted**. The key set is fetched lazily the first time
an RS256 token actually arrives — never at `Setup()`, so upgrading does not add a startup
dependency on `forta-api`.

**Key rotation.** A token carrying a `kid` that is not in the cache triggers one re-fetch of the
key set, so a newly published signing key is discovered on first use. That re-fetch is
rate-limited to once per `JWKSMinRefreshInterval` (default 5 minutes) across the whole key set,
so an attacker cannot use forged `kid` values to drive unbounded traffic at Forta. The trade-off
is that a rotated key can take up to that long to be picked up.

**Do not lower `JWKSMinRefreshInterval` to near-zero in production** — that is exactly the DoS
amplification the limit exists to prevent.

**Key revocation.** Rotation and revocation are different problems, and only the first is solved
by the unknown-`kid` re-fetch. **Previously, a `kid` that was already cached was never
revalidated** — no TTL, no `Cache-Control` handling — so a signing key the issuer had withdrawn
kept verifying tokens, with no further network request, for the life of the process. Emergency
revocation had no propagation mechanism at all.

Cached key sets now carry a max age (`JWKSMaxAge`, default **1 hour**, overridden by the JWKS
response's `Cache-Control: max-age` when present and clamped to 5 minutes–24 hours; `forta-api`
serves `max-age=3600`). Once the entry is older than that, the next RS256 token re-fetches
before verifying, so **a key removed from the published set stops verifying within the max age**.

This is a **separate trigger** from the unknown-`kid` rate limit and does not weaken it: the age
clock is driven by time, not by attacker-supplied `kid` values, and an age-based refresh never
touches the rate limit's clock. A flood of forged `kid`s still produces at most one fetch per
`JWKSMinRefreshInterval`.

If a refresh fails, the existing cached keys keep being served — an unreachable JWKS endpoint
must not become a platform-wide outage. A failed attempt does not extend the entry's age, so it
retries (subject to a short backoff so a downed endpoint does not cost every request a timeout).

## Token issuer

The `iss` claim is checked against an allowlist. By default **both** of these are accepted:

| Issuer | Status |
| ------ | ------ |
| `forta:auth-service` | **Legacy** — what tokens carry today. Transitional; it is not an https URL, so it can never be an OIDC discovery issuer. |
| `https://auth.appleby.cloud` | **Target** — the `issuer` published in `forta-api`'s OIDC discovery document. OIDC Core §3.1.3.7 requires an id_token's `iss` to equal it exactly. |

Accepting both means the issuer migration needs exactly one fleet redeploy: ship this SDK, roll
it everywhere, then change what `forta-api` emits. `forta.DefaultAcceptedIssuers()` returns the
list; `Config.AcceptedIssuers` overrides it exactly.

> **⚠️ Upgrade ordering.** `forta-api` is migrating from HS512 to RS256 **and** will move its
> token issuer to `https://auth.appleby.cloud`. Every service must be on v1.4.0+ **before**
> either change lands — an older go-forta rejects RS256 tokens outright and rejects the URL
> issuer outright. `keyring-api` first: it is the boot-time secret source for the platform.

---

## Registering handlers

Register the three built-in handlers at the routes that match your `CallbackURL` and your preferred login/logout paths.

```go
mux.HandleFunc("/forta/login",    forta.LoginHandler)
mux.HandleFunc("/forta/callback", forta.CallbackHandler)
mux.HandleFunc("/forta/logout",   forta.LogoutHandler)
```

### What each handler does

**`LoginHandler`**
Redirects the browser to `{Domain}/oauth/authorize` with `response_type=code`, your `ClientID`, `CallbackURL`, and a random CSRF `state` value stored in a short-lived HttpOnly cookie.

**`CallbackHandler`**

1. Reads the `code` and `state` query parameters Forta appended to the redirect.
2. Validates `state` against the CSRF cookie — rejects mismatches with `400 Bad Request`.
3. Calls `POST {Domain}/auth/exchange` with your client credentials and the code.
4. Writes `forta-access-token` and `forta-refresh-token` HttpOnly cookies.
5. Redirects to `Config.PostLoginRedirect`.

**`LogoutHandler`**
Expires both auth cookies and redirects to `Config.PostLogoutRedirect`.

---

## Protecting routes

Wrap any `http.HandlerFunc` with `forta.Protected`:

```go
mux.HandleFunc("/api/resource", forta.Protected(handleResource))
```

Requests without a valid token receive `401 Unauthorized` with a JSON body:

```json
{ "error": "missing or invalid authorization" }
```

The token is read from (in order):

1. `Authorization: Bearer <token>` header — only accepted if it is a valid 3-part JWT.
2. `forta-access-token` cookie.

### Auto-refresh

By default, if the access token is expired **and** a valid `forta-refresh-token` cookie is present, the middleware calls `POST {Domain}/auth/refresh` transparently, sets new cookies, and allows the request to continue. The user never sees a 401 due to normal token rotation.

Disable this behaviour per-service with `Config.DisableAutoRefresh: true`.

---

## Reading identity from context

Inside a handler wrapped by `Protected`:

```go
func handleResource(w http.ResponseWriter, r *http.Request) {
    // Always available when Protected succeeds.
    fortaID, ok := forta.GetFortaIDFromContext(r.Context())
    if !ok {
        // Should not happen inside Protected, but guard anyway.
        http.Error(w, "unauthenticated", http.StatusUnauthorized)
        return
    }

    // Full User profile — only available when:
    //   - JWTSigningKey is empty (remote /auth/self validation), OR
    //   - FetchUserOnProtect: true
    user, hasUser := forta.GetUserFromContext(r.Context())
    if hasUser {
        fmt.Fprintf(w, "Hello, %s", user.Email)
    } else {
        fmt.Fprintf(w, "Hello, user %d", fortaID)
    }
}
```

| Function                           | Returns               | Available when                                  |
| ---------------------------------- | --------------------- | ----------------------------------------------- |
| `forta.GetFortaIDFromContext(ctx)` | `(int64, bool)`       | Always inside `Protected`                       |
| `forta.GetUserFromContext(ctx)`    | `(*forta.User, bool)` | Remote validation or `FetchUserOnProtect: true` |

---

## Token validation strategies

### Remote validation (default)

```go
forta.Setup(forta.Config{
    APIDomain:   "https://auth.appleby.cloud",
    LoginDomain: "https://forta.appleby.cloud",
    ClientID:     "...",
    ClientSecret: "...",
    CallbackURL:  "...",
    // JWTSigningKey omitted — validates via /auth/self
})
```

- Every protected request makes one HTTP call to `GET {APIDomain}/auth/self`.
- The full `forta.User` profile is always available in context via `GetUserFromContext`.
- No shared secret needed — simplest configuration.

### Local validation

```go
forta.Setup(forta.Config{
    // ...
    JWTSigningKey: os.Getenv("FORTA_JWT_SIGNING_KEY"),
})
```

- Tokens are validated in-process using HMAC-SHA512 — no network round-trip.
- Only the Forta user ID is placed in context (`GetFortaIDFromContext`).
- Add `FetchUserOnProtect: true` to also fetch the full profile (adds one network call per request, same as remote validation but with the benefit of local expiry pre-check).

**Recommendation:** Use local validation with `FetchUserOnProtect: false` for high-throughput APIs where the user ID is sufficient. Use remote validation (or `FetchUserOnProtect: true`) when you need display-name or email data on every request.

---

## Cookie configuration

### Cross-subdomain (first-party services)

Services hosted on `*.appleby.cloud` can share the same Forta session cookie:

```go
forta.Setup(forta.Config{
    // ...
    CookieDomain: ".appleby.cloud",
})
```

The browser will send the cookie to all `*.appleby.cloud` origins. The `Protected` middleware will read and validate it automatically — no login redirect is needed if the user is already authenticated on any other first-party service.

### Site-specific cookies

Leave `CookieDomain` empty (the default). Cookies are scoped to the exact origin.

### Local development (HTTP)

```go
forta.Setup(forta.Config{
    // ...
    CookieInsecure: true, // disables Secure flag so cookies work over HTTP
})
```

---

## Using multi-service instances

The package-level functions (`forta.Setup`, `forta.Protected`, etc.) delegate to a single global `*forta.Client`. If you need multiple independent configurations in one binary (e.g. different callback URLs for different tenants), instantiate clients directly:

```go
// This API is not yet exposed — use Setup for single-config services.
// Direct Client construction is reserved for future versions.
```

For now, call `forta.Setup` once and use the package-level API throughout.

---

## Fetching the user profile on demand

Use `forta.FetchCurrentUser` to retrieve the full profile from any handler — not just `Protected` ones:

```go
func handlePublicPage(w http.ResponseWriter, r *http.Request) {
    // Returns nil, err if no token is present or the token is invalid.
    user, err := forta.FetchCurrentUser(r)
    if err != nil {
        // Not authenticated — render public view.
        return
    }
    // Authenticated — personalise the response.
    fmt.Fprintf(w, "Welcome back, %s", user.Email)
}
```

`FetchCurrentUser` reads the token from the same sources as `Protected` (Bearer header, then cookie) and calls `/auth/self`. It does **not** set any response cookies or perform auto-refresh.

---

## Optional Forta authentication

Some routes need to accept **either** a Forta token **or** a different credential (e.g. an API key or a service token from another provider). For these routes, skip `forta.Protected` and call `forta.FetchCurrentUser` yourself — it attempts Forta validation without ever rejecting the request:

```go
func handleResource(w http.ResponseWriter, r *http.Request) {
    // Attempt Forta authentication. Returns (nil, err) if no Forta token
    // is present, the token is invalid, or the token is expired.
    user, err := forta.FetchCurrentUser(r)
    if err == nil {
        // Request is authenticated as a Forta user.
        fmt.Fprintf(w, "Hello, %s (Forta user %d)", user.Email, user.ID)
        return
    }

    // Fall back to your own credential validation.
    apiKey := r.Header.Get("X-API-Key")
    if !isValidAPIKey(apiKey) {
        http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
        return
    }

    // Non-Forta authenticated request.
    fmt.Fprintf(w, "Hello, API service")
}
```

`FetchCurrentUser` returns the full `*forta.User` on success, so all profile fields (`ID`, `Email`, `Name`, etc.) are immediately available — no separate context lookup required.

Key points:

- If neither an `Authorization: Bearer` header nor a `forta-access-token` cookie is present, `FetchCurrentUser` returns an error immediately with no network call.
- It does **not** perform auto-refresh or write any cookies.
- `GetFortaIDFromContext` and `GetUserFromContext` are **not** populated on optional-auth routes — use the `*forta.User` returned directly from `FetchCurrentUser` instead.

---

## Error responses

All error responses from the built-in handlers and middleware use the following JSON shape:

```json
{
  "error": "human-readable message"
}
```

HTTP status codes:

| Status                      | Scenario                                                                       |
| --------------------------- | ------------------------------------------------------------------------------ |
| `400 Bad Request`           | Missing `code`/`state`, CSRF mismatch, or auth server error                    |
| `401 Unauthorized`          | Missing token, invalid token, expired (when auto-refresh is disabled or fails) |
| `500 Internal Server Error` | `Setup` not called before a handler is invoked                                 |
