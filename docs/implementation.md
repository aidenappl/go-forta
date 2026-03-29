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
12. [Error responses](#error-responses)

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
        APIDomain:    os.Getenv("FORTA_API_DOMAIN"),   // e.g. "https://api.forta.appleby.cloud"
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

`Setup` validates that `Domain`, `ClientID`, and `ClientSecret` are non-empty. It returns an error without panicking so you can handle it as part of your normal startup sequence.

---

## Config reference

```go
forta.Config{
    // --- Required ---

    // Base URL of the Forta API server — used for token exchange, validation, and user info.
    APIDomain: "https://api.forta.appleby.cloud",

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

    // Domain attribute for auth cookies.
    // Use ".appleby.cloud" on first-party services to share the session across subdomains.
    // Leave empty for site-scoped cookies (default behaviour).
    CookieDomain: ".appleby.cloud",

    // Set to true only for local HTTP development. Disables the Secure flag on cookies.
    CookieInsecure: false,

    // HMAC-SHA512 key shared with forta-api.
    // When set, tokens are validated in-process with no network call.
    // When empty (default), each Protected request calls /oauth/userinfo.
    JWTSigningKey: os.Getenv("FORTA_JWT_SIGNING_KEY"),

    // When JWTSigningKey is set, also call /oauth/userinfo to populate
    // the full User in context (at the cost of a network call per request).
    FetchUserOnProtect: false,

    // Prevents automatic transparent token refresh on expiry. Default: false (refresh enabled).
    DisableAutoRefresh: false,
}
```

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
    //   - JWTSigningKey is empty (remote /oauth/userinfo validation), OR
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
    APIDomain:   "https://api.forta.appleby.cloud",
    LoginDomain: "https://forta.appleby.cloud",
    ClientID:     "...",
    ClientSecret: "...",
    CallbackURL:  "...",
    // JWTSigningKey omitted — validates via /oauth/userinfo
})
```

- Every protected request makes one HTTP call to `GET {Domain}/oauth/userinfo`.
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

`FetchCurrentUser` reads the token from the same sources as `Protected` (Bearer header, then cookie) and calls `/oauth/userinfo`. It does **not** set any response cookies or perform auto-refresh.

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
