# go-forta

Go client library for integrating [Forta](https://forta.appleby.cloud) as an authentication provider into any service.

`go-forta` handles the full OAuth2 lifecycle — login, callback, token validation, auto-refresh, and logout — so your service only needs to register three handlers and wrap protected routes with a single middleware call.

---

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
        APIDomain:    "https://api.forta.appleby.cloud",
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

## Documentation

| Document                                         | Description                                                                                                                                                   |
| ------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [docs/implementation.md](docs/implementation.md) | Complete integration guide — all `Config` options, cookie strategies, bearer tokens, local vs remote validation, and testing patterns.                        |
| [docs/server.md](docs/server.md)                 | Server-side migration guide for `forta-api` — how shared types (`FortaClaims`, `TokenPair`, `User`, etc.) map from the old structs to `go-forta` equivalents. |

---

## How it works

1. **`forta.LoginHandler`** — Redirects the browser to the Forta OAuth2 authorisation endpoint. Stores a CSRF state token in a short-lived HttpOnly cookie.
2. **`forta.CallbackHandler`** — Validates the CSRF state, exchanges the authorisation code for a token pair via `POST /auth/exchange`, and writes `forta-access-token` / `forta-refresh-token` HttpOnly cookies.
3. **`forta.Protected(next)`** — Middleware that reads the token from the `Authorization: Bearer` header or the `forta-access-token` cookie. Validates locally (HMAC-SHA512, no network) when `JWTSigningKey` is set, otherwise calls `/oauth/userinfo`. Transparently refreshes expired tokens.
4. **`forta.LogoutHandler`** — Clears auth cookies and redirects.

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
