# go-forta — Server Migration Guide (`forta-api`)

This document describes what changed in `forta-api` when shared types were moved to `go-forta`, and acts as a reference for keeping the two repos in sync going forward.

---

## Table of contents

1. [Why the migration exists](#why-the-migration-exists)
2. [Dependency setup](#dependency-setup)
3. [Type mapping](#type-mapping)
4. [File-by-file changes](#file-by-file-changes)
   - [structs/auth.struct.go](#structsauthstructgo)
   - [structs/user.struct.go](#structsuserstructgo)
   - [forta/jwt.forta.go](#fortajwtfortago)
   - [util/cookies.util.go](#utilcookiesutilgo)
   - [Route handlers](#route-handlers)
5. [Docker / CI considerations](#docker--ci-considerations)
6. [Adding new shared types](#adding-new-shared-types)

---

## Why the migration exists

Before `go-forta`, both `forta-api` (the auth server) and every consuming service independently duplicated the same types:

- `AuthTokenPair` / `TokenPair`
- `AuthResponse`
- `UserPublic` / `UserMetadataPublic`
- `FortaClaims`
- `OAuthUserInfoResponse`

Consumer services had to copy these structs verbatim and keep them in sync manually. The migration moves the canonical definitions into `go-forta` so there is a single source of truth — `forta-api` signs tokens with `FortaClaims`, and any consumer can verify them with the same struct.

---

## Dependency setup

### go.mod

```go
require (
    github.com/aidenappl/go-forta v0.0.0
    // ...
)

// Local development: point to the sibling directory.
// Remove this replace directive when go-forta is published with a real tag.
replace github.com/aidenappl/go-forta => ../go-forta
```

### Import alias

All files that use `go-forta` types use the import alias `goforta` for brevity:

```go
import goforta "github.com/aidenappl/go-forta"
```

---

## Type mapping

The table below shows what each old `forta-api`-local type became, and where the new type lives.

| Old type (forta-api)                    | New type                        | Package                         |
| --------------------------------------- | ------------------------------- | ------------------------------- |
| `structs.AuthTokenPair`                 | `goforta.TokenPair`             | `github.com/aidenappl/go-forta` |
| `structs.AuthResponse`                  | `goforta.AuthResponse`          | `github.com/aidenappl/go-forta` |
| `structs.UserPublic`                    | `goforta.User`                  | `github.com/aidenappl/go-forta` |
| `structs.UserMetadataPublic`            | `goforta.UserMetadata`          | `github.com/aidenappl/go-forta` |
| `forta.FortaClaims` (local)             | `goforta.FortaClaims`           | `github.com/aidenappl/go-forta` |
| `structs.OAuthUserInfoResponse` (local) | `goforta.OAuthUserInfoResponse` | `github.com/aidenappl/go-forta` |

### Type definitions for reference

```go
// goforta.TokenPair
type TokenPair struct {
    AccessToken  string    `json:"access_token"`
    RefreshToken string    `json:"refresh_token"`
    TokenType    string    `json:"token_type"`
    ExpiresIn    int       `json:"expires_in"`
    ExpiresAt    time.Time `json:"expires_at"`
}

// goforta.AuthResponse
type AuthResponse struct {
    User          User      `json:"user"`
    Authorization TokenPair `json:"authorization"`
    IsNewUser     bool      `json:"is_new_user"`
}

// goforta.User
type User struct {
    ID              int64         `json:"id"`
    UUID            string        `json:"uuid"`
    Name            *string       `json:"name"`
    DisplayName     *string       `json:"display_name"`
    Email           string        `json:"email"`
    EmailVerified   bool          `json:"email_verified"`
    IsSuperAdmin    bool          `json:"is_super_admin"`
    Status          string        `json:"status"`
    ProfileImageURL *string       `json:"profile_image_url"`
    LastLoginAt     *time.Time    `json:"last_login_at"`
    InsertedAt      time.Time     `json:"inserted_at"`
    UpdatedAt       time.Time     `json:"updated_at"`
    Metadata        *UserMetadata `json:"metadata,omitempty"`
}

// goforta.FortaClaims
type FortaClaims struct {
    Type string `json:"typ"`
    jwt.RegisteredClaims
}

// goforta.OAuthUserInfoResponse
type OAuthUserInfoResponse struct {
    Sub               string  `json:"sub"`
    Name              *string `json:"name,omitempty"`
    Email             string  `json:"email"`
    EmailVerified     bool    `json:"email_verified"`
    Picture           *string `json:"picture,omitempty"`
    PreferredUsername *string `json:"preferred_username,omitempty"`
}
```

---

## File-by-file changes

### structs/auth.struct.go

**Removed** (moved to `go-forta`):

- `AuthTokenPair` → `goforta.TokenPair`
- `AuthResponse` → `goforta.AuthResponse`
- `OAuthUserInfoResponse` → `goforta.OAuthUserInfoResponse`

**Kept** (server-only structs, not needed by consumers):

- `LoginGoogleRequest`
- `LoginLocalRequest`
- `RegisterLocalRequest`
- `IssueCodeRequest` / `IssueCodeResponse`
- `ExchangeCodeRequest`
- `OAuthCompleteRequest` / `OAuthCompleteResponse`
- `OAuthTokenRequest` / `OAuthTokenResponse`

No import of `go-forta` is needed in this file — the remaining structs are plain Go.

---

### structs/user.struct.go

**Removed** (moved to `go-forta`):

- `UserPublic` → `goforta.User`
- `UserMetadataPublic` → `goforta.UserMetadata`

**Changed**:

- `(*User).ToPublic()` now returns `goforta.User` instead of the old `structs.UserPublic`.
- `(*User).ToPublicWithMetadata(m *UserMetadata)` (if present) returns `goforta.User` with `Metadata` populated.

**Import added**:

```go
import goforta "github.com/aidenappl/go-forta"
```

**Current `ToPublic` implementation**:

```go
func (u *User) ToPublic() goforta.User {
    return goforta.User{
        ID:              u.ID,
        UUID:            u.UUID,
        Name:            u.Name,
        DisplayName:     u.DisplayName,
        Email:           u.Email,
        EmailVerified:   u.EmailVerified,
        IsSuperAdmin:    u.IsSuperAdmin,
        Status:          u.Status,
        ProfileImageURL: u.ProfileImageURL,
        LastLoginAt:     u.LastLoginAt,
        InsertedAt:      u.InsertedAt,
        UpdatedAt:       u.UpdatedAt,
    }
}
```

Note: `structs.User` keeps internal-only fields (`DeletedAt`) that are not present in `goforta.User` — this is intentional. `goforta.User` is the safe public projection.

---

### forta/jwt.forta.go

**Removed**:

- Local `FortaClaims` struct definition — replaced by `goforta.FortaClaims`.

**Changed**:

- `newSignedToken` creates `goforta.FortaClaims{...}` instead of the local struct.
- `parseAndValidate` parses into `*goforta.FortaClaims`.
- `NewTokenPair` (if it returns a token pair struct) returns `goforta.TokenPair`.

**Kept** (server-only):

- `OAuthRequestClaims` — the short-lived JWT used internally for the OAuth2 code flow. Not needed by consumers.
- `ValidateOAuthRequestToken` — validates `OAuthRequestClaims`. Server internal.
- `NewAccessToken(userID int64) (string, time.Time, error)`
- `NewRefreshToken(userID int64) (string, time.Time, error)`
- `ValidateAccessToken(tokenStr string) (int64, error)`
- `ValidateRefreshToken(tokenStr string) (int64, error)`

**Import added**:

```go
import goforta "github.com/aidenappl/go-forta"
```

**Example — how `NewTokenPair` builds a `goforta.TokenPair`**:

```go
func NewTokenPair(userID int64) (goforta.TokenPair, error) {
    accessToken, expiresAt, err := NewAccessToken(userID)
    if err != nil {
        return goforta.TokenPair{}, err
    }
    refreshToken, _, err := NewRefreshToken(userID)
    if err != nil {
        return goforta.TokenPair{}, err
    }
    return goforta.TokenPair{
        AccessToken:  accessToken,
        RefreshToken: refreshToken,
        TokenType:    "Bearer",
        ExpiresIn:    int(time.Until(expiresAt).Seconds()),
        ExpiresAt:    expiresAt,
    }, nil
}
```

---

### util/cookies.util.go

**Changed**:

- `SetAuthCookies(w http.ResponseWriter, tokens structs.AuthTokenPair)` → `SetAuthCookies(w http.ResponseWriter, tokens goforta.TokenPair)`

All field accesses (`tokens.AccessToken`, `tokens.RefreshToken`, `tokens.ExpiresAt`) are identical — `goforta.TokenPair` uses the same field names as the old `AuthTokenPair`.

**Import added**:

```go
import goforta "github.com/aidenappl/go-forta"
```

No logic changes inside the function — only the parameter type changes.

---

### Route handlers

Every route file that previously used `structs.AuthResponse`, `structs.UserPublic`, or `structs.OAuthUserInfoResponse` now imports `goforta` and uses the equivalent type.

#### Pattern used across all handlers

```go
import (
    // ... other imports ...
    goforta "github.com/aidenappl/go-forta"
)
```

#### Response construction (login/register/refresh handlers)

```go
// Before
responder.New(w, structs.AuthResponse{
    User:          user.ToPublic(),
    Authorization: structs.AuthTokenPair{ ... },
    IsNewUser:     false,
})

// After
tokenPair, err := forta.NewTokenPair(user.ID)
// ... handle err ...
util.SetAuthCookies(w, tokenPair)
responder.New(w, goforta.AuthResponse{
    User:          user.ToPublic(),  // ToPublic() now returns goforta.User
    Authorization: tokenPair,
    IsNewUser:     false,
})
```

Affected handlers: `HandleLoginLocal`, `HandleLoginGoogle`, `HandleRegisterLocal`, `HandleRefresh`, `HandleExchangeCode`.

#### User info handler

```go
// HandleOAuthUserInfo — builds goforta.OAuthUserInfoResponse directly
resp := goforta.OAuthUserInfoResponse{
    Sub:           strconv.FormatInt(user.ID, 10),
    Name:          user.Name,
    Email:         user.Email,
    EmailVerified: user.EmailVerified,
    Picture:       user.ProfileImageURL,
}
if metadata != nil {
    resp.PreferredUsername = metadata.Username
}
json.NewEncoder(w).Encode(resp)
```

#### Admin list users

```go
// HandleAdminListUsers — map []structs.User → []goforta.User
result := make([]goforta.User, 0, len(users))
for _, u := range users {
    result = append(result, u.ToPublic())
}
responder.New(w, result)
```

#### Get self

```go
// HandleGetSelf — returns the authenticated user's own profile
responder.New(w, user.ToPublic()) // returns goforta.User
```

---

## Docker / CI considerations

The `go.mod` `replace` directive (`replace github.com/aidenappl/go-forta => ../go-forta`) works for local development where both repos are siblings, but **breaks Docker builds** because the container only has the `forta-api` directory in its build context.

### Options

**Option A — Publish a tagged release (recommended for production)**

Once `go-forta` is ready for a stable API, tag a release:

```sh
# in go-forta repo
git tag v0.1.0
git push origin v0.1.0
```

Then in `forta-api/go.mod`, replace the `replace` directive with a real version:

```go
require (
    github.com/aidenappl/go-forta v0.1.0
    // ...
)
// remove the replace directive entirely
```

**Option B — Copy go-forta into the Docker build context**

Modify the `Dockerfile` to copy the sibling directory before building:

```dockerfile
# Build stage
FROM golang:1.25-alpine AS builder
WORKDIR /src

# Copy the go-forta module alongside forta-api
COPY ./go-forta /go-forta
COPY ./forta-api  /src

RUN go mod download
RUN go build -o /app ./...
```

And update the CI pipeline to check out both repos before building the Docker image.

**Option C — Use a Go workspace (go.work)**

Create a `go.work` file at the parent directory level for local dev only. Do not commit it to either repo, and ensure Docker builds use the real module version.

```
go 1.25

use (
    ./forta-api
    ./go-forta
)
```

---

## Adding new shared types

When you add a new type that both `forta-api` and consumer services need:

1. **Define it in `go-forta/types.go`** — use exported JSON tags matching existing conventions.
2. **Import it in `forta-api`** via the `goforta` alias — do not duplicate the definition.
3. **Bump the `go-forta` module version** and update `forta-api/go.mod` once the type is tagged.
4. **Do not add server-internal types to `go-forta`** — types like `OAuthRequestClaims`, `LoginLocalRequest`, or DB row structs belong only in `forta-api`.
