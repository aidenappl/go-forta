package forta

import "time"

// User is the public profile of an authenticated Forta user as returned by
// the /oauth/userinfo and /auth/exchange endpoints.
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

// UserMetadata holds optional supplementary profile fields.
type UserMetadata struct {
	Username      *string `json:"username"`
	Phone         *string `json:"phone"`
	PhoneVerified bool    `json:"phone_verified"`
}

// TokenPair holds a Forta access/refresh token pair along with expiry metadata.
type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int       `json:"expires_in"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// AuthResponse is the payload returned by /auth/exchange and /auth/refresh.
type AuthResponse struct {
	User          User      `json:"user"`
	Authorization TokenPair `json:"authorization"`
	IsNewUser     bool      `json:"is_new_user"`
}

// fortaEnvelope is the standard response wrapper used by the Forta API for
// endpoints that use the internal responder package.
type fortaEnvelope[T any] struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Data    T      `json:"data"`
}

// OAuthUserInfoResponse is the OIDC userinfo payload returned by /oauth/userinfo.
// The Sub field contains the Forta user ID as a decimal string.
// This type is used by both go-forta (client parsing) and forta-api (server response body).
type OAuthUserInfoResponse struct {
	Sub               string  `json:"sub"`
	Name              *string `json:"name,omitempty"`
	Email             string  `json:"email"`
	EmailVerified     bool    `json:"email_verified"`
	Picture           *string `json:"picture,omitempty"`
	PreferredUsername *string `json:"preferred_username,omitempty"`
}

// exchangeCodeRequest matches the body expected by POST /auth/exchange.
type exchangeCodeRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Code         string `json:"code"`
}
