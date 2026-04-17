package forta

import (
	"encoding/json"
	"net/http"
)

// ErrCodeGrantRequired is the standardised error code returned when a user
// does not have an active grant for the requested platform. Frontends should
// check for this code to distinguish "no grant" (redirect to access-request
// page) from a generic 403 Forbidden.
const ErrCodeGrantRequired = 4003

// errorResponse is the JSON body written by writeJSONError. It mirrors the
// Forta API error envelope for consistency.
type errorResponse struct {
	Success      bool   `json:"success"`
	ErrorMessage string `json:"error_message"`
}

// codedErrorResponse extends errorResponse with an error code field.
type codedErrorResponse struct {
	Success      bool   `json:"success"`
	ErrorMessage string `json:"error_message"`
	ErrorCode    int    `json:"error_code"`
}

// writeJSONError writes a JSON error response with the given HTTP status code.
func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorResponse{
		Success:      false,
		ErrorMessage: message,
	})
}

// writeGrantDenied writes a 403 response with the standardised grant-required
// error code so frontends can distinguish it from other 403 responses.
func writeGrantDenied(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(codedErrorResponse{
		Success:      false,
		ErrorMessage: "grant required",
		ErrorCode:    ErrCodeGrantRequired,
	})
}
