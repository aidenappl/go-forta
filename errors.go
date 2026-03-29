package forta

import (
	"encoding/json"
	"net/http"
)

// errorResponse is the JSON body written by writeJSONError. It mirrors the
// Forta API error envelope for consistency.
type errorResponse struct {
	Success      bool   `json:"success"`
	ErrorMessage string `json:"error_message"`
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
