package middleware

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/bitovi-corp/auth-middleware-go/models"
)

// AuthMiddleware validates Bearer JWT tokens
func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get Authorization header
		authHeader := r.Header.Get("Authorization")
		
		if authHeader == "" {
			writeUnauthorizedError(w, "MISSING_TOKEN", "Authorization header is required")
			return
		}

		// Check if it's a Bearer token
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			writeUnauthorizedError(w, "INVALID_TOKEN_FORMAT", "Authorization header must be in format: Bearer {token}")
			return
		}

		token := parts[1]
		if token == "" {
			writeUnauthorizedError(w, "EMPTY_TOKEN", "Token cannot be empty")
			return
		}

		// Simple token validation (in production, validate JWT signature and claims)
		// For this example, we'll accept any non-empty token that looks like a JWT
		if !isValidToken(token) {
			writeUnauthorizedError(w, "INVALID_TOKEN", "Invalid or expired token")
			return
		}

		// Token is valid, proceed to next handler
		next(w, r)
	}
}

// isValidToken performs basic token validation
// In production, this would validate JWT signature, expiration, etc.
func isValidToken(token string) bool {
	// For demo purposes, accept tokens that are at least 20 characters
	// In production, use a proper JWT library like github.com/golang-jwt/jwt
	return len(token) >= 20
}

// writeUnauthorizedError writes a 401 Unauthorized error response
func writeUnauthorizedError(w http.ResponseWriter, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	
	errorResp := models.ErrorResponse{
		Code:    code,
		Message: message,
	}
	
	if err := json.NewEncoder(w).Encode(errorResp); err != nil {
		log.Printf("Error encoding unauthorized response: %v", err)
	}
}
