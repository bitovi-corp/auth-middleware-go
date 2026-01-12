package middleware

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/bitovi-corp/auth-middleware-go/models"
)

// contextKey is a custom type for context keys to avoid collisions
type contextKey string

const userClaimsKey contextKey = "userClaims"

// UserClaims represents the decoded JWT payload
type UserClaims struct {
	Subject   string   `json:"sub"`
	Email     string   `json:"email"`
	Roles     []string `json:"roles"`
	ExpiresAt int64    `json:"exp"`
}

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

		// Parse JWT claims
		claims, err := parseJWTClaims(token)
		if err != nil {
			writeUnauthorizedError(w, "INVALID_TOKEN", "Unable to parse token claims")
			return
		}

		// Store claims in request context
		ctx := context.WithValue(r.Context(), userClaimsKey, claims)
		r = r.WithContext(ctx)

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
// parseJWTClaims extracts and decodes the JWT payload
// In mock mode, we parse the claims without verifying the signature
func parseJWTClaims(token string) (*UserClaims, error) {
	// Split JWT into parts (header.payload.signature)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid JWT format: expected 3 parts")
	}

	// Decode the payload (second part)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	// Unmarshal claims
	var claims UserClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}

	return &claims, nil
}

// GetUserClaims retrieves user claims from request context
func GetUserClaims(r *http.Request) *UserClaims {
	claims, ok := r.Context().Value(userClaimsKey).(*UserClaims)
	if !ok {
		return nil
	}
	return claims
}

// RequireRoles returns a middleware that checks if the user has at least one of the specified roles
func RequireRoles(roles ...string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return AuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
			claims := GetUserClaims(r)
			if claims == nil {
				writeForbiddenError(w, "INSUFFICIENT_PERMISSIONS", "Unable to verify user roles")
				return
			}

			// Check if user has at least one of the required roles
			if len(roles) > 0 && !hasAnyRole(claims.Roles, roles) {
				writeForbiddenError(w, "INSUFFICIENT_PERMISSIONS", "User does not have required role(s): "+strings.Join(roles, ", "))
				return
			}

			next(w, r)
		})
	}
}

// RequireAllRoles returns a middleware that checks if the user has all of the specified roles
func RequireAllRoles(roles ...string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return AuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
			claims := GetUserClaims(r)
			if claims == nil {
				writeForbiddenError(w, "INSUFFICIENT_PERMISSIONS", "Unable to verify user roles")
				return
			}

			// Check if user has all required roles
			if len(roles) > 0 && !hasAllRoles(claims.Roles, roles) {
				writeForbiddenError(w, "INSUFFICIENT_PERMISSIONS", "User does not have all required roles: "+strings.Join(roles, ", "))
				return
			}

			next(w, r)
		})
	}
}

// hasAnyRole checks if user has at least one of the required roles
func hasAnyRole(userRoles []string, requiredRoles []string) bool {
	for _, required := range requiredRoles {
		for _, userRole := range userRoles {
			if userRole == required {
				return true
			}
		}
	}
	return false
}

// hasAllRoles checks if user has all of the required roles
func hasAllRoles(userRoles []string, requiredRoles []string) bool {
	for _, required := range requiredRoles {
		found := false
		for _, userRole := range userRoles {
			if userRole == required {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
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

// writeForbiddenError writes a 403 Forbidden error response
func writeForbiddenError(w http.ResponseWriter, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	
	errorResp := models.ErrorResponse{
		Code:    code,
		Message: message,
	}
	
	if err := json.NewEncoder(w).Encode(errorResp); err != nil {
		log.Printf("Error encoding forbidden response: %v", err)
	}
}
