package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bitovi-corp/auth-middleware-go/models"
)

func TestAuthMiddleware(t *testing.T) {
	// Mock handler that should only be called if auth succeeds
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	tests := []struct {
		name           string
		authHeader     string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "Valid Bearer token passes",
			authHeader:     "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0",
			expectedStatus: http.StatusOK,
			expectedError:  "",
		},
		{
			name:           "Missing Authorization header returns 401",
			authHeader:     "",
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "MISSING_TOKEN",
		},
		{
			name:           "Invalid format returns 401",
			authHeader:     "InvalidFormat token123",
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "INVALID_TOKEN_FORMAT",
		},
		{
			name:           "Missing Bearer keyword returns 401",
			authHeader:     "token123",
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "INVALID_TOKEN_FORMAT",
		},
		{
			name:           "Empty token returns 401",
			authHeader:     "Bearer ",
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "EMPTY_TOKEN",
		},
		{
			name:           "Token too short returns 401",
			authHeader:     "Bearer short",
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "INVALID_TOKEN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			w := httptest.NewRecorder()

			// Apply auth middleware
			handler := AuthMiddleware(mockHandler)
			handler(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectedError != "" {
				var errorResp models.ErrorResponse
				if err := json.NewDecoder(w.Body).Decode(&errorResp); err != nil {
					t.Fatalf("Failed to decode error response: %v", err)
				}
				if errorResp.Code != tt.expectedError {
					t.Errorf("Expected error code %s, got %s", tt.expectedError, errorResp.Code)
				}
			}
		})
	}
}
