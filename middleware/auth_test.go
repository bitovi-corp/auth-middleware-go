package middleware

import (
	"encoding/base64"
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
			authHeader:     "Bearer " + createMockJWT(UserClaims{Subject: "user123", Email: "test@example.com", Roles: []string{"user"}}),
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

// createMockJWT creates a mock JWT token with the given claims
func createMockJWT(claims UserClaims) string {
	// Create header
	header := map[string]string{"alg": "HS256", "typ": "JWT"}
	headerJSON, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	// Create payload
	payloadJSON, _ := json.Marshal(claims)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Create mock signature (not verified in mock mode)
	signature := base64.RawURLEncoding.EncodeToString([]byte("mock-signature"))

	return headerB64 + "." + payloadB64 + "." + signature
}

func TestAuthMiddlewareWithClaims(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := GetUserClaims(r)
		if claims == nil {
			t.Error("Expected claims to be available in handler")
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(claims)
	})

	tests := []struct {
		name          string
		claims        UserClaims
		expectSuccess bool
	}{
		{
			name: "Valid JWT with roles",
			claims: UserClaims{
				Subject: "user123",
				Email:   "user@example.com",
				Roles:   []string{"user", "admin"},
			},
			expectSuccess: true,
		},
		{
			name: "Valid JWT without roles",
			claims: UserClaims{
				Subject: "user456",
				Email:   "user2@example.com",
				Roles:   []string{},
			},
			expectSuccess: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := createMockJWT(tt.claims)
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()

			handler := AuthMiddleware(mockHandler)
			handler(w, req)

			if tt.expectSuccess {
				if w.Code != http.StatusOK {
					t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
				}

				var returnedClaims UserClaims
				if err := json.NewDecoder(w.Body).Decode(&returnedClaims); err != nil {
					t.Fatalf("Failed to decode claims: %v", err)
				}

				if returnedClaims.Subject != tt.claims.Subject {
					t.Errorf("Expected subject %s, got %s", tt.claims.Subject, returnedClaims.Subject)
				}
			}
		})
	}
}

func TestRequireRoles(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	tests := []struct {
		name           string
		userRoles      []string
		requiredRoles  []string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "User has required role",
			userRoles:      []string{"admin"},
			requiredRoles:  []string{"admin"},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "User has one of multiple required roles",
			userRoles:      []string{"user", "moderator"},
			requiredRoles:  []string{"admin", "moderator"},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "User lacks required role",
			userRoles:      []string{"user"},
			requiredRoles:  []string{"admin"},
			expectedStatus: http.StatusForbidden,
			expectedError:  "INSUFFICIENT_PERMISSIONS",
		},
		{
			name:           "User has no roles",
			userRoles:      []string{},
			requiredRoles:  []string{"admin"},
			expectedStatus: http.StatusForbidden,
			expectedError:  "INSUFFICIENT_PERMISSIONS",
		},
		{
			name:           "User has multiple roles including required",
			userRoles:      []string{"user", "admin", "moderator"},
			requiredRoles:  []string{"admin"},
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := UserClaims{
				Subject: "user123",
				Email:   "user@example.com",
				Roles:   tt.userRoles,
			}
			token := createMockJWT(claims)

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()

			handler := RequireRoles(tt.requiredRoles...)(mockHandler)
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

func TestRequireAllRoles(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	tests := []struct {
		name           string
		userRoles      []string
		requiredRoles  []string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "User has all required roles",
			userRoles:      []string{"admin", "superuser"},
			requiredRoles:  []string{"admin", "superuser"},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "User has all required roles plus extras",
			userRoles:      []string{"user", "admin", "superuser", "moderator"},
			requiredRoles:  []string{"admin", "superuser"},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "User has only some required roles",
			userRoles:      []string{"admin"},
			requiredRoles:  []string{"admin", "superuser"},
			expectedStatus: http.StatusForbidden,
			expectedError:  "INSUFFICIENT_PERMISSIONS",
		},
		{
			name:           "User has no required roles",
			userRoles:      []string{"user"},
			requiredRoles:  []string{"admin", "superuser"},
			expectedStatus: http.StatusForbidden,
			expectedError:  "INSUFFICIENT_PERMISSIONS",
		},
		{
			name:           "User has empty roles",
			userRoles:      []string{},
			requiredRoles:  []string{"admin"},
			expectedStatus: http.StatusForbidden,
			expectedError:  "INSUFFICIENT_PERMISSIONS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := UserClaims{
				Subject: "user123",
				Email:   "user@example.com",
				Roles:   tt.userRoles,
			}
			token := createMockJWT(claims)

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()

			handler := RequireAllRoles(tt.requiredRoles...)(mockHandler)
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

func TestGetUserClaims(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := GetUserClaims(r)
		if claims == nil {
			t.Error("Expected claims to be retrievable")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if claims.Subject != "user123" {
			t.Errorf("Expected subject user123, got %s", claims.Subject)
		}

		if len(claims.Roles) != 2 {
			t.Errorf("Expected 2 roles, got %d", len(claims.Roles))
		}

		w.WriteHeader(http.StatusOK)
	})

	claims := UserClaims{
		Subject: "user123",
		Email:   "user@example.com",
		Roles:   []string{"user", "admin"},
	}
	token := createMockJWT(claims)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handler := AuthMiddleware(mockHandler)
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestParseJWTClaims(t *testing.T) {
	tests := []struct {
		name        string
		token       string
		expectError bool
	}{
		{
			name: "Valid JWT token",
			token: createMockJWT(UserClaims{
				Subject: "user123",
				Email:   "user@example.com",
				Roles:   []string{"admin"},
			}),
			expectError: false,
		},
		{
			name:        "Invalid JWT - not enough parts",
			token:       "invalid.token",
			expectError: true,
		},
		{
			name:        "Invalid JWT - bad base64",
			token:       "header.!!!invalid!!!.signature",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims, err := parseJWTClaims(tt.token)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
				if claims == nil {
					t.Error("Expected claims but got nil")
				}
			}
		})
	}
}
