# Auth Middleware Go

A reusable Go middleware package for Bearer token authentication and role-based access control (RBAC) in HTTP services.

## Features

- Bearer token validation
- Role-based access control (RBAC)
- JWT claims parsing (mock mode for development)
- User context management
- Standard error responses
- Easy integration with any Go HTTP handler
- Comprehensive test coverage

## Installation

```bash
go get github.com/bitovi-corp/auth-middleware-go
```

## Usage

### Basic Authentication

Validate Bearer tokens without role checks:

```go
import (
    authmiddleware "github.com/bitovi-corp/auth-middleware-go/middleware"
)

func main() {
    http.HandleFunc("/protected", authmiddleware.AuthMiddleware(yourHandler))
    http.ListenAndServe(":8080", nil)
}
```

### Role-Based Access Control

Require specific roles for endpoints:

```go
// Require admin role
http.HandleFunc("/admin", authmiddleware.RequireRoles("admin")(adminHandler))

// Require admin OR moderator role (any-of)
http.HandleFunc("/moderate", authmiddleware.RequireRoles("admin", "moderator")(moderateHandler))

// Require BOTH admin AND superuser roles (all-of)
http.HandleFunc("/critical", authmiddleware.RequireAllRoles("admin", "superuser")(criticalHandler))
```

### Accessing User Claims

Access authenticated user information in your handlers:

```go
func yourHandler(w http.ResponseWriter, r *http.Request) {
    claims := authmiddleware.GetUserClaims(r)
    if claims != nil {
        fmt.Printf("User ID: %s\n", claims.Subject)
        fmt.Printf("Email: %s\n", claims.Email)
        fmt.Printf("Roles: %v\n", claims.Roles)
    }
    // ... rest of handler logic
}
```

## Authentication

The middleware expects an `Authorization` header with a Bearer token:

```
Authorization: Bearer <your-jwt-token>
```

### JWT Token Structure

Expected JWT payload format:

```json
{
  "sub": "user-id-123",
  "email": "user@example.com",
  "roles": ["user", "admin"],
  "exp": 1234567890
}
```

### Validation Rules

- Token must be at least 20 characters long (basic validation)
- Token must be a valid JWT with 3 parts (header.payload.signature)
- JWT payload must be valid JSON
- **Note:** In mock mode, signature is NOT verified (suitable for development/testing)
- For production, implement proper JWT signature validation

## Error Responses

The middleware returns JSON error responses with appropriate HTTP status codes:

### 401 Unauthorized

```json
{
  "code": "MISSING_TOKEN",
  "message": "Authorization header is required"
}
```

**Error Codes:**
- `MISSING_TOKEN`: Authorization header not provided
- `INVALID_TOKEN_FORMAT`: Header format is incorrect
- `EMPTY_TOKEN`: Token value is empty
- `INVALID_TOKEN`: Token failed validation or unable to parse claims

### 403 Forbidden

```json
{
  "code": "INSUFFICIENT_PERMISSIONS",
  "message": "User does not have required role(s): admin"
}
```

**Error Codes:**
- `INSUFFICIENT_PERMISSIONS`: User lacks required role(s)

## API Reference

### Middleware Functions

#### `AuthMiddleware(next http.HandlerFunc) http.HandlerFunc`
Basic authentication middleware that validates Bearer tokens and parses JWT claims.

#### `RequireRoles(roles ...string) func(http.HandlerFunc) http.HandlerFunc`
Wraps AuthMiddleware and requires the user to have at least one of the specified roles.

#### `RequireAllRoles(roles ...string) func(http.HandlerFunc) http.HandlerFunc`
Wraps AuthMiddleware and requires the user to have all of the specified roles.

#### `GetUserClaims(r *http.Request) *UserClaims`
Retrieves the authenticated user's claims from the request context.

### Types

#### `UserClaims`
```go
type UserClaims struct {
    Subject   string   `json:"sub"`      // User ID
    Email     string   `json:"email"`    // User email
    Roles     []string `json:"roles"`    // User roles
    ExpiresAt int64    `json:"exp"`      // Token expiration (Unix timestamp)
}
```

## Examples

### Example 1: Public and Protected Endpoints

```go
func main() {
    // Public endpoint - no authentication
    http.HandleFunc("/api/public", publicHandler)
    
    // Protected endpoint - requires valid token
    http.HandleFunc("/api/profile", authmiddleware.AuthMiddleware(profileHandler))
    
    // Admin only endpoint
    http.HandleFunc("/api/admin/users", authmiddleware.RequireRoles("admin")(adminHandler))
    
    http.ListenAndServe(":8080", nil)
}
```

### Example 2: Role-Based Order Management

```go
// Any authenticated user can list orders
http.HandleFunc("/api/orders", authmiddleware.AuthMiddleware(listOrdersHandler))

// Support staff or admins can cancel orders
http.HandleFunc("/api/orders/cancel", authmiddleware.RequireRoles("support", "admin")(cancelOrderHandler))

// Only admins can issue refunds
http.HandleFunc("/api/orders/refund", authmiddleware.RequireRoles("admin")(refundOrderHandler))
```

### Example 3: Using Claims to Filter Data

```go
func ordersHandler(w http.ResponseWriter, r *http.Request) {
    claims := authmiddleware.GetUserClaims(r)
    
    var orders []Order
    
    // Check if user has admin role
    isAdmin := false
    for _, role := range claims.Roles {
        if role == "admin" {
            isAdmin = true
            break
        }
    }
    
    if isAdmin {
        // Admins see all orders
        orders = orderService.GetAllOrders()
    } else {
        // Regular users see only their orders
        orders = orderService.GetUserOrders(claims.Subject)
    }
    
    json.NewEncoder(w).Encode(orders)
}
```

## Development

### Running Tests

```bash
go test ./...
```

### Running Tests with Verbose Output

```bash
go test ./... -v
```

## Security Considerations

⚠️ **Important:** This implementation uses mock JWT validation for development purposes. The JWT signature is NOT verified. This is suitable for:

- Development and testing environments
- Internal services with trusted token sources
- Prototyping and demonstrations

For production use, you should:
1. Implement proper JWT signature verification using a library like `github.com/golang-jwt/jwt`
2. Validate token expiration (`exp` claim)
3. Verify token issuer (`iss` claim)
4. Use HTTPS for all communications
5. Implement token refresh mechanisms
6. Consider using established auth providers (OAuth2, OIDC)

## Documentation

For detailed implementation specifications, see [spec/00-rbac.md](spec/00-rbac.md)

## License

MIT
