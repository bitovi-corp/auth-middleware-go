# Role-Based Access Control (RBAC) Specification

## Overview
This specification outlines the implementation of role-based access control for the authentication middleware. The RBAC system allows fine-grained access control by validating user roles extracted from JWT tokens.

## Design Goals
1. Maintain backward compatibility with existing `AuthMiddleware`
2. Support multiple roles per user
3. Allow flexible role requirements (any-of or all-of semantics)
4. Provide user context to downstream handlers
5. Keep mock JWT validation simple for development/testing

## Architecture

### JWT Token Structure
Expected JWT payload structure:
```json
{
  "sub": "user-id-123",
  "email": "user@example.com",
  "roles": ["user", "admin"],
  "exp": 1234567890
}
```

### Components

#### 1. UserClaims Model
Represents the decoded JWT payload:
- `Subject` (string): User ID
- `Email` (string): User email
- `Roles` ([]string): Array of role names
- `ExpiresAt` (int64): Token expiration timestamp

#### 2. Enhanced AuthMiddleware
Extended to parse JWT claims and store user context:
- Decodes JWT payload (base64-encoded middle section)
- Validates token structure (3 parts separated by dots)
- Extracts user claims
- Stores claims in request context
- Remains backward compatible (no role enforcement)

#### 3. RequireRoles Middleware
Wraps AuthMiddleware to enforce role requirements:
- Accepts variadic role parameters
- Uses "any-of" semantics (user must have at least one required role)
- Returns 403 Forbidden if user lacks required roles
- Provides clear error messages

#### 4. RequireAllRoles Middleware
Alternative wrapper for stricter role requirements:
- Requires user to have all specified roles
- Useful for operations requiring multiple permissions

## API Design

### Basic Authentication (No Role Check)
```go
http.HandleFunc("/api/protected", middleware.AuthMiddleware(handler))
```

### Single Role Requirement
```go
http.HandleFunc("/api/admin", middleware.RequireRoles("admin")(handler))
```

### Multiple Role Options (Any-Of)
```go
// User must have either "admin" OR "moderator" role
http.HandleFunc("/api/moderate", middleware.RequireRoles("admin", "moderator")(handler))
```

### Multiple Required Roles (All-Of)
```go
// User must have both "admin" AND "superuser" roles
http.HandleFunc("/api/critical", middleware.RequireAllRoles("admin", "superuser")(handler))
```

### Accessing User Claims in Handlers
```go
func handler(w http.ResponseWriter, r *http.Request) {
    claims := middleware.GetUserClaims(r)
    if claims != nil {
        fmt.Printf("User: %s, Roles: %v\n", claims.Subject, claims.Roles)
    }
}
```

## Implementation Details

### JWT Parsing (Mock Mode)
For development/testing without full JWT signature verification:
1. Split token by "." separator (expecting 3 parts)
2. Base64-decode the middle part (payload)
3. Unmarshal JSON into UserClaims struct
4. Basic validation (check expiration if present)

### Context Storage
Use Go's context package to store user claims:
- Key: custom context key type (prevents collisions)
- Value: pointer to UserClaims struct
- Retrieval: `GetUserClaims(r)` helper function

### Error Responses
Following existing error model in `models/error.go`:

**403 Forbidden - Insufficient Permissions:**
```json
{
  "code": "INSUFFICIENT_PERMISSIONS",
  "message": "User does not have required role(s): admin"
}
```

**401 Unauthorized - Invalid Token:**
```json
{
  "code": "INVALID_TOKEN",
  "message": "Unable to parse token claims"
}
```

## Testing Strategy

### Unit Tests
1. **JWT Parsing:**
   - Valid JWT with roles
   - Invalid base64 encoding
   - Missing roles claim
   - Expired token

2. **RequireRoles Middleware:**
   - User has required role (passes)
   - User has one of multiple required roles (passes)
   - User lacks all required roles (403)
   - No roles in token (403)

3. **RequireAllRoles Middleware:**
   - User has all required roles (passes)
   - User has only some required roles (403)

4. **Context Management:**
   - Claims stored correctly
   - Claims retrievable in handlers
   - Nil handling for missing claims

### Integration Tests
- Chain multiple middleware functions
- Verify role enforcement in realistic scenarios
- Test backward compatibility with existing code

## Migration Path

### Phase 1: Core Implementation ✓
- Add UserClaims model
- Enhance AuthMiddleware with JWT parsing
- Implement RequireRoles and RequireAllRoles
- Add context helpers

### Phase 2: Testing ✓
- Comprehensive unit tests
- Integration test scenarios
- Edge case coverage

### Phase 3: Documentation ✓
- Update README with examples
- Add inline code documentation
- Create usage guide

## Future Enhancements

### Short-term
- Support for permission strings (e.g., "users:write", "orders:read")
- Role hierarchy (admin implicitly has user role)

### Long-term
- Full JWT signature verification (RS256, HS256)
- Token refresh mechanism
- Integration with external auth providers (OAuth2, OIDC)
- Caching of decoded claims for performance

## Security Considerations

1. **Mock Mode Warning**: Current implementation uses mock validation without signature verification. Not suitable for production without proper JWT verification.

2. **Token Expiration**: Check `exp` claim when present, but don't enforce in mock mode.

3. **Case Sensitivity**: Role names are case-sensitive. Consider normalizing to lowercase.

4. **Role Injection**: In production, verify JWT signature before trusting claims to prevent role injection attacks.

5. **Error Messages**: Don't leak sensitive information in error messages (e.g., which specific roles exist).

## Examples

### Example 1: Public and Protected Endpoints
```go
// Public - no auth
http.HandleFunc("/api/public", publicHandler)

// Protected - requires valid token
http.HandleFunc("/api/profile", middleware.AuthMiddleware(profileHandler))

// Admin only
http.HandleFunc("/api/admin/users", middleware.RequireRoles("admin")(adminHandler))
```

### Example 2: Multiple Role Tiers
```go
// Any authenticated user
http.HandleFunc("/api/orders", middleware.AuthMiddleware(listOrdersHandler))

// Users with support or admin role
http.HandleFunc("/api/orders/cancel", middleware.RequireRoles("support", "admin")(cancelOrderHandler))

// Only admins
http.HandleFunc("/api/orders/refund", middleware.RequireRoles("admin")(refundOrderHandler))
```

### Example 3: Using Claims in Handler
```go
func ordersHandler(w http.ResponseWriter, r *http.Request) {
    claims := middleware.GetUserClaims(r)
    
    // Filter orders based on user role
    if hasRole(claims.Roles, "admin") {
        // Return all orders
        orders = orderService.GetAllOrders()
    } else {
        // Return only user's orders
        orders = orderService.GetUserOrders(claims.Subject)
    }
    
    json.NewEncoder(w).Encode(orders)
}
```

## Conclusion
This RBAC implementation provides a flexible, backward-compatible approach to role-based access control while maintaining simplicity for development and testing. The mock JWT parsing allows teams to develop and test role-based features before integrating full JWT verification in production.
