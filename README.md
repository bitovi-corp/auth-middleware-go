# Auth Middleware Go

A reusable Go middleware package for Bearer token authentication in HTTP services.

## Features

- Bearer token validation
- Standard error responses
- Easy integration with any Go HTTP handler
- Comprehensive test coverage

## Installation

```bash
go get github.com/bitovi-corp/auth-middleware-go
```

## Usage

```go
import (
    authmiddleware "github.com/bitovi-corp/auth-middleware-go/middleware"
)

func main() {
    http.HandleFunc("/protected", authmiddleware.AuthMiddleware(yourHandler))
    http.ListenAndServe(":8080", nil)
}
```

## Authentication

The middleware expects an `Authorization` header with a Bearer token:

```
Authorization: Bearer <your-token>
```

### Validation Rules

- Token must be at least 20 characters long (basic validation for demo purposes)
- In production, implement proper JWT signature validation

## Error Responses

The middleware returns JSON error responses with appropriate HTTP status codes:

```json
{
  "code": "MISSING_TOKEN",
  "message": "Authorization header is required"
}
```

### Error Codes

- `MISSING_TOKEN`: Authorization header not provided
- `INVALID_TOKEN_FORMAT`: Header format is incorrect
- `EMPTY_TOKEN`: Token value is empty
- `INVALID_TOKEN`: Token failed validation

## Development

### Running Tests

```bash
go test ./...
```

## License

MIT
