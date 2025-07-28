# CloudCam API Documentation

## Table of Contents
- [Authentication](#authentication)
- [Rate Limiting](#rate-limiting)
- [Endpoints](#endpoints)
  - [Authentication](#authentication-endpoints)
  - [Google Drive](#google-drive-endpoints)
- [Error Handling](#error-handling)
- [Environment Variables](#environment-variables)

## Authentication

All API endpoints (except public ones) require authentication using a JWT token. The token should be included in the `Authorization` header as follows:

```
Authorization: Bearer <token>
```

## Rate Limiting

Different endpoints have different rate limits:

- **Authentication Endpoints**: 10 requests per 15 minutes per IP
- **API Endpoints**: 200 requests per 15 minutes per IP
- **Public Endpoints**: 500 requests per 15 minutes per IP

When the rate limit is exceeded, the API will respond with a `429 Too Many Requests` status code.

## Endpoints

### Authentication Endpoints

#### `POST /api/auth/register`

Register a new user.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "name": "John Doe"
}
```

**Success Response:**
```json
{
  "success": true,
  "message": "User registered successfully",
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "name": "John Doe"
  }
}
```

#### `POST /api/auth/login`

Authenticate a user and get access and refresh tokens.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

**Success Response:**
```json
{
  "success": true,
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "name": "John Doe"
  }
}
```

### Google Drive Endpoints

#### `GET /api/auth/drive/status`

Get the status of the Google Drive integration for the authenticated user.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Success Response:**
```json
{
  "connected": true,
  "quota": {
    "limit": 10737418240,
    "usage": 5368709120,
    "usageInTrash": 107374182,
    "percentageUsed": 50
  },
  "lastSync": "2023-07-28T13:45:30.000Z",
  "encryptionEnabled": true,
  "rootFolderId": "1A2B3C4D5E6F7G8H9I0J"
}
```

#### `POST /api/auth/drive/revoke`

Revoke Google Drive access for the authenticated user.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Success Response:**
```json
{
  "success": true,
  "message": "Google Drive access has been revoked"
}
```

## Error Handling

All error responses follow this format:

```json
{
  "success": false,
  "message": "Error message",
  "code": "ERROR_CODE",
  "errors": [
    {
      "field": "field_name",
      "message": "Error message for this field"
    }
  ]
}
```

### Common Error Codes

- `AUTH_INVALID_CREDENTIALS`: Invalid email or password
- `AUTH_UNAUTHORIZED`: Missing or invalid authentication token
- `AUTH_TOKEN_EXPIRED`: The access token has expired
- `RATE_LIMIT_EXCEEDED`: Too many requests
- `VALIDATION_ERROR`: Request validation failed
- `INTERNAL_SERVER_ERROR`: An unexpected error occurred

## Environment Variables

### Required

- `DATABASE_URL`: PostgreSQL connection string
- `JWT_SECRET`: Secret key for JWT token signing
- `GOOGLE_CLIENT_ID`: Google OAuth client ID
- `GOOGLE_CLIENT_SECRET`: Google OAuth client secret
- `GOOGLE_SERVICE_ACCOUNT_EMAIL`: Google service account email
- `GOOGLE_SERVICE_ACCOUNT_KEY`: Google service account private key (JSON)
- `AES_SECRET`: 32-character secret key for AES encryption

### Optional

- `NODE_ENV`: Application environment (development, test, production)
- `PORT`: Port to run the server on (default: 3001)
- `LOG_LEVEL`: Logging level (error, warn, info, debug, trace)
- `GOOGLE_ENCRYPTION_ENABLED`: Enable/disable file encryption (default: true)
- `GOOGLE_DRIVE_QUOTA_WARNING_THRESHOLD`: Warning threshold for drive quota (default: 8GB)
- `GOOGLE_DRIVE_QUOTA_CRITICAL_THRESHOLD`: Critical threshold for drive quota (default: 9GB)
