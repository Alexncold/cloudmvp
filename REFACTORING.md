# CloudCam MVP Refactoring Documentation

This document outlines the major changes and deletions made during the refactoring of CloudCam to create a simplified MVP focused on automatic backup of IP cameras to Google Drive.

## Major Changes

### 1. Project Structure
- Reorganized the project into a monorepo structure with separate directories for backend, web-ui, shared types, and Terraform configurations.
- Simplified the backend structure to focus on core functionality.

### 2. Backend Services
- **Authentication Service**: Implemented a simplified auth service with JWT and refresh tokens.
- **Recording Service**: Created a service to handle camera recording with FFmpeg integration.
- **Storage Service**: Added local storage management with cleanup and size limits.
- **Encryption Service**: Implemented AES-256-GCM encryption for sensitive data and video files.
- **Google Drive Service**: Integrated with Google Drive API for cloud backups.

### 3. Database Schema
- Simplified the database schema to focus on core entities:
  - `users`: Store user accounts and authentication details
  - `cameras`: Store camera configurations and status
- Removed unnecessary tables related to streaming, analytics, and complex relationships.

### 4. API Endpoints
- Implemented RESTful endpoints for:
  - Authentication (login, register, refresh tokens)
  - Camera management (add, update, delete, list)
  - System health and monitoring
  - Recording control (start/stop)

### 5. Infrastructure
- Simplified Docker Compose configuration to only include essential services:
  - PostgreSQL database
  - Backend API service
- Removed Redis, monitoring, and other non-essential services from the MVP.

## Deleted Components

### 1. Frontend
- Removed the entire React frontend application.
- Will be replaced with a minimal HTMX-based UI in a future update.

### 2. Streaming Infrastructure
- Removed WebRTC and RTMP streaming components.
- Removed WebSocket server and client implementations.

### 3. Analytics and Dashboard
- Removed analytics collection and processing code.
- Removed dashboard-related components and endpoints.

### 4. Monitoring and Logging
- Removed Prometheus, Grafana, and other monitoring tools.
- Simplified logging to focus on essential application logs.

### 5. CI/CD and Testing
- Removed complex CI/CD pipelines.
- Will implement simplified testing and deployment in future updates.

## Environment Variables

Updated `.env.example` with simplified configuration:

```
# Application
NODE_ENV=development
PORT=3000
HOST=0.0.0.0
CORS_ORIGIN=*

# Database
POSTGRES_HOST=postgres
POSTGRES_PORT=5432
POSTGRES_DB=cloudcam
POSTGRES_USER=cloudcam
POSTGRES_PASSWORD=cloudcam_password

# JWT Authentication
JWT_SECRET=your_jwt_secret_key
JWT_EXPIRES_IN=1d
JWT_REFRESH_EXPIRES_IN=7d

# Google OAuth
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
GOOGLE_CALLBACK_URL=http://localhost:3000/api/auth/google/callback

# Google Drive API
GOOGLE_SERVICE_ACCOUNT_EMAIL=your-service-account@your-project.iam.gserviceaccount.com
GOOGLE_SERVICE_ACCOUNT_KEY=your_service_account_private_key

# Storage
STORAGE_DIR=./storage
SEGMENT_DURATION=300  # 5 minutes in seconds
MAX_STORAGE_GB=10
ENABLE_VIDEO_ENCRYPTION=false
AES_ENCRYPTION_KEY=your_secure_encryption_key

# Camera Defaults
DEFAULT_CAMERA_USERNAME=admin
DEFAULT_CAMERA_PASSWORD=password

# Logging
LOG_LEVEL=info
LOG_TO_FILE=true
LOG_FILE_PATH=./logs/cloudcam.log
```

## Next Steps

1. **Implement Minimal Web UI**: Create a simple HTMX-based interface for camera management.
2. **Add Testing**: Implement unit and integration tests for critical components.
3. **Documentation**: Complete API documentation with OpenAPI/Swagger.
4. **Deployment**: Create deployment scripts for different environments.
5. **Monitoring**: Add basic health checks and logging.

## Known Issues

- The current implementation lacks comprehensive error handling for edge cases.
- Some error messages might be too verbose or not user-friendly.
- The storage cleanup mechanism could be more efficient for large numbers of files.

## Migration Notes

When upgrading from a previous version:

1. Backup your database before running migrations.
2. Update environment variables according to the new `.env.example`.
3. Run database migrations to update the schema.
4. Test all critical functionality before deploying to production.
