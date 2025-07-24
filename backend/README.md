# OrAura Backend - User Module Implementation

## 🎯 Overview

This is a complete implementation of the user module for the OrAura spiritual divination application backend. The implementation follows Go best practices with a clean architecture pattern (Handler → Service → Repository).

## 🏗️ Architecture

```
┌─────────────────────────────────────────┐
│                Handler                   │  ← HTTP request handling & validation
│  (user_handler.go)                      │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│                Service                   │  ← Business logic & rules
│  (user_service.go)                      │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│              Repository                  │  ← Data access & persistence
│  (user_repository.go)                   │
└─────────────────────────────────────────┘
```

## 📁 Project Structure

```
backend/
├── cmd/server/main.go              # Application entry point
├── internal/
│   ├── config/config.go            # Configuration management
│   ├── handlers/
│   │   ├── user_handler.go         # HTTP request handlers
│   │   └── user_handler_test.go    # Handler tests
│   ├── services/
│   │   ├── user_service.go         # Business logic
│   │   └── user_service_test.go    # Service tests
│   ├── store/
│   │   └── user_repository.go      # Data access layer
│   ├── models/
│   │   ├── user.go                 # Database models
│   │   └── dto.go                  # Request/Response DTOs
│   ├── middleware/
│   │   └── auth.go                 # Authentication & middleware
│   ├── routes/
│   │   └── user_routes.go          # Route definitions
│   └── utils/
│       └── jwt.go                  # JWT & crypto utilities
├── configs/app.env                 # Configuration file
└── go.mod                          # Go dependencies
```

## 🚀 Features Implemented

### ✅ Authentication & Authorization
- **User Registration**: Email/password with validation
- **User Login**: Secure authentication with JWT tokens
- **Token Refresh**: Automatic token renewal mechanism
- **User Logout**: Token blacklisting for security
- **OAuth Support**: Google & Apple Sign-In (interfaces ready)

### ✅ User Management
- **Profile Management**: Get/update user information
- **Password Management**: Change password with validation
- **Avatar Upload**: File upload support (interface ready)
- **Account Deletion**: Complete account removal

### ✅ Security Features
- **Password Hashing**: bcrypt for secure password storage
- **JWT Blacklisting**: Revoked token management
- **Rate Limiting**: IP-based and user-based limits
- **CORS Protection**: Cross-origin request handling
- **Request Validation**: Comprehensive input validation

### ✅ Data Models
- **User Model**: Complete user entity with relationships
- **User Profile**: Extended user information & preferences
- **Refresh Tokens**: Secure token management
- **Login Logs**: Audit trail for security
- **Password Reset**: Secure password recovery system

## 🔧 API Endpoints

### Authentication Routes (Public)
```http
POST /api/v1/auth/register          # User registration
POST /api/v1/auth/login             # User login
POST /api/v1/auth/refresh           # Refresh access token
POST /api/v1/auth/forgot-password   # Request password reset
POST /api/v1/auth/reset-password    # Reset password with token
POST /api/v1/auth/oauth/google      # Google OAuth login
POST /api/v1/auth/oauth/apple       # Apple OAuth login
```

### User Routes (Protected)
```http
POST /api/v1/auth/logout            # User logout
GET  /api/v1/users/profile          # Get user profile
PUT  /api/v1/users/profile          # Update user profile
PUT  /api/v1/users/password         # Change password
POST /api/v1/users/avatar           # Upload avatar
DELETE /api/v1/users/account        # Delete account
```

## 🗄️ Database Schema

### Core Tables
```sql
-- Users table
users (id, email, username, password_hash, oauth_provider, oauth_subject, 
       email_verified, status, created_at, updated_at)

-- User profiles table  
user_profiles (user_id, nickname, avatar_url, timezone, preferences, 
               created_at, updated_at)

-- Refresh tokens table
refresh_tokens (id, user_id, token_hash, expires_at, is_revoked, 
                device_info, ip_address, user_agent, created_at, updated_at)

-- JWT blacklist table
jwt_blacklist (id, token_hash, user_id, expires_at, created_at)

-- Password reset tokens table
password_reset_tokens (id, user_id, token_hash, expires_at, is_used, 
                       ip_address, created_at)

-- Login logs table
user_login_logs (id, user_id, login_type, ip_address, user_agent, 
                 location, success, failure_reason, created_at)
```

## 🛠️ Configuration

### Environment Variables
```bash
# Server Configuration
ORAURA_SERVER_HOST=0.0.0.0
ORAURA_SERVER_PORT=8080
ORAURA_SERVER_MODE=debug

# Database Configuration
ORAURA_DATABASE_HOST=localhost
ORAURA_DATABASE_PORT=5432
ORAURA_DATABASE_USER=oraura
ORAURA_DATABASE_PASSWORD=password
ORAURA_DATABASE_NAME=oraura_db

# JWT Configuration
ORAURA_JWT_SECRET=your-super-secret-key
ORAURA_JWT_ACCESS_TOKEN_EXPIRE=1h
ORAURA_JWT_REFRESH_TOKEN_EXPIRE=720h

# OAuth Configuration
ORAURA_OAUTH_GOOGLE_CLIENT_ID=your-google-client-id
ORAURA_OAUTH_GOOGLE_CLIENT_SECRET=your-google-client-secret
```

## 🏃‍♂️ Running the Application

### Prerequisites
- Go 1.24.1+
- PostgreSQL 13+
- Redis (optional, for distributed rate limiting)

### Setup Steps
1. **Clone & Navigate**
   ```bash
   cd backend
   ```

2. **Install Dependencies**
   ```bash
   go mod download
   ```

3. **Setup Database**
   ```bash
   # Create PostgreSQL database
   createdb oraura_db
   
   # Run migrations (auto-migration on startup)
   ```

4. **Configure Environment**
   ```bash
   cp configs/app.example.yaml configs/app.env
   # Edit configs/app.env with your settings
   ```

5. **Run Application**
   ```bash
   # Development
   go run cmd/server/main.go
   
   # Or using make (if available)
   make run
   ```

## 🧪 Testing

### Run All Tests
```bash
go test ./...
```

### Run Tests with Coverage
```bash
go test -v -cover ./...
```

### Run Specific Tests
```bash
# Service layer tests
go test ./internal/services -v

# Handler tests
go test ./internal/handlers -v
```

## 📊 Test Coverage

Current test coverage includes:
- ✅ **Service Layer**: User registration, login, profile management, password changes
- ✅ **Handler Layer**: HTTP request/response handling, validation errors
- ✅ **Mock Implementation**: Complete mock interfaces for testing
- 🔄 **Integration Tests**: Basic API endpoint testing

Target: 85%+ test coverage

## 🔒 Security Features

### Implemented Security Measures
1. **Password Security**: bcrypt hashing with salt
2. **JWT Security**: Signed tokens with expiration
3. **Token Blacklisting**: Logout invalidates tokens
4. **Rate Limiting**: Prevents brute force attacks
5. **Input Validation**: Comprehensive request validation
6. **CORS Protection**: Configurable cross-origin policies
7. **Audit Logging**: Complete login attempt tracking

### Security Best Practices
- Passwords never stored in plain text
- Sensitive data excluded from JSON responses
- JWT tokens have short expiration times
- Refresh tokens are securely hashed
- Failed login attempts are logged and limited

## 🔮 Future Enhancements

### Phase 2 Features (Ready for Implementation)
- **OAuth Integration**: Complete Google & Apple Sign-In
- **Email Verification**: Account activation via email
- **Password Recovery**: Email-based reset functionality
- **Two-Factor Authentication**: TOTP support
- **Session Management**: Multiple device handling
- **Advanced Auditing**: Enhanced security logging

### Phase 3 Features
- **Social Features**: User connections & sharing
- **Admin Panel**: User management interface
- **Analytics**: User behavior tracking
- **Notifications**: Push notification system

## 🏆 Quality Assurance

### Code Quality Standards
- ✅ **Go Best Practices**: Followed official Go guidelines
- ✅ **Clean Architecture**: Clear separation of concerns  
- ✅ **SOLID Principles**: Applied throughout the codebase
- ✅ **Error Handling**: Comprehensive error management
- ✅ **Logging**: Structured logging with Zap
- ✅ **Documentation**: Swagger API documentation ready
- ✅ **Testing**: Unit tests with mocking

### Performance Considerations
- Database connection pooling configured
- JWT tokens for stateless authentication
- Efficient database queries with proper indexing
- Rate limiting to prevent abuse
- Pagination ready for large datasets

## 🚀 Production Readiness

### Deployment Features
- **Docker Support**: Containerization ready
- **Health Checks**: `/health` endpoint for monitoring
- **Graceful Shutdown**: Proper resource cleanup
- **Configuration Management**: Environment-based config
- **Logging**: Structured JSON logging for production
- **Metrics**: Ready for Prometheus integration

### Scalability Features
- **Stateless Design**: Horizontal scaling ready
- **Database Connection Pool**: Optimized for high load
- **Caching Layer**: Redis integration interfaces ready
- **Load Balancer Friendly**: No session dependencies

---

## 📝 API Documentation

For complete API documentation, see the Swagger definitions in the handler files. The API follows RESTful conventions with consistent error response formats.

**Base URL**: `http://localhost:8080/api/v1`

**Authentication**: Bearer JWT tokens in Authorization header

**Content-Type**: `application/json`

This implementation provides a solid foundation for the OrAura application's user management system with enterprise-grade security, scalability, and maintainability.