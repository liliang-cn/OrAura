# OrAura Backend API Testing Examples

## 1. 用户注册 (Register)
```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "username": "testuser",
    "password": "password123",
    "timezone": "UTC"
  }'
```

**预期响应:**
```json
{
  "code": 200,
  "message": "Registration successful",
  "data": {
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "test@example.com",
    "username": "testuser",
    "timezone": "UTC",
    "email_verified": false,
    "created_at": "2025-01-24T10:30:00Z",
    "updated_at": "2025-01-24T10:30:00Z"
  }
}
```

## 2. 用户登录 (Login)
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "password123"
  }'
```

**预期响应:**
```json
{
  "code": 200,
  "message": "Login successful",
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "550e8400-e29b-41d4-a716-446655440000",
    "token_type": "Bearer",
    "expires_in": 3600,
    "user": {
      "user_id": "550e8400-e29b-41d4-a716-446655440000",
      "email": "test@example.com",
      "username": "testuser",
      "timezone": "UTC"
    }
  }
}
```

## 3. 获取用户信息 (Get Profile)
```bash
curl -X GET http://localhost:8080/api/v1/users/profile \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

## 4. 更新用户信息 (Update Profile)
```bash
curl -X PUT http://localhost:8080/api/v1/users/profile \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "Content-Type: application/json" \
  -d '{
    "username": "newusername",
    "nickname": "My Nickname",
    "timezone": "America/New_York"
  }'
```

## 5. 修改密码 (Change Password)
```bash
curl -X PUT http://localhost:8080/api/v1/users/password \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "Content-Type: application/json" \
  -d '{
    "current_password": "password123",
    "new_password": "newpassword456",
    "confirm_password": "newpassword456"
  }'
```

## 6. 刷新令牌 (Refresh Token)
```bash
curl -X POST http://localhost:8080/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "550e8400-e29b-41d4-a716-446655440000"
  }'
```

## 7. 用户注销 (Logout)
```bash
curl -X POST http://localhost:8080/api/v1/auth/logout \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

## 8. 健康检查 (Health Check)
```bash
curl -X GET http://localhost:8080/health
```

**预期响应:**
```json
{
  "status": "ok",
  "service": "OrAura Backend",
  "time": "2025-01-24T10:30:00Z"
}
```

## HTTPie Examples

使用 HTTPie 测试（更简洁）:

```bash
# 注册
http POST localhost:8080/api/v1/auth/register email=test@example.com username=testuser password=password123 timezone=UTC

# 登录
http POST localhost:8080/api/v1/auth/login email=test@example.com password=password123

# 获取用户信息
http GET localhost:8080/api/v1/users/profile Authorization:"Bearer YOUR_TOKEN"

# 更新用户信息
http PUT localhost:8080/api/v1/users/profile Authorization:"Bearer YOUR_TOKEN" username=newusername nickname="My Nickname"
```

## Postman Collection

导入以下 JSON 到 Postman：

```json
{
  "info": {
    "name": "OrAura Backend API",
    "description": "OrAura 用户模块 API 测试集合"
  },
  "item": [
    {
      "name": "Register",
      "request": {
        "method": "POST",
        "header": [
          {
            "key": "Content-Type",
            "value": "application/json"
          }
        ],
        "body": {
          "mode": "raw",
          "raw": "{\n  \"email\": \"test@example.com\",\n  \"username\": \"testuser\",\n  \"password\": \"password123\",\n  \"timezone\": \"UTC\"\n}"
        },
        "url": {
          "raw": "http://localhost:8080/api/v1/auth/register",
          "protocol": "http",
          "host": ["localhost"],
          "port": "8080",
          "path": ["api", "v1", "auth", "register"]
        }
      }
    },
    {
      "name": "Login",
      "request": {
        "method": "POST",
        "header": [
          {
            "key": "Content-Type",
            "value": "application/json"
          }
        ],
        "body": {
          "mode": "raw",
          "raw": "{\n  \"email\": \"test@example.com\",\n  \"password\": \"password123\"\n}"
        },
        "url": {
          "raw": "http://localhost:8080/api/v1/auth/login",
          "protocol": "http",
          "host": ["localhost"],
          "port": "8080",
          "path": ["api", "v1", "auth", "login"]
        }
      }
    }
  ]
}
```