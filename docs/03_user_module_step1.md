# 用户模块开发文档

## 第1步：模块功能分析与接口清单设计

### 1. 模块概述

**模块名称**: User Module (用户模块)

**模块职责**: 
- 处理用户注册、登录、注销
- JWT Token 签发与刷新 
- OAuth2 第三方登录（Google、Apple）
- 用户信息管理（头像、昵称、偏好设置）
- 用户会话管理
- 用户权限验证

### 2. 功能需求分析

#### 2.1 核心功能

| 功能模块 | 功能描述 | 优先级 |
|---------|----------|--------|
| 用户注册 | 邮箱密码注册，邮箱验证 | P0 |
| 用户登录 | 邮箱密码登录，JWT token 签发 | P0 |
| Token 刷新 | Refresh token 换取新的 access token | P0 |
| OAuth 登录 | Google/Apple 第三方登录 | P1 |
| 用户信息 | 获取、更新用户基本信息 | P1 |
| 密码管理 | 修改密码、忘记密码 | P1 |
| 用户注销 | 登出并使 token 失效 | P2 |
| 账户删除 | 删除用户账户及相关数据 | P2 |

#### 2.2 非功能需求

- **安全性**: 密码 bcrypt 加密，JWT 签名验证，OAuth 安全流程
- **性能**: 登录响应时间 < 200ms，支持并发 1000 用户
- **可用性**: 99.9% 可用性，优雅的错误处理
- **扩展性**: 支持新的 OAuth 提供商接入

### 3. RESTful API 接口设计

#### 3.1 认证相关接口

##### 3.1.1 用户注册
```http
POST /api/v1/auth/register
Content-Type: application/json

# 请求体
{
  \"email\": \"user@example.com\",
  \"password\": \"password123\",
  \"username\": \"johndoe\",
  \"timezone\": \"Asia/Shanghai\"
}

# 响应体 (201 Created)
{
  \"code\": 200,
  \"message\": \"Registration successful\",
  \"data\": {
    \"user_id\": \"550e8400-e29b-41d4-a716-446655440000\",
    \"email\": \"user@example.com\",
    \"username\": \"johndoe\",
    \"created_at\": \"2025-01-15T10:30:00Z\"
  }
}

# 错误响应 (400 Bad Request)
{
  \"code\": 40001,
  \"message\": \"Email already exists\",
  \"errors\": [
    {
      \"field\": \"email\",
      \"message\": \"This email is already registered\"
    }
  ]
}
```

##### 3.1.2 用户登录
```http
POST /api/v1/auth/login
Content-Type: application/json

# 请求体
{
  \"email\": \"user@example.com\",
  \"password\": \"password123\"
}

# 响应体 (200 OK)
{
  \"code\": 200,
  \"message\": \"Login successful\",
  \"data\": {
    \"access_token\": \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...\",
    \"refresh_token\": \"550e8400-e29b-41d4-a716-446655440000\",
    \"token_type\": \"Bearer\",
    \"expires_in\": 3600,
    \"user\": {
      \"user_id\": \"550e8400-e29b-41d4-a716-446655440000\",
      \"email\": \"user@example.com\",
      \"username\": \"johndoe\",
      \"avatar_url\": \"https://cdn.example.com/avatars/default.png\"
    }
  }
}

# 错误响应 (401 Unauthorized)
{
  \"code\": 40101,
  \"message\": \"Invalid credentials\"
}
```

##### 3.1.3 刷新Token
```http
POST /api/v1/auth/refresh
Content-Type: application/json

# 请求体
{
  \"refresh_token\": \"550e8400-e29b-41d4-a716-446655440000\"
}

# 响应体 (200 OK)
{
  \"code\": 200,
  \"message\": \"Token refreshed successfully\",
  \"data\": {
    \"access_token\": \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...\",
    \"token_type\": \"Bearer\",
    \"expires_in\": 3600
  }
}
```

##### 3.1.4 用户注销
```http
POST /api/v1/auth/logout
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# 响应体 (200 OK)  
{
  \"code\": 200,
  \"message\": \"Logout successful\"
}
```

#### 3.2 OAuth 相关接口

##### 3.2.1 Google OAuth 登录
```http
POST /api/v1/auth/oauth/google
Content-Type: application/json

# 请求体
{
  \"id_token\": \"eyJhbGciOiJSUzI1NiIsImtpZCI6IjE2NzAyN...\",
  \"access_token\": \"ya29.a0ARrdaM-2xQv9s4F8V7Q...\"
}

# 响应体 (200 OK)
{
  \"code\": 200,
  \"message\": \"OAuth login successful\",
  \"data\": {
    \"access_token\": \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...\",
    \"refresh_token\": \"550e8400-e29b-41d4-a716-446655440000\",
    \"token_type\": \"Bearer\",
    \"expires_in\": 3600,
    \"user\": {
      \"user_id\": \"550e8400-e29b-41d4-a716-446655440000\",
      \"email\": \"user@gmail.com\",
      \"username\": \"John Doe\",
      \"avatar_url\": \"https://lh3.googleusercontent.com/a/default-user\",
      \"oauth_provider\": \"google\"
    },
    \"is_new_user\": false
  }
}
```

##### 3.2.2 Apple OAuth 登录
```http
POST /api/v1/auth/oauth/apple
Content-Type: application/json

# 请求体
{
  \"id_token\": \"eyJraWQiOiJmaDZCczhDIiwiYWxnIjoiUlMyNTYifQ...\",
  \"authorization_code\": \"c6295ce8e98b4c1f9b49827d7c7b4f8c8.0.rrvs.v8FjVlN...\",
  \"user_info\": {
    \"name\": {
      \"firstName\": \"John\",
      \"lastName\": \"Doe\"
    },
    \"email\": \"user@privaterelay.appleid.com\"
  }
}

# 响应体格式同 Google OAuth
```

#### 3.3 用户信息管理接口

##### 3.3.1 获取用户信息
```http
GET /api/v1/users/profile
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# 响应体 (200 OK)
{
  \"code\": 200,
  \"message\": \"Profile retrieved successfully\",
  \"data\": {
    \"user_id\": \"550e8400-e29b-41d4-a716-446655440000\",
    \"email\": \"user@example.com\",
    \"username\": \"johndoe\",
    \"avatar_url\": \"https://cdn.example.com/avatars/user123.png\",
    \"nickname\": \"John\",
    \"timezone\": \"Asia/Shanghai\",
    \"preferences\": {
      \"language\": \"zh-CN\",
      \"theme\": \"dark\",
      \"notifications\": {
        \"email\": true,
        \"push\": false
      }
    },
    \"oauth_provider\": null,
    \"created_at\": \"2025-01-15T10:30:00Z\",
    \"updated_at\": \"2025-01-20T15:45:00Z\"
  }
}
```

##### 3.3.2 更新用户信息
```http
PUT /api/v1/users/profile
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json

# 请求体
{
  \"username\": \"john_doe_updated\",
  \"nickname\": \"Johnny\",
  \"timezone\": \"America/New_York\",
  \"preferences\": {
    \"language\": \"en-US\",
    \"theme\": \"light\",
    \"notifications\": {
      \"email\": false,
      \"push\": true
    }
  }
}

# 响应体 (200 OK)
{
  \"code\": 200,
  \"message\": \"Profile updated successfully\",
  \"data\": {
    \"user_id\": \"550e8400-e29b-41d4-a716-446655440000\",
    \"username\": \"john_doe_updated\",
    \"nickname\": \"Johnny\",
    \"updated_at\": \"2025-01-20T16:00:00Z\"
  }
}
```

##### 3.3.3 上传头像
```http
POST /api/v1/users/avatar
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: multipart/form-data

# 请求体 (form-data)
avatar: [binary file data]

# 响应体 (200 OK)
{
  \"code\": 200,
  \"message\": \"Avatar uploaded successfully\",
  \"data\": {
    \"avatar_url\": \"https://cdn.example.com/avatars/550e8400-e29b-41d4-a716-446655440000.jpg\"
  }
}
```

#### 3.4 密码管理接口

##### 3.4.1 修改密码
```http
PUT /api/v1/users/password
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json

# 请求体
{
  \"current_password\": \"old_password123\",
  \"new_password\": \"new_password456\",
  \"confirm_password\": \"new_password456\"
}

# 响应体 (200 OK)
{
  \"code\": 200,
  \"message\": \"Password updated successfully\"
}
```

##### 3.4.2 忘记密码
```http
POST /api/v1/auth/forgot-password
Content-Type: application/json

# 请求体
{
  \"email\": \"user@example.com\"
}

# 响应体 (200 OK)
{
  \"code\": 200,
  \"message\": \"Password reset email sent\"
}
```

##### 3.4.3 重置密码
```http
POST /api/v1/auth/reset-password
Content-Type: application/json

# 请求体
{
  \"token\": \"reset_token_from_email\",
  \"new_password\": \"new_password123\",
  \"confirm_password\": \"new_password123\"
}

# 响应体 (200 OK)
{
  \"code\": 200,
  \"message\": \"Password reset successfully\"
}
```

#### 3.5 账户管理接口

##### 3.5.1 删除账户
```http
DELETE /api/v1/users/account
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json

# 请求体
{
  \"password\": \"current_password123\",
  \"confirmation\": \"DELETE_MY_ACCOUNT\"
}

# 响应体 (200 OK)
{
  \"code\": 200,
  \"message\": \"Account deleted successfully\"
}
```

### 4. 错误码设计

#### 4.1 通用错误码

| 错误码 | HTTP状态码 | 错误信息 | 说明 |
|--------|-----------|----------|------|
| 200 | 200 | Success | 请求成功 |
| 40001 | 400 | Invalid request parameters | 请求参数错误 |
| 40002 | 400 | Validation failed | 数据验证失败 |
| 40101 | 401 | Unauthorized | 未授权访问 |
| 40102 | 401 | Token expired | Token 已过期 |
| 40103 | 401 | Invalid token | Token 无效 |
| 40301 | 403 | Forbidden | 禁止访问 |
| 40401 | 404 | Resource not found | 资源不存在 |
| 42901 | 429 | Too many requests | 请求过于频繁 |
| 50001 | 500 | Internal server error | 服务器内部错误 |

#### 4.2 用户模块专用错误码

| 错误码 | HTTP状态码 | 错误信息 | 说明 |
|--------|-----------|----------|------|
| 40011 | 400 | Email already exists | 邮箱已存在 |
| 40012 | 400 | Username already exists | 用户名已存在 |
| 40013 | 400 | Invalid email format | 邮箱格式错误 |
| 40014 | 400 | Password too weak | 密码强度不足 |
| 40015 | 400 | Invalid password format | 密码格式错误 |
| 40111 | 401 | Invalid credentials | 用户名或密码错误 |
| 40112 | 401 | Account not verified | 账户未验证 |
| 40113 | 401 | Account suspended | 账户已被暂停 |
| 40114 | 401 | OAuth verification failed | OAuth 验证失败 |
| 40411 | 404 | User not found | 用户不存在 |
| 40012 | 400 | Current password incorrect | 当前密码错误 |
| 40016 | 400 | Password confirmation mismatch | 密码确认不匹配 |

### 5. 请求/响应数据结构

#### 5.1 统一响应格式

```go
type APIResponse struct {
    Code    int         `json:\"code\"`                // 错误码
    Message string      `json:\"message\"`             // 消息
    Data    interface{} `json:\"data,omitempty\"`      // 数据
    Errors  []FieldError `json:\"errors,omitempty\"`   // 字段错误列表
}

type FieldError struct {
    Field   string `json:\"field\"`   // 字段名
    Message string `json:\"message\"` // 错误信息
}
```

#### 5.2 用户数据结构

```go
type User struct {
    UserID        string              `json:\"user_id\"`
    Email         string              `json:\"email\"`
    Username      string              `json:\"username\"`
    Nickname      *string             `json:\"nickname,omitempty\"`
    AvatarURL     *string             `json:\"avatar_url,omitempty\"`
    Timezone      string              `json:\"timezone\"`
    Preferences   *UserPreferences    `json:\"preferences,omitempty\"`
    OAuthProvider *string             `json:\"oauth_provider,omitempty\"`
    CreatedAt     time.Time           `json:\"created_at\"`
    UpdatedAt     time.Time           `json:\"updated_at\"`
}

type UserPreferences struct {
    Language      string              `json:\"language\"`
    Theme         string              `json:\"theme\"`
    Notifications NotificationSettings `json:\"notifications\"`
}

type NotificationSettings struct {
    Email bool `json:\"email\"`
    Push  bool `json:\"push\"`
}
```

#### 5.3 认证数据结构

```go
type LoginRequest struct {
    Email    string `json:\"email\" validate:\"required,email\"`
    Password string `json:\"password\" validate:\"required,min=8\"`
}

type RegisterRequest struct {
    Email    string `json:\"email\" validate:\"required,email\"`
    Password string `json:\"password\" validate:\"required,min=8,max=128\"`
    Username string `json:\"username\" validate:\"required,min=3,max=50\"`
    Timezone string `json:\"timezone\" validate:\"required\"`
}

type TokenResponse struct {
    AccessToken  string    `json:\"access_token\"`
    RefreshToken string    `json:\"refresh_token\"`
    TokenType    string    `json:\"token_type\"`
    ExpiresIn    int64     `json:\"expires_in\"`
    User         *User     `json:\"user,omitempty\"`
    IsNewUser    bool      `json:\"is_new_user,omitempty\"`
}

type RefreshTokenRequest struct {
    RefreshToken string `json:\"refresh_token\" validate:\"required\"`
}
```

### 6. 接口权限说明

#### 6.1 公开接口 (无需认证)
- POST /api/v1/auth/register
- POST /api/v1/auth/login  
- POST /api/v1/auth/refresh
- POST /api/v1/auth/oauth/google
- POST /api/v1/auth/oauth/apple
- POST /api/v1/auth/forgot-password
- POST /api/v1/auth/reset-password

#### 6.2 受保护接口 (需要 JWT Token)
- POST /api/v1/auth/logout
- GET /api/v1/users/profile
- PUT /api/v1/users/profile  
- POST /api/v1/users/avatar
- PUT /api/v1/users/password
- DELETE /api/v1/users/account

#### 6.3 中间件说明

1. **认证中间件 (AuthMiddleware)**
   - 验证 JWT Token 有效性
   - 提取用户信息到请求上下文
   - 处理 Token 过期和无效情况

2. **限流中间件 (RateLimitMiddleware)**
   - 全局限流：每 IP 每分钟 100 请求
   - 用户限流：每用户每分钟 60 请求
   - 登录限流：每 IP 每分钟 5 次登录尝试

3. **参数验证中间件 (ValidationMiddleware)**
   - 使用 validator 库验证请求参数
   - 统一错误格式返回
   - 支持自定义验证规则

### 7. 下一步计划

接下来将进行：
1. **第2步**: 数据模型定义（SQL + GORM）
2. **第3步**: 路由与 handler 实现  
3. **第4步**: service 逻辑实现
4. **第5步**: repository 实现与封装
5. **第6步**: middleware 设计
6. **第7步**: 单元测试代码
7. **第8步**: Swagger 注释 + API 文档
8. **第9步**: 模块结构组织与使用说明

---

*第1步完成：已完成用户模块的功能分析和详细的 RESTful API 接口设计，包括完整的请求响应格式、错误码定义和权限说明。*