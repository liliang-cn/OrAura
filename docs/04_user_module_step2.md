# 用户模块开发文档 - 第2步：数据模型定义

## 1. 数据库表设计

### 1.1 用户主表 (users)

```sql
-- 用户主表
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255), -- OAuth 用户可能为空
    oauth_provider VARCHAR(20), -- 'google', 'apple', null
    oauth_subject VARCHAR(255), -- OAuth 提供商的用户 ID
    email_verified BOOLEAN DEFAULT FALSE,
    status VARCHAR(20) DEFAULT 'active', -- 'active', 'suspended', 'deleted'
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 索引
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_oauth_provider_subject ON users(oauth_provider, oauth_subject);
CREATE INDEX idx_users_created_at ON users(created_at);
CREATE INDEX idx_users_status ON users(status);
```

### 1.2 用户配置表 (user_profiles)

```sql
-- 用户配置表
CREATE TABLE user_profiles (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    nickname VARCHAR(100),
    avatar_url TEXT,
    timezone VARCHAR(50) DEFAULT 'UTC',
    preferences JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 索引
CREATE INDEX idx_user_profiles_updated_at ON user_profiles(updated_at);
CREATE INDEX idx_user_profiles_preferences ON user_profiles USING GIN(preferences);
```

### 1.3 刷新令牌表 (refresh_tokens)

```sql
-- 刷新令牌表
CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    is_revoked BOOLEAN DEFAULT FALSE,
    device_info JSONB DEFAULT '{}', -- 设备信息
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 索引
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_token_hash ON refresh_tokens(token_hash);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
CREATE INDEX idx_refresh_tokens_is_revoked ON refresh_tokens(is_revoked);
```

### 1.4 JWT 黑名单表 (jwt_blacklist)

```sql
-- JWT 黑名单表（用于注销时使 token 失效）
CREATE TABLE jwt_blacklist (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash VARCHAR(255) NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 索引
CREATE INDEX idx_jwt_blacklist_token_hash ON jwt_blacklist(token_hash);
CREATE INDEX idx_jwt_blacklist_expires_at ON jwt_blacklist(expires_at);
CREATE INDEX idx_jwt_blacklist_user_id ON jwt_blacklist(user_id);
```

### 1.5 密码重置表 (password_reset_tokens)

```sql
-- 密码重置令牌表
CREATE TABLE password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    is_used BOOLEAN DEFAULT FALSE,
    ip_address INET,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 索引
CREATE INDEX idx_password_reset_tokens_token_hash ON password_reset_tokens(token_hash);
CREATE INDEX idx_password_reset_tokens_user_id ON password_reset_tokens(user_id);
CREATE INDEX idx_password_reset_tokens_expires_at ON password_reset_tokens(expires_at);
```

### 1.6 用户登录日志表 (user_login_logs)

```sql
-- 用户登录日志表
CREATE TABLE user_login_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    login_type VARCHAR(20) NOT NULL, -- 'password', 'google', 'apple'
    ip_address INET,
    user_agent TEXT,
    location JSONB, -- 地理位置信息
    success BOOLEAN NOT NULL,
    failure_reason VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 索引
CREATE INDEX idx_user_login_logs_user_id ON user_login_logs(user_id);
CREATE INDEX idx_user_login_logs_created_at ON user_login_logs(created_at);
CREATE INDEX idx_user_login_logs_success ON user_login_logs(success);
CREATE INDEX idx_user_login_logs_ip_address ON user_login_logs(ip_address);
```

## 2. GORM 模型定义

### 2.1 用户模型

```go
// internal/user/model.go
package user

import (
    \"time\"
    \"database/sql/driver\"
    \"encoding/json\"
    \"errors\"
    
    \"github.com/google/uuid\"
    \"gorm.io/gorm\"
)

// User 用户主表模型
type User struct {
    ID             uuid.UUID  `gorm:\"type:uuid;primary_key;default:gen_random_uuid()\" json:\"id\"`
    Email          string     `gorm:\"uniqueIndex;not null;size:255\" json:\"email\"`
    Username       string     `gorm:\"uniqueIndex;not null;size:50\" json:\"username\"`
    PasswordHash   *string    `gorm:\"size:255\" json:\"-\"`                   // JSON 中不返回密码
    OAuthProvider  *string    `gorm:\"size:20\" json:\"oauth_provider,omitempty\"`
    OAuthSubject   *string    `gorm:\"size:255\" json:\"-\"`                   // OAuth 用户的唯一标识
    EmailVerified  bool       `gorm:\"default:false\" json:\"email_verified\"`
    Status         UserStatus `gorm:\"type:varchar(20);default:'active'\" json:\"status\"`
    CreatedAt      time.Time  `gorm:\"autoCreateTime\" json:\"created_at\"`
    UpdatedAt      time.Time  `gorm:\"autoUpdateTime\" json:\"updated_at\"`
    
    // 关联
    Profile      *UserProfile     `gorm:\"foreignKey:UserID;constraint:OnDelete:CASCADE\" json:\"profile,omitempty\"`
    RefreshTokens []RefreshToken  `gorm:\"foreignKey:UserID;constraint:OnDelete:CASCADE\" json:\"-\"`
    LoginLogs    []UserLoginLog   `gorm:\"foreignKey:UserID;constraint:OnDelete:CASCADE\" json:\"-\"`
}

// UserStatus 用户状态枚举
type UserStatus string

const (
    UserStatusActive    UserStatus = \"active\"
    UserStatusSuspended UserStatus = \"suspended\"
    UserStatusDeleted   UserStatus = \"deleted\"
)

// UserProfile 用户配置模型
type UserProfile struct {
    UserID      uuid.UUID       `gorm:\"type:uuid;primary_key\" json:\"user_id\"`
    Nickname    *string         `gorm:\"size:100\" json:\"nickname,omitempty\"`
    AvatarURL   *string         `gorm:\"type:text\" json:\"avatar_url,omitempty\"`
    Timezone    string          `gorm:\"size:50;default:'UTC'\" json:\"timezone\"`
    Preferences UserPreferences `gorm:\"type:jsonb\" json:\"preferences\"`
    CreatedAt   time.Time       `gorm:\"autoCreateTime\" json:\"created_at\"`
    UpdatedAt   time.Time       `gorm:\"autoUpdateTime\" json:\"updated_at\"`
    
    // 关联
    User User `gorm:\"constraint:OnDelete:CASCADE\" json:\"-\"`
}

// UserPreferences 用户偏好设置
type UserPreferences struct {
    Language      string                `json:\"language\"`
    Theme         string                `json:\"theme\"`
    Notifications NotificationSettings `json:\"notifications\"`
}

// NotificationSettings 通知设置
type NotificationSettings struct {
    Email bool `json:\"email\"`
    Push  bool `json:\"push\"`
}

// Scan 实现 sql.Scanner 接口
func (up *UserPreferences) Scan(value interface{}) error {
    if value == nil {
        *up = UserPreferences{}
        return nil
    }
    
    bytes, ok := value.([]byte)
    if !ok {
        return errors.New(\"type assertion to []byte failed\")
    }
    
    return json.Unmarshal(bytes, up)
}

// Value 实现 driver.Valuer 接口
func (up UserPreferences) Value() (driver.Value, error) {
    return json.Marshal(up)
}

// RefreshToken 刷新令牌模型
type RefreshToken struct {
    ID         uuid.UUID  `gorm:\"type:uuid;primary_key;default:gen_random_uuid()\" json:\"id\"`
    UserID     uuid.UUID  `gorm:\"type:uuid;not null;index\" json:\"user_id\"`
    TokenHash  string     `gorm:\"size:255;not null;index\" json:\"-\"`
    ExpiresAt  time.Time  `gorm:\"not null;index\" json:\"expires_at\"`
    IsRevoked  bool       `gorm:\"default:false;index\" json:\"is_revoked\"`
    DeviceInfo DeviceInfo `gorm:\"type:jsonb\" json:\"device_info\"`
    IPAddress  *string    `gorm:\"type:inet\" json:\"ip_address,omitempty\"`
    UserAgent  *string    `gorm:\"type:text\" json:\"user_agent,omitempty\"`
    CreatedAt  time.Time  `gorm:\"autoCreateTime\" json:\"created_at\"`
    UpdatedAt  time.Time  `gorm:\"autoUpdateTime\" json:\"updated_at\"`
    
    // 关联
    User User `gorm:\"constraint:OnDelete:CASCADE\" json:\"-\"`
}

// DeviceInfo 设备信息
type DeviceInfo struct {
    Platform     string `json:\"platform\"`      // ios, android, web
    DeviceModel  string `json:\"device_model\"`  // iPhone 13, Pixel 6, etc
    AppVersion   string `json:\"app_version\"`   // 1.0.0
    OSVersion    string `json:\"os_version\"`    // iOS 15.0, Android 12, etc
    DeviceID     string `json:\"device_id\"`     // 设备唯一标识
}

// Scan 实现 sql.Scanner 接口
func (di *DeviceInfo) Scan(value interface{}) error {
    if value == nil {
        *di = DeviceInfo{}
        return nil
    }
    
    bytes, ok := value.([]byte)
    if !ok {
        return errors.New(\"type assertion to []byte failed\")
    }
    
    return json.Unmarshal(bytes, di)
}

// Value 实现 driver.Valuer 接口
func (di DeviceInfo) Value() (driver.Value, error) {
    return json.Marshal(di)
}

// JWTBlacklist JWT 黑名单模型
type JWTBlacklist struct {
    ID        uuid.UUID `gorm:\"type:uuid;primary_key;default:gen_random_uuid()\" json:\"id\"`
    TokenHash string    `gorm:\"size:255;not null;index\" json:\"-\"`
    UserID    uuid.UUID `gorm:\"type:uuid;not null;index\" json:\"user_id\"`
    ExpiresAt time.Time `gorm:\"not null;index\" json:\"expires_at\"`
    CreatedAt time.Time `gorm:\"autoCreateTime\" json:\"created_at\"`
    
    // 关联
    User User `gorm:\"constraint:OnDelete:CASCADE\" json:\"-\"`
}

// PasswordResetToken 密码重置令牌模型
type PasswordResetToken struct {
    ID          uuid.UUID `gorm:\"type:uuid;primary_key;default:gen_random_uuid()\" json:\"id\"`
    UserID      uuid.UUID `gorm:\"type:uuid;not null;index\" json:\"user_id\"`
    TokenHash   string    `gorm:\"size:255;not null;index\" json:\"-\"`
    ExpiresAt   time.Time `gorm:\"not null;index\" json:\"expires_at\"`
    IsUsed      bool      `gorm:\"default:false\" json:\"is_used\"`
    IPAddress   *string   `gorm:\"type:inet\" json:\"ip_address,omitempty\"`
    CreatedAt   time.Time `gorm:\"autoCreateTime\" json:\"created_at\"`
    
    // 关联
    User User `gorm:\"constraint:OnDelete:CASCADE\" json:\"-\"`
}

// UserLoginLog 用户登录日志模型
type UserLoginLog struct {
    ID            uuid.UUID    `gorm:\"type:uuid;primary_key;default:gen_random_uuid()\" json:\"id\"`
    UserID        uuid.UUID    `gorm:\"type:uuid;not null;index\" json:\"user_id\"`
    LoginType     LoginType    `gorm:\"type:varchar(20);not null\" json:\"login_type\"`
    IPAddress     *string      `gorm:\"type:inet;index\" json:\"ip_address,omitempty\"`
    UserAgent     *string      `gorm:\"type:text\" json:\"user_agent,omitempty\"`
    Location      *Location    `gorm:\"type:jsonb\" json:\"location,omitempty\"`
    Success       bool         `gorm:\"not null;index\" json:\"success\"`
    FailureReason *string      `gorm:\"size:100\" json:\"failure_reason,omitempty\"`
    CreatedAt     time.Time    `gorm:\"autoCreateTime;index\" json:\"created_at\"`
    
    // 关联
    User User `gorm:\"constraint:OnDelete:CASCADE\" json:\"-\"`
}

// LoginType 登录类型枚举
type LoginType string

const (
    LoginTypePassword LoginType = \"password\"
    LoginTypeGoogle   LoginType = \"google\"
    LoginTypeApple    LoginType = \"apple\"
)

// Location 地理位置信息
type Location struct {
    Country string  `json:\"country\"`
    Region  string  `json:\"region\"`
    City    string  `json:\"city\"`
    Lat     float64 `json:\"lat\"`
    Lon     float64 `json:\"lon\"`
}

// Scan 实现 sql.Scanner 接口
func (l *Location) Scan(value interface{}) error {
    if value == nil {
        return nil
    }
    
    bytes, ok := value.([]byte)
    if !ok {
        return errors.New(\"type assertion to []byte failed\")
    }
    
    return json.Unmarshal(bytes, l)
}

// Value 实现 driver.Valuer 接口
func (l Location) Value() (driver.Value, error) {
    return json.Marshal(l)
}

// BeforeCreate GORM 钩子 - 创建前
func (u *User) BeforeCreate(tx *gorm.DB) error {
    if u.ID == uuid.Nil {
        u.ID = uuid.New()
    }
    return nil
}

// BeforeUpdate GORM 钩子 - 更新前
func (u *User) BeforeUpdate(tx *gorm.DB) error {
    u.UpdatedAt = time.Now()
    return nil
}

// IsOAuthUser 判断是否是 OAuth 用户
func (u *User) IsOAuthUser() bool {
    return u.OAuthProvider != nil && *u.OAuthProvider != \"\"
}

// HasPassword 判断用户是否设置了密码
func (u *User) HasPassword() bool {
    return u.PasswordHash != nil && *u.PasswordHash != \"\"
}

// IsActive 判断用户是否是活跃状态
func (u *User) IsActive() bool {
    return u.Status == UserStatusActive
}

// TableName 指定表名
func (User) TableName() string {
    return \"users\"
}

func (UserProfile) TableName() string {
    return \"user_profiles\"
}

func (RefreshToken) TableName() string {
    return \"refresh_tokens\"
}

func (JWTBlacklist) TableName() string {
    return \"jwt_blacklist\"
}

func (PasswordResetToken) TableName() string {
    return \"password_reset_tokens\"
}

func (UserLoginLog) TableName() string {
    return \"user_login_logs\"
}
```

### 2.2 请求/响应 DTO 模型

```go
// internal/user/dto.go
package user

import (
    \"time\"
    
    \"github.com/google/uuid\"
)

// 注册请求
type RegisterRequest struct {
    Email    string `json:\"email\" validate:\"required,email,max=255\"`
    Password string `json:\"password\" validate:\"required,min=8,max=128\"`
    Username string `json:\"username\" validate:\"required,min=3,max=50,alphanum\"`
    Timezone string `json:\"timezone\" validate:\"required,max=50\"`
}

// 登录请求
type LoginRequest struct {
    Email    string `json:\"email\" validate:\"required,email\"`
    Password string `json:\"password\" validate:\"required\"`
}

// OAuth 登录请求
type OAuthLoginRequest struct {
    IDToken     string                 `json:\"id_token\" validate:\"required\"`
    AccessToken *string                `json:\"access_token,omitempty\"`
    UserInfo    *OAuthUserInfo         `json:\"user_info,omitempty\"`
}

// OAuth 用户信息
type OAuthUserInfo struct {
    Name  *OAuthName `json:\"name,omitempty\"`
    Email *string    `json:\"email,omitempty\"`
}

// OAuth 姓名信息
type OAuthName struct {
    FirstName string `json:\"firstName\"`
    LastName  string `json:\"lastName\"`
}

// Token 刷新请求
type RefreshTokenRequest struct {
    RefreshToken string `json:\"refresh_token\" validate:\"required\"`
}

// 密码修改请求
type ChangePasswordRequest struct {
    CurrentPassword string `json:\"current_password\" validate:\"required\"`
    NewPassword     string `json:\"new_password\" validate:\"required,min=8,max=128\"`
    ConfirmPassword string `json:\"confirm_password\" validate:\"required,eqfield=NewPassword\"`
}

// 忘记密码请求
type ForgotPasswordRequest struct {
    Email string `json:\"email\" validate:\"required,email\"`
}

// 重置密码请求
type ResetPasswordRequest struct {
    Token           string `json:\"token\" validate:\"required\"`
    NewPassword     string `json:\"new_password\" validate:\"required,min=8,max=128\"`
    ConfirmPassword string `json:\"confirm_password\" validate:\"required,eqfield=NewPassword\"`
}

// 用户信息更新请求
type UpdateProfileRequest struct {
    Username    *string          `json:\"username,omitempty\" validate:\"omitempty,min=3,max=50,alphanum\"`
    Nickname    *string          `json:\"nickname,omitempty\" validate:\"omitempty,max=100\"`
    Timezone    *string          `json:\"timezone,omitempty\" validate:\"omitempty,max=50\"`
    Preferences *UserPreferences `json:\"preferences,omitempty\"`
}

// 账户删除请求
type DeleteAccountRequest struct {
    Password     string `json:\"password\" validate:\"required\"`
    Confirmation string `json:\"confirmation\" validate:\"required,eq=DELETE_MY_ACCOUNT\"`
}

// Token 响应
type TokenResponse struct {
    AccessToken  string    `json:\"access_token\"`
    RefreshToken string    `json:\"refresh_token\"`
    TokenType    string    `json:\"token_type\"`
    ExpiresIn    int64     `json:\"expires_in\"`
    User         *UserInfo `json:\"user,omitempty\"`
    IsNewUser    bool      `json:\"is_new_user,omitempty\"`
}

// 用户信息响应（不包含敏感信息）
type UserInfo struct {
    UserID        uuid.UUID        `json:\"user_id\"`
    Email         string           `json:\"email\"`
    Username      string           `json:\"username\"`
    Nickname      *string          `json:\"nickname,omitempty\"`
    AvatarURL     *string          `json:\"avatar_url,omitempty\"`
    Timezone      string           `json:\"timezone\"`
    Preferences   *UserPreferences `json:\"preferences,omitempty\"`
    OAuthProvider *string          `json:\"oauth_provider,omitempty\"`
    EmailVerified bool             `json:\"email_verified\"`
    CreatedAt     time.Time        `json:\"created_at\"`
    UpdatedAt     time.Time        `json:\"updated_at\"`
}

// 头像上传响应
type AvatarUploadResponse struct {
    AvatarURL string `json:\"avatar_url\"`
}

// 用户转换为 UserInfo
func (u *User) ToUserInfo() *UserInfo {
    userInfo := &UserInfo{
        UserID:        u.ID,
        Email:         u.Email,
        Username:      u.Username,
        OAuthProvider: u.OAuthProvider,
        EmailVerified: u.EmailVerified,
        CreatedAt:     u.CreatedAt,
        UpdatedAt:     u.UpdatedAt,
    }
    
    if u.Profile != nil {
        userInfo.Nickname = u.Profile.Nickname
        userInfo.AvatarURL = u.Profile.AvatarURL
        userInfo.Timezone = u.Profile.Timezone
        userInfo.Preferences = &u.Profile.Preferences
    }
    
    return userInfo
}
```

## 3. 数据库迁移文件

### 3.1 创建用户表迁移

```sql
-- migrations/001_create_users_table.up.sql
CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255),
    oauth_provider VARCHAR(20),
    oauth_subject VARCHAR(255),
    email_verified BOOLEAN DEFAULT FALSE,
    status VARCHAR(20) DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 索引
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_oauth_provider_subject ON users(oauth_provider, oauth_subject);
CREATE INDEX idx_users_created_at ON users(created_at);
CREATE INDEX idx_users_status ON users(status);

-- 约束
ALTER TABLE users ADD CONSTRAINT check_oauth_or_password 
    CHECK (
        (oauth_provider IS NOT NULL AND oauth_subject IS NOT NULL) OR 
        (password_hash IS NOT NULL)
    );

ALTER TABLE users ADD CONSTRAINT check_status 
    CHECK (status IN ('active', 'suspended', 'deleted'));
```

```sql
-- migrations/001_create_users_table.down.sql
DROP TABLE IF EXISTS users CASCADE;
```

### 3.2 创建用户配置表迁移

```sql
-- migrations/002_create_user_profiles_table.up.sql
CREATE TABLE user_profiles (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    nickname VARCHAR(100),
    avatar_url TEXT,
    timezone VARCHAR(50) DEFAULT 'UTC',
    preferences JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 索引
CREATE INDEX idx_user_profiles_updated_at ON user_profiles(updated_at);
CREATE INDEX idx_user_profiles_preferences ON user_profiles USING GIN(preferences);

-- 默认偏好设置
ALTER TABLE user_profiles ALTER COLUMN preferences 
    SET DEFAULT '{\"language\": \"en-US\", \"theme\": \"light\", \"notifications\": {\"email\": true, \"push\": true}}';
```

```sql
-- migrations/002_create_user_profiles_table.down.sql
DROP TABLE IF EXISTS user_profiles CASCADE;
```

### 3.3 创建令牌相关表迁移

```sql
-- migrations/003_create_token_tables.up.sql

-- 刷新令牌表
CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    is_revoked BOOLEAN DEFAULT FALSE,
    device_info JSONB DEFAULT '{}',
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- JWT 黑名单表
CREATE TABLE jwt_blacklist (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash VARCHAR(255) NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 密码重置令牌表
CREATE TABLE password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    is_used BOOLEAN DEFAULT FALSE,
    ip_address INET,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 索引
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_token_hash ON refresh_tokens(token_hash);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
CREATE INDEX idx_refresh_tokens_is_revoked ON refresh_tokens(is_revoked);

CREATE INDEX idx_jwt_blacklist_token_hash ON jwt_blacklist(token_hash);
CREATE INDEX idx_jwt_blacklist_expires_at ON jwt_blacklist(expires_at);
CREATE INDEX idx_jwt_blacklist_user_id ON jwt_blacklist(user_id);

CREATE INDEX idx_password_reset_tokens_token_hash ON password_reset_tokens(token_hash);
CREATE INDEX idx_password_reset_tokens_user_id ON password_reset_tokens(user_id);
CREATE INDEX idx_password_reset_tokens_expires_at ON password_reset_tokens(expires_at);
```

```sql
-- migrations/003_create_token_tables.down.sql
DROP TABLE IF EXISTS password_reset_tokens CASCADE;
DROP TABLE IF EXISTS jwt_blacklist CASCADE;
DROP TABLE IF EXISTS refresh_tokens CASCADE;
```

### 3.4 创建日志表迁移

```sql
-- migrations/004_create_user_login_logs_table.up.sql
CREATE TABLE user_login_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    login_type VARCHAR(20) NOT NULL,
    ip_address INET,
    user_agent TEXT,
    location JSONB,
    success BOOLEAN NOT NULL,
    failure_reason VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 索引
CREATE INDEX idx_user_login_logs_user_id ON user_login_logs(user_id);
CREATE INDEX idx_user_login_logs_created_at ON user_login_logs(created_at);
CREATE INDEX idx_user_login_logs_success ON user_login_logs(success);
CREATE INDEX idx_user_login_logs_ip_address ON user_login_logs(ip_address);

-- 约束
ALTER TABLE user_login_logs ADD CONSTRAINT check_login_type 
    CHECK (login_type IN ('password', 'google', 'apple'));
```

```sql
-- migrations/004_create_user_login_logs_table.down.sql
DROP TABLE IF EXISTS user_login_logs CASCADE;
```

## 4. 数据库连接配置

### 4.1 数据库连接池配置

```go
// internal/common/database/database.go
package database

import (
    \"fmt\"
    \"time\"
    
    \"gorm.io/driver/postgres\"
    \"gorm.io/gorm\"
    \"gorm.io/gorm/logger\"
    
    \"your-project/internal/common/config\"
    \"your-project/internal/user\"
)

type DB struct {
    *gorm.DB
}

func NewDatabase(cfg *config.DatabaseConfig) (*DB, error) {
    dsn := fmt.Sprintf(\"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s\",
        cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.Name, cfg.SSLMode)
    
    // GORM 配置
    gormConfig := &gorm.Config{
        Logger: logger.Default.LogMode(logger.Info),
        NowFunc: func() time.Time {
            return time.Now().UTC()
        },
    }
    
    db, err := gorm.Open(postgres.Open(dsn), gormConfig)
    if err != nil {
        return nil, fmt.Errorf(\"failed to connect to database: %w\", err)
    }
    
    // 获取底层的 sql.DB 实例
    sqlDB, err := db.DB()
    if err != nil {
        return nil, fmt.Errorf(\"failed to get sql.DB instance: %w\", err)
    }
    
    // 设置连接池参数
    sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)
    sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
    sqlDB.SetConnMaxLifetime(cfg.ConnMaxLifetime)
    
    return &DB{db}, nil
}

// AutoMigrate 自动迁移数据库表
func (db *DB) AutoMigrate() error {
    return db.DB.AutoMigrate(
        &user.User{},
        &user.UserProfile{},
        &user.RefreshToken{},
        &user.JWTBlacklist{},
        &user.PasswordResetToken{},
        &user.UserLoginLog{},
    )
}

// Close 关闭数据库连接
func (db *DB) Close() error {
    sqlDB, err := db.DB.DB()
    if err != nil {
        return err
    }
    return sqlDB.Close()
}

// HealthCheck 健康检查
func (db *DB) HealthCheck() error {
    sqlDB, err := db.DB.DB()
    if err != nil {
        return err
    }
    return sqlDB.Ping()
}
```

## 5. 数据模型验证规则

### 5.1 自定义验证器

```go
// internal/common/validator/validator.go
package validator

import (
    \"regexp\"
    \"unicode\"
    
    \"github.com/go-playground/validator/v10\"
)

var validate *validator.Validate

func init() {
    validate = validator.New()
    
    // 注册自定义验证器
    validate.RegisterValidation(\"password\", validatePassword)
    validate.RegisterValidation(\"username\", validateUsername)
}

// GetValidator 获取验证器实例
func GetValidator() *validator.Validate {
    return validate
}

// validatePassword 密码强度验证
func validatePassword(fl validator.FieldLevel) bool {
    password := fl.Field().String()
    
    // 长度检查
    if len(password) < 8 || len(password) > 128 {
        return false
    }
    
    var (
        hasUpper   = false
        hasLower   = false
        hasNumber  = false
        hasSpecial = false
    )
    
    for _, char := range password {
        switch {
        case unicode.IsUpper(char):
            hasUpper = true
        case unicode.IsLower(char):
            hasLower = true
        case unicode.IsNumber(char):
            hasNumber = true
        case unicode.IsPunct(char) || unicode.IsSymbol(char):
            hasSpecial = true
        }
    }
    
    // 至少包含大写字母、小写字母、数字、特殊字符中的三种
    count := 0
    if hasUpper {
        count++
    }
    if hasLower {
        count++
    }
    if hasNumber {
        count++
    }
    if hasSpecial {
        count++
    }
    
    return count >= 3
}

// validateUsername 用户名验证
func validateUsername(fl validator.FieldLevel) bool {
    username := fl.Field().String()
    
    // 只允许字母、数字、下划线，不能以数字开头
    matched, _ := regexp.MatchString(`^[a-zA-Z][a-zA-Z0-9_]*$`, username)
    return matched
}
```

## 6. 下一步计划

已完成数据模型的完整定义，包括：
- ✅ 数据库表结构设计（6个核心表）
- ✅ GORM 模型定义（完整的实体关系）
- ✅ 请求响应 DTO 定义
- ✅ 数据库迁移文件
- ✅ 数据库连接配置
- ✅ 数据验证规则

**下一步将进行第3步**：路由与 handler 实现（含 REST 规范）

---

*第2步完成：已完成用户模块的完整数据模型定义，包括数据库表设计、GORM 模型、DTO 定义、迁移文件和验证规则。数据模型支持完整的用户管理功能，包括OAuth登录、密码管理、会话管理和审计日志。*