package models

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// UserRole 用户角色枚举
type UserRole string

const (
	UserRoleRegular    UserRole = "regular"     // 普通用户
	UserRoleMember     UserRole = "member"      // 会员用户
	UserRoleAdmin      UserRole = "admin"       // 管理员
	UserRoleSuperAdmin UserRole = "super_admin" // 超级管理员
)

// User 用户主表模型
type User struct {
	ID            uuid.UUID  `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	Email         string     `gorm:"uniqueIndex;not null;size:255" json:"email"`
	Username      string     `gorm:"uniqueIndex;not null;size:50" json:"username"`
	PasswordHash  *string    `gorm:"size:255" json:"-"` // JSON 中不返回密码
	OAuthProvider *string    `gorm:"size:20" json:"oauth_provider,omitempty"`
	OAuthSubject  *string    `gorm:"size:255" json:"-"` // OAuth 用户的唯一标识
	EmailVerified bool       `gorm:"default:false" json:"email_verified"`
	Status        UserStatus `gorm:"type:varchar(20);default:'active'" json:"status"`

	// 角色相关字段
	DefaultRole      UserRole   `gorm:"type:varchar(50);default:'regular';index" json:"default_role"`
	MembershipExpiry *time.Time `gorm:"index" json:"membership_expiry,omitempty"` // 会员过期时间
	LastLoginAt      *time.Time `gorm:"index" json:"last_login_at,omitempty"`
	LoginCount       int        `gorm:"default:0" json:"login_count"`

	CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt time.Time `gorm:"autoUpdateTime" json:"updated_at"`

	// 关联
	Profile         *UserProfile         `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"profile,omitempty"`
	RefreshTokens   []RefreshToken       `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"-"`
	LoginLogs       []UserLoginLog       `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"-"`
	RoleAssignments []UserRoleAssignment `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"roles,omitempty"`
	APITokens       []APIToken           `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"-"`
	Sessions        []UserSession        `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"-"`
}

// UserStatus 用户状态枚举
type UserStatus string

const (
	UserStatusActive    UserStatus = "active"
	UserStatusSuspended UserStatus = "suspended"
	UserStatusDeleted   UserStatus = "deleted"
)

// UserProfile 用户配置模型
type UserProfile struct {
	UserID      uuid.UUID       `gorm:"type:uuid;primary_key" json:"user_id"`
	Nickname    *string         `gorm:"size:100" json:"nickname,omitempty"`
	AvatarURL   *string         `gorm:"type:text" json:"avatar_url,omitempty"`
	Timezone    string          `gorm:"size:50;default:'UTC'" json:"timezone"`
	Preferences UserPreferences `gorm:"type:jsonb" json:"preferences"`
	CreatedAt   time.Time       `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt   time.Time       `gorm:"autoUpdateTime" json:"updated_at"`

	// 关联
	User User `gorm:"constraint:OnDelete:CASCADE" json:"-"`
}

// UserPreferences 用户偏好设置
type UserPreferences struct {
	Language      string               `json:"language"`
	Theme         string               `json:"theme"`
	Notifications NotificationSettings `json:"notifications"`
}

// NotificationSettings 通知设置
type NotificationSettings struct {
	Email bool `json:"email"`
	Push  bool `json:"push"`
}

// Scan 实现 sql.Scanner 接口
func (up *UserPreferences) Scan(value interface{}) error {
	if value == nil {
		*up = UserPreferences{
			Language: "en-US",
			Theme:    "light",
			Notifications: NotificationSettings{
				Email: true,
				Push:  true,
			},
		}
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
	}

	return json.Unmarshal(bytes, up)
}

// Value 实现 driver.Valuer 接口
func (up UserPreferences) Value() (driver.Value, error) {
	return json.Marshal(up)
}

// RefreshToken 刷新令牌模型
type RefreshToken struct {
	ID         uuid.UUID  `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	UserID     uuid.UUID  `gorm:"type:uuid;not null;index" json:"user_id"`
	TokenHash  string     `gorm:"size:255;not null;index" json:"-"`
	ExpiresAt  time.Time  `gorm:"not null;index" json:"expires_at"`
	IsRevoked  bool       `gorm:"default:false;index" json:"is_revoked"`
	DeviceInfo DeviceInfo `gorm:"type:jsonb" json:"device_info"`
	IPAddress  *string    `gorm:"type:inet" json:"ip_address,omitempty"`
	UserAgent  *string    `gorm:"type:text" json:"user_agent,omitempty"`
	CreatedAt  time.Time  `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt  time.Time  `gorm:"autoUpdateTime" json:"updated_at"`

	// 关联
	User User `gorm:"constraint:OnDelete:CASCADE" json:"-"`
}

// DeviceInfo 设备信息
type DeviceInfo struct {
	Platform    string `json:"platform"`     // ios, android, web
	DeviceModel string `json:"device_model"` // iPhone 13, Pixel 6, etc
	AppVersion  string `json:"app_version"`  // 1.0.0
	OSVersion   string `json:"os_version"`   // iOS 15.0, Android 12, etc
	DeviceID    string `json:"device_id"`    // 设备唯一标识
}

// Scan 实现 sql.Scanner 接口
func (di *DeviceInfo) Scan(value interface{}) error {
	if value == nil {
		*di = DeviceInfo{}
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
	}

	return json.Unmarshal(bytes, di)
}

// Value 实现 driver.Valuer 接口
func (di DeviceInfo) Value() (driver.Value, error) {
	return json.Marshal(di)
}

// JWTBlacklist JWT 黑名单模型
type JWTBlacklist struct {
	ID        uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	TokenHash string    `gorm:"size:255;not null;index" json:"-"`
	UserID    uuid.UUID `gorm:"type:uuid;not null;index" json:"user_id"`
	ExpiresAt time.Time `gorm:"not null;index" json:"expires_at"`
	CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at"`

	// 关联
	User User `gorm:"constraint:OnDelete:CASCADE" json:"-"`
}

// PasswordResetToken 密码重置令牌模型
type PasswordResetToken struct {
	ID        uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	UserID    uuid.UUID `gorm:"type:uuid;not null;index" json:"user_id"`
	TokenHash string    `gorm:"size:255;not null;index" json:"-"`
	ExpiresAt time.Time `gorm:"not null;index" json:"expires_at"`
	IsUsed    bool      `gorm:"default:false" json:"is_used"`
	IPAddress *string   `gorm:"type:inet" json:"ip_address,omitempty"`
	CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at"`

	// 关联
	User User `gorm:"constraint:OnDelete:CASCADE" json:"-"`
}

// UserLoginLog 用户登录日志模型
type UserLoginLog struct {
	ID            uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	UserID        uuid.UUID `gorm:"type:uuid;not null;index" json:"user_id"`
	LoginType     LoginType `gorm:"type:varchar(20);not null" json:"login_type"`
	IPAddress     *string   `gorm:"type:inet;index" json:"ip_address,omitempty"`
	UserAgent     *string   `gorm:"type:text" json:"user_agent,omitempty"`
	Location      *Location `gorm:"type:jsonb" json:"location,omitempty"`
	Success       bool      `gorm:"not null;index" json:"success"`
	FailureReason *string   `gorm:"size:100" json:"failure_reason,omitempty"`
	CreatedAt     time.Time `gorm:"autoCreateTime;index" json:"created_at"`

	// 关联
	User User `gorm:"constraint:OnDelete:CASCADE" json:"-"`
}

// LoginType 登录类型枚举
type LoginType string

const (
	LoginTypePassword LoginType = "password"
	LoginTypeGoogle   LoginType = "google"
	LoginTypeApple    LoginType = "apple"
	LoginTypeAPIToken LoginType = "api_token"
)

// Location 地理位置信息
type Location struct {
	Country string  `json:"country"`
	Region  string  `json:"region"`
	City    string  `json:"city"`
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
}

// EmailVerification 邮箱验证记录
type EmailVerification struct {
	ID        uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	UserID    uuid.UUID `gorm:"type:uuid;not null;index" json:"user_id"`
	Token     string    `gorm:"size:64;not null;unique" json:"token"`
	ExpiresAt time.Time `gorm:"not null;index" json:"expires_at"`
	CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at"`

	// 关联
	User *User `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"user,omitempty"`
}

// Scan 实现 sql.Scanner 接口
func (l *Location) Scan(value interface{}) error {
	if value == nil {
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
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
	if u.DefaultRole == "" {
		u.DefaultRole = UserRoleRegular
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
	return u.OAuthProvider != nil && *u.OAuthProvider != ""
}

// HasPassword 判断用户是否设置了密码
func (u *User) HasPassword() bool {
	return u.PasswordHash != nil && *u.PasswordHash != ""
}

// IsActive 判断用户是否是活跃状态
func (u *User) IsActive() bool {
	return u.Status == UserStatusActive
}

// HasRole 检查用户是否拥有指定角色
func (u *User) HasRole(role UserRole) bool {
	if u.DefaultRole == role {
		return true
	}

	for _, assignment := range u.RoleAssignments {
		if assignment.IsActive && assignment.Role.Name == role {
			if assignment.ExpiresAt == nil || assignment.ExpiresAt.After(time.Now()) {
				return true
			}
		}
	}
	return false
}

// GetHighestRole 获取用户的最高角色
func (u *User) GetHighestRole() UserRole {
	roles := []UserRole{u.DefaultRole}

	for _, assignment := range u.RoleAssignments {
		if assignment.IsActive && (assignment.ExpiresAt == nil || assignment.ExpiresAt.After(time.Now())) {
			roles = append(roles, assignment.Role.Name)
		}
	}

	// 角色优先级: super_admin > admin > member > regular
	for _, role := range []UserRole{UserRoleSuperAdmin, UserRoleAdmin, UserRoleMember, UserRoleRegular} {
		for _, userRole := range roles {
			if userRole == role {
				return role
			}
		}
	}

	return UserRoleRegular
}

// IsMembershipActive 检查会员是否有效
func (u *User) IsMembershipActive() bool {
	return u.MembershipExpiry != nil && u.MembershipExpiry.After(time.Now())
}

// Role 角色模型
type Role struct {
	ID          uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	Name        UserRole  `gorm:"uniqueIndex;not null;type:varchar(50)" json:"name"`
	DisplayName string    `gorm:"not null;size:100" json:"display_name"` // 显示名称
	Description string    `gorm:"size:255" json:"description"`           // 角色描述
	Level       int       `gorm:"not null;default:0;index" json:"level"` // 角色等级
	IsSystem    bool      `gorm:"default:false;index" json:"is_system"`  // 是否系统角色
	IsActive    bool      `gorm:"default:true;index" json:"is_active"`   // 是否激活
	CreatedAt   time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt   time.Time `gorm:"autoUpdateTime" json:"updated_at"`

	// 关联
	UserRoles       []UserRoleAssignment `gorm:"foreignKey:RoleID;constraint:OnDelete:CASCADE" json:"-"`
	RolePermissions []RolePermission     `gorm:"foreignKey:RoleID;constraint:OnDelete:CASCADE" json:"permissions,omitempty"`
}

// Permission 权限模型
type Permission struct {
	ID          uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	Name        string    `gorm:"uniqueIndex;not null;size:100" json:"name"` // 权限名称
	Description string    `gorm:"size:255" json:"description"`               // 权限描述
	Resource    string    `gorm:"not null;size:100;index" json:"resource"`   // 资源名称
	Action      string    `gorm:"not null;size:50;index" json:"action"`      // 操作类型
	CreatedAt   time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt   time.Time `gorm:"autoUpdateTime" json:"updated_at"`

	// 关联
	RolePermissions []RolePermission `gorm:"foreignKey:PermissionID;constraint:OnDelete:CASCADE" json:"-"`
}

// RolePermission 角色权限关联模型
type RolePermission struct {
	ID           uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	RoleID       uuid.UUID `gorm:"type:uuid;not null;index" json:"role_id"`
	PermissionID uuid.UUID `gorm:"type:uuid;not null;index" json:"permission_id"`
	CreatedAt    time.Time `gorm:"autoCreateTime" json:"created_at"`

	// 关联
	Role       Role       `gorm:"constraint:OnDelete:CASCADE" json:"-"`
	Permission Permission `gorm:"constraint:OnDelete:CASCADE" json:"permission,omitempty"`
}

// UserRoleAssignment 用户角色分配模型
type UserRoleAssignment struct {
	ID        uuid.UUID  `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	UserID    uuid.UUID  `gorm:"type:uuid;not null;index" json:"user_id"`
	RoleID    uuid.UUID  `gorm:"type:uuid;not null;index" json:"role_id"`
	GrantedBy *uuid.UUID `gorm:"type:uuid;index" json:"granted_by,omitempty"` // 授予者ID
	GrantedAt time.Time  `gorm:"autoCreateTime" json:"granted_at"`
	ExpiresAt *time.Time `gorm:"index" json:"expires_at,omitempty"` // 过期时间（可选）
	IsActive  bool       `gorm:"default:true;index" json:"is_active"`

	// 关联
	Role          Role  `gorm:"constraint:OnDelete:CASCADE" json:"role,omitempty"`
	GrantedByUser *User `gorm:"foreignKey:GrantedBy;constraint:OnDelete:SET NULL" json:"-"`
}

// APIToken API令牌模型
type APIToken struct {
	ID          uuid.UUID           `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	UserID      uuid.UUID           `gorm:"type:uuid;not null;index" json:"user_id"`
	Name        string              `gorm:"not null;size:100" json:"name"`              // 令牌名称
	TokenHash   string              `gorm:"size:255;not null;uniqueIndex" json:"-"`     // 令牌哈希
	TokenPrefix string              `gorm:"size:20;not null;index" json:"token_prefix"` // 令牌前缀（显示用）
	Permissions APITokenPermissions `gorm:"type:jsonb" json:"permissions"`              // 令牌权限
	LastUsedAt  *time.Time          `gorm:"index" json:"last_used_at,omitempty"`
	ExpiresAt   *time.Time          `gorm:"index" json:"expires_at,omitempty"` // 过期时间
	IsActive    bool                `gorm:"default:true;index" json:"is_active"`
	CreatedAt   time.Time           `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt   time.Time           `gorm:"autoUpdateTime" json:"updated_at"`

	// 关联
	User User `gorm:"constraint:OnDelete:CASCADE" json:"-"`
}

// APITokenPermissions API令牌权限
type APITokenPermissions struct {
	Scopes       []string          `json:"scopes"`       // 权限范围
	Resources    []string          `json:"resources"`    // 可访问资源
	RateLimit    *TokenRateLimit   `json:"rate_limit"`   // 速率限制
	IPWhitelist  []string          `json:"ip_whitelist"` // IP白名单
	Restrictions TokenRestrictions `json:"restrictions"` // 其他限制
}

// TokenRateLimit 令牌速率限制
type TokenRateLimit struct {
	RequestsPerMinute int `json:"requests_per_minute"`
	RequestsPerHour   int `json:"requests_per_hour"`
	RequestsPerDay    int `json:"requests_per_day"`
}

// TokenRestrictions 令牌限制
type TokenRestrictions struct {
	ReadOnly       bool     `json:"read_only"`       // 只读权限
	AllowedMethods []string `json:"allowed_methods"` // 允许的HTTP方法
	AllowedPaths   []string `json:"allowed_paths"`   // 允许的路径模式
}

// UserSession 用户会话模型
type UserSession struct {
	ID           uuid.UUID  `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	UserID       uuid.UUID  `gorm:"type:uuid;not null;index" json:"user_id"`
	SessionToken string     `gorm:"size:255;not null;uniqueIndex" json:"-"` // 会话令牌哈希
	AccessToken  string     `gorm:"size:1000;not null" json:"-"`            // 当前访问令牌哈希
	RefreshToken string     `gorm:"size:255;not null;uniqueIndex" json:"-"` // 刷新令牌哈希
	DeviceInfo   DeviceInfo `gorm:"type:jsonb" json:"device_info"`
	IPAddress    *string    `gorm:"type:inet" json:"ip_address,omitempty"`
	UserAgent    *string    `gorm:"type:text" json:"user_agent,omitempty"`
	Location     *Location  `gorm:"type:jsonb" json:"location,omitempty"`
	IsActive     bool       `gorm:"default:true;index" json:"is_active"`
	LastActivity time.Time  `gorm:"index" json:"last_activity"`
	ExpiresAt    time.Time  `gorm:"not null;index" json:"expires_at"`
	CreatedAt    time.Time  `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt    time.Time  `gorm:"autoUpdateTime" json:"updated_at"`

	// 关联
	User User `gorm:"constraint:OnDelete:CASCADE" json:"-"`
}

// APITokenPermissions Scanner and Valuer
func (atp *APITokenPermissions) Scan(value interface{}) error {
	if value == nil {
		*atp = APITokenPermissions{}
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
	}

	return json.Unmarshal(bytes, atp)
}

func (atp APITokenPermissions) Value() (driver.Value, error) {
	return json.Marshal(atp)
}

// TableName 指定表名
func (User) TableName() string {
	return "users"
}

func (UserProfile) TableName() string {
	return "user_profiles"
}

func (RefreshToken) TableName() string {
	return "refresh_tokens"
}

func (JWTBlacklist) TableName() string {
	return "jwt_blacklist"
}

func (PasswordResetToken) TableName() string {
	return "password_reset_tokens"
}

func (UserLoginLog) TableName() string {
	return "user_login_logs"
}

func (Role) TableName() string {
	return "roles"
}

func (Permission) TableName() string {
	return "permissions"
}

func (RolePermission) TableName() string {
	return "role_permissions"
}

func (UserRoleAssignment) TableName() string {
	return "user_role_assignments"
}

func (APIToken) TableName() string {
	return "api_tokens"
}

func (UserSession) TableName() string {
	return "user_sessions"
}
