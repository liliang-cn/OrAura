package models

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// User 用户主表模型
type User struct {
	ID            uuid.UUID  `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	Email         string     `gorm:"uniqueIndex;not null;size:255" json:"email"`
	Username      string     `gorm:"uniqueIndex;not null;size:50" json:"username"`
	PasswordHash  *string    `gorm:"size:255" json:"-"`                   // JSON 中不返回密码
	OAuthProvider *string    `gorm:"size:20" json:"oauth_provider,omitempty"`
	OAuthSubject  *string    `gorm:"size:255" json:"-"`                   // OAuth 用户的唯一标识
	EmailVerified bool       `gorm:"default:false" json:"email_verified"`
	Status        UserStatus `gorm:"type:varchar(20);default:'active'" json:"status"`
	CreatedAt     time.Time  `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt     time.Time  `gorm:"autoUpdateTime" json:"updated_at"`
	
	// 关联
	Profile       *UserProfile     `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"profile,omitempty"`
	RefreshTokens []RefreshToken   `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"-"`
	LoginLogs     []UserLoginLog   `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"-"`
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
	Language      string                `json:"language"`
	Theme         string                `json:"theme"`
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