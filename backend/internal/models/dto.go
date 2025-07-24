package models

import (
	"time"

	"github.com/google/uuid"
)

// 注册请求
type RegisterRequest struct {
	Email    string `json:"email" validate:"required,email,max=255"`
	Password string `json:"password" validate:"required,min=8,max=128"`
	Username string `json:"username" validate:"required,min=3,max=50,alphanum"`
	Timezone string `json:"timezone" validate:"required,max=50"`
}

// 登录请求
type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// OAuth 登录请求
type OAuthLoginRequest struct {
	IDToken     string         `json:"id_token" validate:"required"`
	AccessToken *string        `json:"access_token,omitempty"`
	UserInfo    *OAuthUserInfo `json:"user_info,omitempty"`
}

// OAuth 用户信息
type OAuthUserInfo struct {
	Name  *OAuthName `json:"name,omitempty"`
	Email *string    `json:"email,omitempty"`
}

// OAuth 姓名信息
type OAuthName struct {
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
}

// Token 刷新请求
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// 密码修改请求
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" validate:"required"`
	NewPassword     string `json:"new_password" validate:"required,min=8,max=128"`
	ConfirmPassword string `json:"confirm_password" validate:"required,eqfield=NewPassword"`
}

// 忘记密码请求
type ForgotPasswordRequest struct {
	Email string `json:"email" validate:"required,email"`
}

// 重置密码请求
type ResetPasswordRequest struct {
	Token           string `json:"token" validate:"required"`
	NewPassword     string `json:"new_password" validate:"required,min=8,max=128"`
	ConfirmPassword string `json:"confirm_password" validate:"required,eqfield=NewPassword"`
}

// 用户信息更新请求
type UpdateProfileRequest struct {
	Username    *string          `json:"username,omitempty" validate:"omitempty,min=3,max=50,alphanum"`
	Nickname    *string          `json:"nickname,omitempty" validate:"omitempty,max=100"`
	Timezone    *string          `json:"timezone,omitempty" validate:"omitempty,max=50"`
	Preferences *UserPreferences `json:"preferences,omitempty"`
}

// 账户删除请求
type DeleteAccountRequest struct {
	Password     string `json:"password" validate:"required"`
	Confirmation string `json:"confirmation" validate:"required,eq=DELETE_MY_ACCOUNT"`
}

// Token 响应
type TokenResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int64     `json:"expires_in"`
	User         *UserInfo `json:"user,omitempty"`
	IsNewUser    bool      `json:"is_new_user,omitempty"`
}

// 用户信息响应（不包含敏感信息）
type UserInfo struct {
	UserID        uuid.UUID        `json:"user_id"`
	Email         string           `json:"email"`
	Username      string           `json:"username"`
	Nickname      *string          `json:"nickname,omitempty"`
	AvatarURL     *string          `json:"avatar_url,omitempty"`
	Timezone      string           `json:"timezone"`
	Preferences   *UserPreferences `json:"preferences,omitempty"`
	OAuthProvider *string          `json:"oauth_provider,omitempty"`
	EmailVerified bool             `json:"email_verified"`
	CreatedAt     time.Time        `json:"created_at"`
	UpdatedAt     time.Time        `json:"updated_at"`
}

// 头像上传响应
type AvatarUploadResponse struct {
	AvatarURL string `json:"avatar_url"`
}

// API 统一响应格式
type APIResponse struct {
	Code    int         `json:"code"`                // 错误码
	Message string      `json:"message"`             // 消息
	Data    interface{} `json:"data,omitempty"`      // 数据
	Errors  []FieldError `json:"errors,omitempty"`   // 字段错误列表
}

// 字段错误
type FieldError struct {
	Field   string `json:"field"`   // 字段名
	Message string `json:"message"` // 错误信息
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
	} else {
		// 设置默认时区
		userInfo.Timezone = "UTC"
	}
	
	return userInfo
}

// NewSuccessResponse 创建成功响应
func NewSuccessResponse(data interface{}, message string) *APIResponse {
	if message == "" {
		message = "Success"
	}
	return &APIResponse{
		Code:    200,
		Message: message,
		Data:    data,
	}
}

// NewErrorResponse 创建错误响应
func NewErrorResponse(code int, message string, errors []FieldError) *APIResponse {
	return &APIResponse{
		Code:    code,
		Message: message,
		Errors:  errors,
	}
}