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
	IDToken     string         `json:"id_token,omitempty"`
	AccessToken string         `json:"access_token" validate:"required"`
	UserInfo    *OAuthUserInfo `json:"user_info,omitempty"`
}

// OAuth 用户信息
type OAuthUserInfo struct {
	Name  *OAuthName `json:"name,omitempty"`
	Email *string    `json:"email,omitempty"`
}

// OAuth 内部用户信息（用于服务间传递）
type OAuthUserProfile struct {
	Provider   string     `json:"provider"`
	ProviderID string     `json:"provider_id"`
	Email      string     `json:"email"`
	Name       *OAuthName `json:"name,omitempty"`
	AvatarURL  string     `json:"avatar_url,omitempty"`
	Locale     string     `json:"locale,omitempty"`
}

// OAuth 姓名信息
type OAuthName struct {
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	FullName  string `json:"fullName,omitempty"`
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
	
	// 新增角色相关字段
	DefaultRole     UserRole     `json:"default_role"`
	CurrentRole     UserRole     `json:"current_role"`
	Roles           []RoleInfo   `json:"roles,omitempty"`
	MembershipExpiry *time.Time  `json:"membership_expiry,omitempty"`
	LastLoginAt     *time.Time   `json:"last_login_at,omitempty"`
	LoginCount      int          `json:"login_count"`
	
	CreatedAt     time.Time        `json:"created_at"`
	UpdatedAt     time.Time        `json:"updated_at"`
}

// RoleInfo 角色信息响应
type RoleInfo struct {
	ID          uuid.UUID `json:"id"`
	Name        UserRole  `json:"name"`
	DisplayName string    `json:"display_name"`
	Description string    `json:"description"`
	Level       int       `json:"level"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// AdminUserInfo 管理员查看的用户信息
type AdminUserInfo struct {
	ID            uuid.UUID    `json:"id"`
	Email         string       `json:"email"`
	Username      string       `json:"username"`
	EmailVerified bool         `json:"email_verified"`
	Status        UserStatus   `json:"status"`
	DefaultRole   UserRole     `json:"default_role"`
	Roles         []RoleInfo   `json:"roles"`
	LoginCount    int          `json:"login_count"`
	LastLoginAt   *time.Time   `json:"last_login_at,omitempty"`
	MembershipExpiry *time.Time `json:"membership_expiry,omitempty"`
	CreatedAt     time.Time    `json:"created_at"`
	UpdatedAt     time.Time    `json:"updated_at"`
}

// CreateAPITokenRequest 创建API令牌请求
type CreateAPITokenRequest struct {
	Name        string              `json:"name" binding:"required,max=100" example:"My API Token"`
	Permissions APITokenPermissions `json:"permissions" binding:"required"`
	ExpiresAt   *time.Time          `json:"expires_at,omitempty"`
}

// APITokenInfo API令牌信息响应
type APITokenInfo struct {
	ID          uuid.UUID           `json:"id"`
	Name        string              `json:"name"`
	TokenPrefix string              `json:"token_prefix"`
	Permissions APITokenPermissions `json:"permissions"`
	LastUsedAt  *time.Time          `json:"last_used_at,omitempty"`
	ExpiresAt   *time.Time          `json:"expires_at,omitempty"`
	IsActive    bool                `json:"is_active"`
	CreatedAt   time.Time           `json:"created_at"`
}

// APITokenResponse 创建API令牌响应
type APITokenResponse struct {
	Token     string       `json:"token"`      // 完整令牌，只在创建时返回
	TokenInfo APITokenInfo `json:"token_info"`
}

// AssignRoleRequest 分配角色请求
type AssignRoleRequest struct {
	UserID    uuid.UUID  `json:"user_id" binding:"required"`
	RoleID    uuid.UUID  `json:"role_id" binding:"required"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// UpdateUserStatusRequest 更新用户状态请求
type UpdateUserStatusRequest struct {
	Status UserStatus `json:"status" binding:"required,oneof=active suspended deleted"`
	Reason *string    `json:"reason,omitempty" binding:"omitempty,max=255"`
}

// UserListQuery 用户列表查询参数
type UserListQuery struct {
	Page     int        `form:"page,default=1" binding:"min=1"`
	PerPage  int        `form:"per_page,default=20" binding:"min=1,max=100"`
	Status   *UserStatus `form:"status" binding:"omitempty,oneof=active suspended deleted"`
	Role     *UserRole   `form:"role" binding:"omitempty,oneof=regular member admin super_admin"`
	Search   string     `form:"search" binding:"omitempty,max=100"`
	SortBy   string     `form:"sort_by,default=created_at" binding:"omitempty,oneof=created_at updated_at login_count last_login_at"`
	SortDesc bool       `form:"sort_desc,default=true"`
}

// LoginLogQuery 登录日志查询参数
type LoginLogQuery struct {
	Page      int        `form:"page,default=1" binding:"min=1"`
	PerPage   int        `form:"per_page,default=20" binding:"min=1,max=100"`
	UserID    *uuid.UUID `form:"user_id" binding:"omitempty,uuid"`
	IPAddress string     `form:"ip_address" binding:"omitempty"`
	Success   *bool      `form:"success"`
	StartDate *time.Time `form:"start_date" binding:"omitempty"`
	EndDate   *time.Time `form:"end_date" binding:"omitempty"`
	SortDesc  bool       `form:"sort_desc,default=true"`
}

// 头像上传响应
type AvatarUploadResponse struct {
	AvatarURL string `json:"avatar_url"`
}

// 邮箱验证请求
type VerifyEmailRequest struct {
	Token string `json:"token" validate:"required"`
}

// 重新发送验证邮件请求
type ResendVerificationRequest struct {
	Email string `json:"email" validate:"required,email"`
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
		DefaultRole:   u.DefaultRole,
		CurrentRole:   u.GetHighestRole(),
		MembershipExpiry: u.MembershipExpiry,
		LastLoginAt:   u.LastLoginAt,
		LoginCount:    u.LoginCount,
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

	// 转换角色信息
	for _, assignment := range u.RoleAssignments {
		if assignment.IsActive {
			userInfo.Roles = append(userInfo.Roles, RoleInfo{
				ID:          assignment.Role.ID,
				Name:        assignment.Role.Name,
				DisplayName: assignment.Role.DisplayName,
				Description: assignment.Role.Description,
				Level:       assignment.Role.Level,
				ExpiresAt:   assignment.ExpiresAt,
			})
		}
	}
	
	return userInfo
}

// ToAdminUserInfo 将User转换为AdminUserInfo
func (u *User) ToAdminUserInfo() *AdminUserInfo {
	info := &AdminUserInfo{
		ID:            u.ID,
		Email:         u.Email,
		Username:      u.Username,
		EmailVerified: u.EmailVerified,
		Status:        u.Status,
		DefaultRole:   u.DefaultRole,
		LoginCount:    u.LoginCount,
		LastLoginAt:   u.LastLoginAt,
		MembershipExpiry: u.MembershipExpiry,
		CreatedAt:     u.CreatedAt,
		UpdatedAt:     u.UpdatedAt,
	}

	// 转换角色信息
	for _, assignment := range u.RoleAssignments {
		if assignment.IsActive {
			info.Roles = append(info.Roles, RoleInfo{
				ID:          assignment.Role.ID,
				Name:        assignment.Role.Name,
				DisplayName: assignment.Role.DisplayName,
				Description: assignment.Role.Description,
				Level:       assignment.Role.Level,
				ExpiresAt:   assignment.ExpiresAt,
			})
		}
	}

	return info
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

// 补充缺失的DTO类型

// UpdateAPITokenRequest 更新API令牌请求
type UpdateAPITokenRequest struct {
	Name        *string              `json:"name,omitempty" binding:"omitempty,max=100"`
	Permissions *APITokenPermissions `json:"permissions,omitempty"`
	IsActive    *bool                `json:"is_active,omitempty"`
}

// PaginatedResponse 分页响应
type PaginatedResponse struct {
	Data       interface{} `json:"data"`
	Pagination *Pagination `json:"pagination"`
}

// Pagination 分页信息
type Pagination struct {
	Page       int   `json:"page"`
	PageSize   int   `json:"page_size"`
	Total      int64 `json:"total"`
	TotalPages int   `json:"total_pages"`
}

// 管理员相关 DTO

// CreateRoleRequest 创建角色请求
type CreateRoleRequest struct {
	Name        UserRole `json:"name" binding:"required"`
	DisplayName string   `json:"display_name" binding:"required,max=100"`
	Description string   `json:"description" binding:"omitempty,max=255"`
}

// UpdateRoleRequest 更新角色请求
type UpdateRoleRequest struct {
	DisplayName *string `json:"display_name,omitempty" binding:"omitempty,max=100"`
	Description *string `json:"description,omitempty" binding:"omitempty,max=255"`
	IsActive    *bool   `json:"is_active,omitempty"`
}

// RolePermissionRequest 角色权限请求
type RolePermissionRequest struct {
	PermissionIDs []uuid.UUID `json:"permission_ids" binding:"required"`
}

// AdminStatsResponse 管理员统计信息响应
type AdminStatsResponse struct {
	TotalUsers      int64 `json:"total_users"`
	ActiveUsers     int64 `json:"active_users"`
	MemberUsers     int64 `json:"member_users"`
	AdminUsers      int64 `json:"admin_users"`
	NewUsersToday   int64 `json:"new_users_today"`
	NewUsersWeek    int64 `json:"new_users_week"`
	NewUsersMonth   int64 `json:"new_users_month"`
}

// SystemHealthResponse 系统健康检查响应
type SystemHealthResponse struct {
	Status    string                     `json:"status"`
	Timestamp time.Time                  `json:"timestamp"`
	Services  map[string]ServiceHealth   `json:"services"`
}

// ServiceHealth 服务健康状态
type ServiceHealth struct {
	Status    string    `json:"status"`
	Message   string    `json:"message,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
}