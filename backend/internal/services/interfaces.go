package services

import (
	"context"
	"time"

	"github.com/OrAura/backend/internal/models"
	"github.com/google/uuid"
)

// 🎯 按职责拆分接口 - 不再使用巨大的UserService接口

// AuthService 认证层接口 - 只包含认证相关方法
type AuthService interface {
	ValidateAccessToken(ctx context.Context, tokenString string) (*models.User, error)
	IsTokenBlacklisted(ctx context.Context, token string) (bool, error)
	HasPermission(ctx context.Context, userID uuid.UUID, resource, action string) (bool, error)
}

// UserManagementService 用户管理接口 - 只包含用户管理方法
type UserManagementService interface {
	Register(ctx context.Context, req *models.RegisterRequest) (*models.User, error)
	Login(ctx context.Context, req *models.LoginRequest) (*models.TokenResponse, error)
	GetUserProfile(ctx context.Context, userID uuid.UUID) (*models.UserInfo, error)
	UpdateUserProfile(ctx context.Context, userID uuid.UUID, req *models.UpdateProfileRequest) (*models.UserInfo, error)
}

// AdminService 管理员功能接口 - 只包含管理功能
type AdminService interface {
	GetDashboardStats(ctx context.Context) (*models.AdminStatsResponse, error)
	GetSystemHealth(ctx context.Context) (*models.SystemHealthResponse, error)
	ListUsers(ctx context.Context, query *models.UserListQuery) (*models.PaginatedResponse, error)
	GetUserByID(ctx context.Context, userID uuid.UUID) (*models.User, error)
	UpdateUserStatus(ctx context.Context, userID uuid.UUID, req *models.UpdateUserStatusRequest) error
	GetUserLoginLogs(ctx context.Context, query *models.LoginLogQuery) (*models.PaginatedResponse, error)
	AssignRole(ctx context.Context, userID, roleID uuid.UUID, grantedBy uuid.UUID, expiresAt *time.Time) error
	RevokeRole(ctx context.Context, userID, roleID uuid.UUID) error
}

// TokenService 令牌管理接口
type TokenService interface {
	RefreshToken(ctx context.Context, refreshToken string) (*models.TokenResponse, error)
	BlacklistToken(ctx context.Context, token string, userID uuid.UUID, expiresAt time.Time) error
	Logout(ctx context.Context, userID uuid.UUID, accessToken string) error
}