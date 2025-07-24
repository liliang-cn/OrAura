package services

import (
	"context"
	"testing"
	"time"

	"github.com/OrAura/backend/internal/models"
	"github.com/OrAura/backend/internal/utils"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

// MockUserRepository 简化的模拟用户仓储
type MockUserRepository struct {
	mock.Mock
}

// 基本用户操作
func (m *MockUserRepository) CreateUser(ctx context.Context, user *models.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) GetUserByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	args := m.Called(ctx, username)
	if args.Get(0) == nil {
		return nil, args.Error(1)  
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) GetUserByOAuth(ctx context.Context, provider, subject string) (*models.User, error) {
	args := m.Called(ctx, provider, subject)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) UpdateUser(ctx context.Context, user *models.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) DeleteUser(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

// 配置操作
func (m *MockUserRepository) CreateUserProfile(ctx context.Context, profile *models.UserProfile) error {
	args := m.Called(ctx, profile)
	return args.Error(0)
}

func (m *MockUserRepository) GetUserProfile(ctx context.Context, userID uuid.UUID) (*models.UserProfile, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.UserProfile), args.Error(1)
}

func (m *MockUserRepository) UpdateUserProfile(ctx context.Context, profile *models.UserProfile) error {
	args := m.Called(ctx, profile)
	return args.Error(0)
}

// 刷新令牌操作
func (m *MockUserRepository) CreateRefreshToken(ctx context.Context, token *models.RefreshToken) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

func (m *MockUserRepository) GetRefreshToken(ctx context.Context, tokenHash string) (*models.RefreshToken, error) {
	args := m.Called(ctx, tokenHash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.RefreshToken), args.Error(1)
}

func (m *MockUserRepository) UpdateRefreshToken(ctx context.Context, token *models.RefreshToken) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

func (m *MockUserRepository) DeleteRefreshToken(ctx context.Context, tokenHash string) error {
	args := m.Called(ctx, tokenHash)
	return args.Error(0)
}

func (m *MockUserRepository) DeleteUserRefreshTokens(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockUserRepository) DeleteAllRefreshTokens(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockUserRepository) CleanExpiredRefreshTokens(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// JWT黑名单操作
func (m *MockUserRepository) AddToJWTBlacklist(ctx context.Context, blacklist *models.JWTBlacklist) error {
	args := m.Called(ctx, blacklist)
	return args.Error(0)
}

func (m *MockUserRepository) IsJWTBlacklisted(ctx context.Context, tokenHash string) (bool, error) {
	args := m.Called(ctx, tokenHash)
	return args.Bool(0), args.Error(1)
}

func (m *MockUserRepository) IsTokenBlacklisted(ctx context.Context, token string) (bool, error) {
	args := m.Called(ctx, token)
	return args.Bool(0), args.Error(1)
}

func (m *MockUserRepository) BlacklistToken(ctx context.Context, token string, userID uuid.UUID, expiresAt time.Time) error {
	args := m.Called(ctx, token, userID, expiresAt)
	return args.Error(0)
}

func (m *MockUserRepository) CleanExpiredJWTBlacklist(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// 密码重置令牌操作
func (m *MockUserRepository) CreatePasswordResetToken(ctx context.Context, token *models.PasswordResetToken) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

func (m *MockUserRepository) GetPasswordResetToken(ctx context.Context, tokenHash string) (*models.PasswordResetToken, error) {
	args := m.Called(ctx, tokenHash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.PasswordResetToken), args.Error(1)
}

func (m *MockUserRepository) UpdatePasswordResetToken(ctx context.Context, token *models.PasswordResetToken) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

func (m *MockUserRepository) DeletePasswordResetToken(ctx context.Context, tokenHash string) error {
	args := m.Called(ctx, tokenHash)
	return args.Error(0)
}

func (m *MockUserRepository) DeleteUserPasswordResetTokens(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockUserRepository) CleanExpiredPasswordResetTokens(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// 登录日志操作
func (m *MockUserRepository) CreateLoginLog(ctx context.Context, log *models.UserLoginLog) error {
	args := m.Called(ctx, log)
	return args.Error(0)
}

func (m *MockUserRepository) GetUserLoginLogs(ctx context.Context, userID uuid.UUID, limit int) ([]models.UserLoginLog, error) {
	args := m.Called(ctx, userID, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.UserLoginLog), args.Error(1)
}

// 邮箱验证操作
func (m *MockUserRepository) CreateEmailVerification(ctx context.Context, verification *models.EmailVerification) error {
	args := m.Called(ctx, verification)
	return args.Error(0)
}

func (m *MockUserRepository) GetEmailVerificationByToken(ctx context.Context, token string) (*models.EmailVerification, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.EmailVerification), args.Error(1)
}

func (m *MockUserRepository) DeleteEmailVerification(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockUserRepository) DeleteEmailVerificationByUserID(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockUserRepository) CleanExpiredEmailVerifications(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// 角色权限操作
func (m *MockUserRepository) GetRoleByName(ctx context.Context, name models.UserRole) (*models.Role, error) {
	args := m.Called(ctx, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Role), args.Error(1)
}

func (m *MockUserRepository) GetRoleByID(ctx context.Context, roleID uuid.UUID) (*models.Role, error) {
	args := m.Called(ctx, roleID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Role), args.Error(1)
}

func (m *MockUserRepository) GetAllRoles(ctx context.Context) ([]*models.Role, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Role), args.Error(1)
}

func (m *MockUserRepository) CreateRole(ctx context.Context, role *models.Role) error {
	args := m.Called(ctx, role)
	return args.Error(0)
}

func (m *MockUserRepository) UpdateRole(ctx context.Context, role *models.Role) error {
	args := m.Called(ctx, role)
	return args.Error(0)
}

func (m *MockUserRepository) DeleteRole(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockUserRepository) GetPermissionByName(ctx context.Context, name string) (*models.Permission, error) {
	args := m.Called(ctx, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Permission), args.Error(1)
}

func (m *MockUserRepository) GetAllPermissions(ctx context.Context) ([]*models.Permission, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Permission), args.Error(1)
}

func (m *MockUserRepository) CreatePermission(ctx context.Context, permission *models.Permission) error {
	args := m.Called(ctx, permission)
	return args.Error(0)
}

func (m *MockUserRepository) AssignRoleToUser(ctx context.Context, assignment *models.UserRoleAssignment) error {
	args := m.Called(ctx, assignment)
	return args.Error(0)
}

func (m *MockUserRepository) RevokeRoleFromUser(ctx context.Context, userID, roleID uuid.UUID) error {
	args := m.Called(ctx, userID, roleID)
	return args.Error(0)
}

func (m *MockUserRepository) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]*models.Role, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Role), args.Error(1)
}

func (m *MockUserRepository) GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]*models.Permission, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Permission), args.Error(1)
}

func (m *MockUserRepository) AssignPermissionToRole(ctx context.Context, rolePermission *models.RolePermission) error {
	args := m.Called(ctx, rolePermission)
	return args.Error(0)
}

func (m *MockUserRepository) RevokePermissionFromRole(ctx context.Context, roleID, permissionID uuid.UUID) error {
	args := m.Called(ctx, roleID, permissionID)
	return args.Error(0)
}

func (m *MockUserRepository) GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]*models.Permission, error) {
	args := m.Called(ctx, roleID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Permission), args.Error(1)
}

// 统计操作
func (m *MockUserRepository) CountUsers(ctx context.Context) (int64, error) {
	args := m.Called(ctx)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockUserRepository) CountActiveUsers(ctx context.Context, since time.Time) (int64, error) {
	args := m.Called(ctx, since)
	return args.Get(0).(int64), args.Error(1)
}

// 管理员功能
func (m *MockUserRepository) ListUsers(ctx context.Context, query *models.UserListQuery) (*models.PaginatedResponse, error) {
	args := m.Called(ctx, query)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.PaginatedResponse), args.Error(1)
}

// 简化测试用例

func TestUserService_Register(t *testing.T) {
	mockRepo := new(MockUserRepository)
	jwtManager := utils.NewJWTManager("test-secret", time.Hour, 24*time.Hour)
	logger := zap.NewNop()
	userService := NewUserService(mockRepo, jwtManager, logger)

	ctx := context.Background()
	req := &models.RegisterRequest{
		Email:    "test@example.com",
		Username: "testuser",
		Password: "password123",
		Timezone: "UTC",
	}

	// Mock: 检查邮箱不存在
	mockRepo.On("GetUserByEmail", ctx, req.Email).Return(nil, nil)
	// Mock: 检查用户名不存在
	mockRepo.On("GetUserByUsername", ctx, req.Username).Return(nil, nil)
	// Mock: 创建用户成功
	mockRepo.On("CreateUser", ctx, mock.AnythingOfType("*models.User")).Return(nil)
	// Mock: 创建用户配置成功
	mockRepo.On("CreateUserProfile", ctx, mock.AnythingOfType("*models.UserProfile")).Return(nil)

	user, err := userService.Register(ctx, req)

	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, req.Email, user.Email)
	assert.Equal(t, req.Username, user.Username)
	mockRepo.AssertExpectations(t)
}

func TestUserService_Register_EmailExists(t *testing.T) {
	mockRepo := new(MockUserRepository)
	jwtManager := utils.NewJWTManager("test-secret", time.Hour, 24*time.Hour)
	logger := zap.NewNop()
	userService := NewUserService(mockRepo, jwtManager, logger)

	ctx := context.Background()
	req := &models.RegisterRequest{
		Email:    "test@example.com",
		Username: "testuser",
		Password: "password123",
		Timezone: "UTC",
	}

	existingUser := &models.User{
		ID:       uuid.New(),
		Email:    req.Email,
		Username: "existinguser",
	}

	// Mock: 邮箱已存在
	mockRepo.On("GetUserByEmail", ctx, req.Email).Return(existingUser, nil)

	user, err := userService.Register(ctx, req)

	assert.Error(t, err)
	assert.Equal(t, ErrEmailAlreadyExists, err)
	assert.Nil(t, user)
	mockRepo.AssertExpectations(t)
}

func TestUserService_Login_InvalidCredentials(t *testing.T) {
	mockRepo := new(MockUserRepository)
	jwtManager := utils.NewJWTManager("test-secret", time.Hour, 24*time.Hour)
	logger := zap.NewNop()
	userService := NewUserService(mockRepo, jwtManager, logger)

	ctx := context.Background()
	req := &models.LoginRequest{
		Email:    "test@example.com",
		Password: "wrongpassword",
	}

	// Mock: 用户不存在
	mockRepo.On("GetUserByEmail", ctx, req.Email).Return(nil, nil)
	// Mock: 创建登录日志（失败）
	mockRepo.On("CreateLoginLog", ctx, mock.AnythingOfType("*models.UserLoginLog")).Return(nil)

	tokenResponse, err := userService.Login(ctx, req)

	assert.Error(t, err)
	assert.Equal(t, ErrInvalidCredentials, err)
	assert.Nil(t, tokenResponse)
	mockRepo.AssertExpectations(t)
}

func TestUserService_AssignRole(t *testing.T) {
	mockRepo := new(MockUserRepository)
	jwtManager := utils.NewJWTManager("test-secret", time.Hour, 24*time.Hour)
	logger := zap.NewNop()
	userService := NewUserService(mockRepo, jwtManager, logger)

	ctx := context.Background()
	userID := uuid.New()
	roleID := uuid.New()
	grantedBy := uuid.New()

	// 创建测试用户
	user := &models.User{
		ID:     userID,
		Email:  "test@example.com",
		Status: models.UserStatusActive,
	}

	// 创建测试角色
	role := &models.Role{
		ID:          roleID,
		Name:        "admin",
		DisplayName: "管理员",
		Level:       20,
		IsActive:    true,
	}

	// Mock: 获取用户成功（AssignRole内部会调用）
	mockRepo.On("GetUserByID", ctx, userID).Return(user, nil)
	// Mock: 获取角色成功（AssignRole内部会调用）
	mockRepo.On("GetRoleByID", ctx, roleID).Return(role, nil)
	// Mock: 分配角色成功
	mockRepo.On("AssignRoleToUser", ctx, mock.AnythingOfType("*models.UserRoleAssignment")).Return(nil)

	err := userService.AssignRole(ctx, userID, roleID, grantedBy, nil)

	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
}

func TestUserService_RevokeRole(t *testing.T) {
	mockRepo := new(MockUserRepository)
	jwtManager := utils.NewJWTManager("test-secret", time.Hour, 24*time.Hour)
	logger := zap.NewNop()
	userService := NewUserService(mockRepo, jwtManager, logger)

	ctx := context.Background()
	userID := uuid.New()
	roleID := uuid.New()

	// Mock: 撤销角色成功
	mockRepo.On("RevokeRoleFromUser", ctx, userID, roleID).Return(nil)

	err := userService.RevokeRole(ctx, userID, roleID)

	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
}