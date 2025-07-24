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

// MockUserRepository 模拟用户仓储
type MockUserRepository struct {
	mock.Mock
}

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

func (m *MockUserRepository) CleanExpiredRefreshTokens(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockUserRepository) AddToJWTBlacklist(ctx context.Context, blacklist *models.JWTBlacklist) error {
	args := m.Called(ctx, blacklist)
	return args.Error(0)
}

func (m *MockUserRepository) IsJWTBlacklisted(ctx context.Context, tokenHash string) (bool, error) {
	args := m.Called(ctx, tokenHash)
	return args.Bool(0), args.Error(1)
}

func (m *MockUserRepository) CleanExpiredJWTBlacklist(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

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

func (m *MockUserRepository) CleanExpiredPasswordResetTokens(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

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

func (m *MockUserRepository) CountUsers(ctx context.Context) (int64, error) {
	args := m.Called(ctx)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockUserRepository) CountActiveUsers(ctx context.Context, since time.Time) (int64, error) {
	args := m.Called(ctx, since)
	return args.Get(0).(int64), args.Error(1)
}

// 测试用例

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
	assert.True(t, user.HasPassword())
	assert.Equal(t, models.UserStatusActive, user.Status)
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

func TestUserService_Login(t *testing.T) {
	mockRepo := new(MockUserRepository)
	jwtManager := utils.NewJWTManager("test-secret", time.Hour, 24*time.Hour)
	logger := zap.NewNop()
	userService := NewUserService(mockRepo, jwtManager, logger)

	ctx := context.Background()
	
	// 创建测试用户
	passwordHash, _ := utils.HashPassword("password123")
	user := &models.User{
		ID:           uuid.New(),
		Email:        "test@example.com",
		Username:     "testuser",
		PasswordHash: &passwordHash,
		Status:       models.UserStatusActive,
		Profile: &models.UserProfile{
			UserID:   uuid.New(),
			Timezone: "UTC",
		},
	}

	req := &models.LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}

	// Mock: 获取用户成功
	mockRepo.On("GetUserByEmail", ctx, "test@example.com").Return(user, nil)
	// Mock: 创建刷新令牌成功
	mockRepo.On("CreateRefreshToken", ctx, mock.AnythingOfType("*models.RefreshToken")).Return(nil)
	// Mock: 创建登录日志成功
	mockRepo.On("CreateLoginLog", ctx, mock.AnythingOfType("*models.UserLoginLog")).Return(nil)

	tokenResponse, err := userService.Login(ctx, req)

	assert.NoError(t, err)
	assert.NotNil(t, tokenResponse)
	assert.NotEmpty(t, tokenResponse.AccessToken)
	assert.NotEmpty(t, tokenResponse.RefreshToken)
	assert.Equal(t, "Bearer", tokenResponse.TokenType)
	assert.Equal(t, int64(3600), tokenResponse.ExpiresIn)
	assert.NotNil(t, tokenResponse.User)
	assert.Equal(t, user.ID, tokenResponse.User.UserID)
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

func TestUserService_GetUserProfile(t *testing.T) {
	mockRepo := new(MockUserRepository)
	jwtManager := utils.NewJWTManager("test-secret", time.Hour, 24*time.Hour)
	logger := zap.NewNop()
	userService := NewUserService(mockRepo, jwtManager, logger)

	ctx := context.Background()
	userID := uuid.New()

	user := &models.User{
		ID:       userID,
		Email:    "test@example.com",
		Username: "testuser",
		Status:   models.UserStatusActive,
		Profile: &models.UserProfile{
			UserID:   userID,
			Timezone: "UTC",
			Preferences: models.UserPreferences{
				Language: "en-US",
				Theme:    "light",
			},
		},
	}

	// Mock: 获取用户成功
	mockRepo.On("GetUserByID", ctx, userID).Return(user, nil)

	userInfo, err := userService.GetUserProfile(ctx, userID)

	assert.NoError(t, err)
	assert.NotNil(t, userInfo)
	assert.Equal(t, user.ID, userInfo.UserID)
	assert.Equal(t, user.Email, userInfo.Email)
	assert.Equal(t, user.Username, userInfo.Username)
	assert.Equal(t, "UTC", userInfo.Timezone)
	mockRepo.AssertExpectations(t)
}

func TestUserService_UpdateUserProfile(t *testing.T) {
	mockRepo := new(MockUserRepository)
	jwtManager := utils.NewJWTManager("test-secret", time.Hour, 24*time.Hour)
	logger := zap.NewNop()
	userService := NewUserService(mockRepo, jwtManager, logger)

	ctx := context.Background()
	userID := uuid.New()

	user := &models.User{
		ID:       userID,
		Email:    "test@example.com",
		Username: "testuser",
		Status:   models.UserStatusActive,
		Profile: &models.UserProfile{
			UserID:   userID,
			Timezone: "UTC",
		},
	}

	newUsername := "newtestuser"
	newTimezone := "America/New_York"
	req := &models.UpdateProfileRequest{
		Username: &newUsername,
		Timezone: &newTimezone,
	}

	// Mock: 获取用户成功
	mockRepo.On("GetUserByID", ctx, userID).Return(user, nil)
	// Mock: 检查新用户名不存在
	mockRepo.On("GetUserByUsername", ctx, newUsername).Return(nil, nil)
	// Mock: 更新用户成功
	mockRepo.On("UpdateUser", ctx, mock.AnythingOfType("*models.User")).Return(nil)
	// Mock: 更新用户配置成功
	mockRepo.On("UpdateUserProfile", ctx, mock.AnythingOfType("*models.UserProfile")).Return(nil)

	userInfo, err := userService.UpdateUserProfile(ctx, userID, req)

	assert.NoError(t, err)
	assert.NotNil(t, userInfo)
	assert.Equal(t, newUsername, userInfo.Username)
	assert.Equal(t, newTimezone, userInfo.Timezone)
	mockRepo.AssertExpectations(t)
}

func TestUserService_ChangePassword(t *testing.T) {
	mockRepo := new(MockUserRepository)
	jwtManager := utils.NewJWTManager("test-secret", time.Hour, 24*time.Hour)
	logger := zap.NewNop()
	userService := NewUserService(mockRepo, jwtManager, logger)

	ctx := context.Background()
	userID := uuid.New()

	currentPasswordHash, _ := utils.HashPassword("oldpassword123")
	user := &models.User{
		ID:           userID,
		Email:        "test@example.com",
		Username:     "testuser",
		PasswordHash: &currentPasswordHash,
		Status:       models.UserStatusActive,
	}

	req := &models.ChangePasswordRequest{
		CurrentPassword: "oldpassword123",
		NewPassword:     "newpassword123",
		ConfirmPassword: "newpassword123",
	}

	// Mock: 获取用户成功
	mockRepo.On("GetUserByID", ctx, userID).Return(user, nil)
	// Mock: 更新用户成功
	mockRepo.On("UpdateUser", ctx, mock.AnythingOfType("*models.User")).Return(nil)
	// Mock: 删除所有刷新令牌
	mockRepo.On("DeleteUserRefreshTokens", ctx, userID).Return(nil)

	err := userService.ChangePassword(ctx, userID, req)

	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
}

func TestUserService_ChangePassword_InvalidCurrentPassword(t *testing.T) {
	mockRepo := new(MockUserRepository)
	jwtManager := utils.NewJWTManager("test-secret", time.Hour, 24*time.Hour)
	logger := zap.NewNop()
	userService := NewUserService(mockRepo, jwtManager, logger)

	ctx := context.Background()
	userID := uuid.New()

	currentPasswordHash, _ := utils.HashPassword("oldpassword123")
	user := &models.User{
		ID:           userID,
		Email:        "test@example.com",
		Username:     "testuser",
		PasswordHash: &currentPasswordHash,
		Status:       models.UserStatusActive,
	}

	req := &models.ChangePasswordRequest{
		CurrentPassword: "wrongpassword",
		NewPassword:     "newpassword123",
		ConfirmPassword: "newpassword123",
	}

	// Mock: 获取用户成功
	mockRepo.On("GetUserByID", ctx, userID).Return(user, nil)

	err := userService.ChangePassword(ctx, userID, req)

	assert.Error(t, err)
	assert.Equal(t, ErrInvalidPassword, err)
	mockRepo.AssertExpectations(t)
}