package services

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/OrAura/backend/internal/models"
	"github.com/OrAura/backend/internal/store"
	"github.com/OrAura/backend/internal/utils"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// 业务错误定义
var (
	ErrUserNotFound        = errors.New("user not found")
	ErrUserAlreadyExists   = errors.New("user already exists")
	ErrEmailAlreadyExists  = errors.New("email already exists")
	ErrUsernameAlreadyExists = errors.New("username already exists")
	ErrInvalidCredentials  = errors.New("invalid credentials")
	ErrInvalidPassword     = errors.New("invalid password")
	ErrUserNotActive       = errors.New("user account is not active")
	ErrTokenExpired        = errors.New("token expired")
	ErrTokenInvalid        = errors.New("token invalid")
	ErrPermissionDenied    = errors.New("permission denied")
)

// UserService 用户服务接口
type UserService interface {
	// 认证相关
	Register(ctx context.Context, req *models.RegisterRequest) (*models.User, error)
	Login(ctx context.Context, req *models.LoginRequest) (*models.TokenResponse, error)
	RefreshToken(ctx context.Context, refreshToken string) (*models.TokenResponse, error)
	Logout(ctx context.Context, userID uuid.UUID, accessToken string) error
	
	// OAuth 相关
	LoginWithGoogle(ctx context.Context, req *models.OAuthLoginRequest) (*models.TokenResponse, error)
	LoginWithApple(ctx context.Context, req *models.OAuthLoginRequest) (*models.TokenResponse, error)
	
	// 用户信息管理
	GetUserProfile(ctx context.Context, userID uuid.UUID) (*models.UserInfo, error)
	UpdateUserProfile(ctx context.Context, userID uuid.UUID, req *models.UpdateProfileRequest) (*models.UserInfo, error)
	
	// 密码管理
	ChangePassword(ctx context.Context, userID uuid.UUID, req *models.ChangePasswordRequest) error
	ForgotPassword(ctx context.Context, req *models.ForgotPasswordRequest) error
	ResetPassword(ctx context.Context, req *models.ResetPasswordRequest) error
	
	// 账户管理
	DeleteAccount(ctx context.Context, userID uuid.UUID, req *models.DeleteAccountRequest) error
	
	// 工具方法
	ValidateAccessToken(ctx context.Context, tokenString string) (*models.User, error)
}

// userService 用户服务实现
type userService struct {
	userRepo   store.UserRepository
	jwtManager *utils.JWTManager
	logger     *zap.Logger
}

// NewUserService 创建用户服务
func NewUserService(userRepo store.UserRepository, jwtManager *utils.JWTManager, logger *zap.Logger) UserService {
	return &userService{
		userRepo:   userRepo,
		jwtManager: jwtManager,
		logger:     logger,
	}
}

// Register 用户注册
func (s *userService) Register(ctx context.Context, req *models.RegisterRequest) (*models.User, error) {
	// 检查邮箱是否已存在
	existingUser, err := s.userRepo.GetUserByEmail(ctx, req.Email)
	if err != nil {
		s.logger.Error("Failed to check existing user by email", zap.Error(err))
		return nil, err
	}
	if existingUser != nil {
		return nil, ErrEmailAlreadyExists
	}
	
	// 检查用户名是否已存在
	existingUser, err = s.userRepo.GetUserByUsername(ctx, req.Username)
	if err != nil {
		s.logger.Error("Failed to check existing user by username", zap.Error(err))
		return nil, err
	}
	if existingUser != nil {
		return nil, ErrUsernameAlreadyExists
	}
	
	// 密码哈希
	passwordHash, err := utils.HashPassword(req.Password)
	if err != nil {
		s.logger.Error("Failed to hash password", zap.Error(err))
		return nil, err
	}
	
	// 创建用户
	user := &models.User{
		Email:         strings.ToLower(req.Email),
		Username:      req.Username,
		PasswordHash:  &passwordHash,
		EmailVerified: false,
		Status:        models.UserStatusActive,
	}
	
	if err := s.userRepo.CreateUser(ctx, user); err != nil {
		s.logger.Error("Failed to create user", zap.Error(err))
		return nil, err
	}
	
	// 创建用户配置
	profile := &models.UserProfile{
		UserID:   user.ID,
		Timezone: req.Timezone,
		Preferences: models.UserPreferences{
			Language: "en-US",
			Theme:    "light",
			Notifications: models.NotificationSettings{
				Email: true,
				Push:  true,
			},
		},
	}
	
	if err := s.userRepo.CreateUserProfile(ctx, profile); err != nil {
		s.logger.Error("Failed to create user profile", zap.Error(err))
		return nil, err
	}
	
	user.Profile = profile
	
	s.logger.Info("User registered successfully", zap.String("user_id", user.ID.String()), zap.String("email", user.Email))
	return user, nil
}

// Login 用户登录
func (s *userService) Login(ctx context.Context, req *models.LoginRequest) (*models.TokenResponse, error) {
	// 获取用户
	user, err := s.userRepo.GetUserByEmail(ctx, strings.ToLower(req.Email))
	if err != nil {
		s.logger.Error("Failed to get user by email", zap.Error(err))
		return nil, err
	}
	if user == nil {
		s.logFailedLogin(ctx, uuid.Nil, models.LoginTypePassword, "user not found")
		return nil, ErrInvalidCredentials
	}
	
	// 检查用户状态
	if !user.IsActive() {
		s.logFailedLogin(ctx, user.ID, models.LoginTypePassword, "user not active")
		return nil, ErrUserNotActive
	}
	
	// 验证密码
	if !user.HasPassword() || !utils.VerifyPassword(req.Password, *user.PasswordHash) {
		s.logFailedLogin(ctx, user.ID, models.LoginTypePassword, "invalid password")
		return nil, ErrInvalidCredentials
	}
	
	// 生成令牌
	tokenResponse, err := s.generateTokens(ctx, user)
	if err != nil {
		s.logger.Error("Failed to generate tokens", zap.Error(err))
		return nil, err
	}
	
	// 记录成功登录
	s.logSuccessfulLogin(ctx, user.ID, models.LoginTypePassword)
	
	s.logger.Info("User logged in successfully", zap.String("user_id", user.ID.String()))
	return tokenResponse, nil
}

// RefreshToken 刷新令牌
func (s *userService) RefreshToken(ctx context.Context, refreshToken string) (*models.TokenResponse, error) {
	tokenHash := utils.HashToken(refreshToken)
	
	// 获取刷新令牌
	token, err := s.userRepo.GetRefreshToken(ctx, tokenHash)
	if err != nil {
		s.logger.Error("Failed to get refresh token", zap.Error(err))
		return nil, err
	}
	if token == nil {
		return nil, ErrTokenInvalid
	}
	
	// 检查令牌是否过期
	if token.ExpiresAt.Before(time.Now()) {
		return nil, ErrTokenExpired
	}
	
	// 获取用户信息
	user, err := s.userRepo.GetUserByID(ctx, token.UserID)
	if err != nil {
		s.logger.Error("Failed to get user by ID", zap.Error(err))
		return nil, err
	}
	if user == nil || !user.IsActive() {
		return nil, ErrUserNotActive
	}
	
	// 生成新的访问令牌
	accessToken, err := s.jwtManager.GenerateAccessToken(user.ID, user.Email, user.Username)
	if err != nil {
		s.logger.Error("Failed to generate access token", zap.Error(err))
		return nil, err
	}
	
	tokenResponse := &models.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600, // 1小时
		User:         user.ToUserInfo(),
	}
	
	s.logger.Info("Token refreshed successfully", zap.String("user_id", user.ID.String()))
	return tokenResponse, nil
}

// Logout 用户注销
func (s *userService) Logout(ctx context.Context, userID uuid.UUID, accessToken string) error {
	// 将 JWT 添加到黑名单
	tokenHash := utils.HashToken(accessToken)
	blacklist := &models.JWTBlacklist{
		TokenHash: tokenHash,
		UserID:    userID,
		ExpiresAt: time.Now().Add(24 * time.Hour), // JWT 有效期
	}
	
	if err := s.userRepo.AddToJWTBlacklist(ctx, blacklist); err != nil {
		s.logger.Error("Failed to add token to blacklist", zap.Error(err))
		return err
	}
	
	// 删除用户的所有刷新令牌
	if err := s.userRepo.DeleteUserRefreshTokens(ctx, userID); err != nil {
		s.logger.Error("Failed to delete user refresh tokens", zap.Error(err))
		return err
	}
	
	s.logger.Info("User logged out successfully", zap.String("user_id", userID.String()))
	return nil
}

// GetUserProfile 获取用户信息
func (s *userService) GetUserProfile(ctx context.Context, userID uuid.UUID) (*models.UserInfo, error) {
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to get user", zap.Error(err))
		return nil, err
	}
	if user == nil {
		return nil, ErrUserNotFound
	}
	
	return user.ToUserInfo(), nil
}

// UpdateUserProfile 更新用户信息
func (s *userService) UpdateUserProfile(ctx context.Context, userID uuid.UUID, req *models.UpdateProfileRequest) (*models.UserInfo, error) {
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to get user", zap.Error(err))
		return nil, err
	}
	if user == nil {
		return nil, ErrUserNotFound
	}
	
	// 更新用户名
	if req.Username != nil && *req.Username != user.Username {
		// 检查用户名是否已存在
		existingUser, err := s.userRepo.GetUserByUsername(ctx, *req.Username)
		if err != nil {
			s.logger.Error("Failed to check existing username", zap.Error(err))
			return nil, err
		}
		if existingUser != nil && existingUser.ID != user.ID {
			return nil, ErrUsernameAlreadyExists
		}
		user.Username = *req.Username
	}
	
	// 更新用户
	if err := s.userRepo.UpdateUser(ctx, user); err != nil {
		s.logger.Error("Failed to update user", zap.Error(err))
		return nil, err
	}
	
	// 获取或创建用户配置
	profile := user.Profile
	if profile == nil {
		profile = &models.UserProfile{
			UserID:   userID,
			Timezone: "UTC",
			Preferences: models.UserPreferences{
				Language: "en-US",
				Theme:    "light",
				Notifications: models.NotificationSettings{
					Email: true,
					Push:  true,
				},
			},
		}
		if err := s.userRepo.CreateUserProfile(ctx, profile); err != nil {
			s.logger.Error("Failed to create user profile", zap.Error(err))
			return nil, err
		}
	}
	
	// 更新配置
	if req.Nickname != nil {
		profile.Nickname = req.Nickname
	}
	if req.Timezone != nil {
		profile.Timezone = *req.Timezone
	}
	if req.Preferences != nil {
		profile.Preferences = *req.Preferences
	}
	
	if err := s.userRepo.UpdateUserProfile(ctx, profile); err != nil {
		s.logger.Error("Failed to update user profile", zap.Error(err))
		return nil, err
	}
	
	user.Profile = profile
	s.logger.Info("User profile updated successfully", zap.String("user_id", userID.String()))
	return user.ToUserInfo(), nil
}

// ChangePassword 修改密码
func (s *userService) ChangePassword(ctx context.Context, userID uuid.UUID, req *models.ChangePasswordRequest) error {
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to get user", zap.Error(err))
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}
	
	// 验证当前密码
	if !user.HasPassword() || !utils.VerifyPassword(req.CurrentPassword, *user.PasswordHash) {
		return ErrInvalidPassword
	}
	
	// 生成新密码哈希
	newPasswordHash, err := utils.HashPassword(req.NewPassword)
	if err != nil {
		s.logger.Error("Failed to hash new password", zap.Error(err))
		return err
	}
	
	// 更新密码
	user.PasswordHash = &newPasswordHash
	if err := s.userRepo.UpdateUser(ctx, user); err != nil {
		s.logger.Error("Failed to update user password", zap.Error(err))
		return err
	}
	
	// 删除所有刷新令牌，强制重新登录
	if err := s.userRepo.DeleteUserRefreshTokens(ctx, userID); err != nil {
		s.logger.Error("Failed to delete user refresh tokens", zap.Error(err))
		return err
	}
	
	s.logger.Info("Password changed successfully", zap.String("user_id", userID.String()))
	return nil
}

// ValidateAccessToken 验证访问令牌
func (s *userService) ValidateAccessToken(ctx context.Context, tokenString string) (*models.User, error) {
	// 验证 JWT
	claims, err := s.jwtManager.VerifyAccessToken(tokenString)
	if err != nil {
		return nil, err
	}
	
	// 检查令牌是否在黑名单中
	tokenHash := utils.HashToken(tokenString)
	isBlacklisted, err := s.userRepo.IsJWTBlacklisted(ctx, tokenHash)
	if err != nil {
		s.logger.Error("Failed to check JWT blacklist", zap.Error(err))
		return nil, err
	}
	if isBlacklisted {
		return nil, ErrTokenInvalid
	}
	
	// 获取用户信息
	user, err := s.userRepo.GetUserByID(ctx, claims.UserID)
	if err != nil {
		s.logger.Error("Failed to get user", zap.Error(err))
		return nil, err
	}
	if user == nil || !user.IsActive() {
		return nil, ErrUserNotActive
	}
	
	return user, nil
}

// generateTokens 生成访问令牌和刷新令牌
func (s *userService) generateTokens(ctx context.Context, user *models.User) (*models.TokenResponse, error) {
	// 生成访问令牌
	accessToken, err := s.jwtManager.GenerateAccessToken(user.ID, user.Email, user.Username)
	if err != nil {
		return nil, err
	}
	
	// 生成刷新令牌
	refreshTokenString, err := s.jwtManager.GenerateRefreshToken()
	if err != nil {
		return nil, err
	}
	
	// 存储刷新令牌
	refreshToken := &models.RefreshToken{
		UserID:    user.ID,
		TokenHash: utils.HashToken(refreshTokenString),
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour), // 30天
	}
	
	if err := s.userRepo.CreateRefreshToken(ctx, refreshToken); err != nil {
		return nil, err
	}
	
	return &models.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshTokenString,
		TokenType:    "Bearer",
		ExpiresIn:    3600, // 1小时
		User:         user.ToUserInfo(),
	}, nil
}

// logSuccessfulLogin 记录成功登录
func (s *userService) logSuccessfulLogin(ctx context.Context, userID uuid.UUID, loginType models.LoginType) {
	log := &models.UserLoginLog{
		UserID:    userID,
		LoginType: loginType,
		Success:   true,
	}
	
	if err := s.userRepo.CreateLoginLog(ctx, log); err != nil {
		s.logger.Error("Failed to create login log", zap.Error(err))
	}
}

// logFailedLogin 记录失败登录
func (s *userService) logFailedLogin(ctx context.Context, userID uuid.UUID, loginType models.LoginType, reason string) {
	log := &models.UserLoginLog{
		UserID:        userID,
		LoginType:     loginType,
		Success:       false,
		FailureReason: &reason,
	}
	
	if err := s.userRepo.CreateLoginLog(ctx, log); err != nil {
		s.logger.Error("Failed to create login log", zap.Error(err))
	}
}

// 其他方法的实现（OAuth、忘记密码、删除账户等）将在后续实现
func (s *userService) LoginWithGoogle(ctx context.Context, req *models.OAuthLoginRequest) (*models.TokenResponse, error) {
	// TODO: 实现 Google OAuth 登录
	return nil, errors.New("not implemented")
}

func (s *userService) LoginWithApple(ctx context.Context, req *models.OAuthLoginRequest) (*models.TokenResponse, error) {
	// TODO: 实现 Apple OAuth 登录
	return nil, errors.New("not implemented")
}

func (s *userService) ForgotPassword(ctx context.Context, req *models.ForgotPasswordRequest) error {
	// TODO: 实现忘记密码功能
	return errors.New("not implemented")
}

func (s *userService) ResetPassword(ctx context.Context, req *models.ResetPasswordRequest) error {
	// TODO: 实现重置密码功能
	return errors.New("not implemented")
}

func (s *userService) DeleteAccount(ctx context.Context, userID uuid.UUID, req *models.DeleteAccountRequest) error {
	// TODO: 实现删除账户功能
	return errors.New("not implemented")
}