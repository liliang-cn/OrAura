package store

import (
	"context"
	"errors"
	"time"

	"github.com/OrAura/backend/internal/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// UserRepository 用户仓储接口
type UserRepository interface {
	// 用户基本操作
	CreateUser(ctx context.Context, user *models.User) error
	GetUserByID(ctx context.Context, id uuid.UUID) (*models.User, error)
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
	GetUserByUsername(ctx context.Context, username string) (*models.User, error)
	GetUserByOAuth(ctx context.Context, provider, subject string) (*models.User, error)
	UpdateUser(ctx context.Context, user *models.User) error
	DeleteUser(ctx context.Context, id uuid.UUID) error
	
	// 用户配置操作
	CreateUserProfile(ctx context.Context, profile *models.UserProfile) error
	GetUserProfile(ctx context.Context, userID uuid.UUID) (*models.UserProfile, error)
	UpdateUserProfile(ctx context.Context, profile *models.UserProfile) error
	
	// 刷新令牌操作
	CreateRefreshToken(ctx context.Context, token *models.RefreshToken) error
	GetRefreshToken(ctx context.Context, tokenHash string) (*models.RefreshToken, error)
	UpdateRefreshToken(ctx context.Context, token *models.RefreshToken) error
	DeleteRefreshToken(ctx context.Context, tokenHash string) error
	DeleteUserRefreshTokens(ctx context.Context, userID uuid.UUID) error
	CleanExpiredRefreshTokens(ctx context.Context) error
	
	// JWT 黑名单操作
	AddToJWTBlacklist(ctx context.Context, blacklist *models.JWTBlacklist) error
	IsJWTBlacklisted(ctx context.Context, tokenHash string) (bool, error)
	CleanExpiredJWTBlacklist(ctx context.Context) error
	
	// 密码重置令牌操作
	CreatePasswordResetToken(ctx context.Context, token *models.PasswordResetToken) error
	GetPasswordResetToken(ctx context.Context, tokenHash string) (*models.PasswordResetToken, error)
	UpdatePasswordResetToken(ctx context.Context, token *models.PasswordResetToken) error
	DeletePasswordResetToken(ctx context.Context, tokenHash string) error
	DeleteUserPasswordResetTokens(ctx context.Context, userID uuid.UUID) error
	CleanExpiredPasswordResetTokens(ctx context.Context) error
	
	// 登录日志操作
	CreateLoginLog(ctx context.Context, log *models.UserLoginLog) error
	GetUserLoginLogs(ctx context.Context, userID uuid.UUID, limit int) ([]models.UserLoginLog, error)
	
	// 邮箱验证操作
	CreateEmailVerification(ctx context.Context, verification *models.EmailVerification) error
	GetEmailVerificationByToken(ctx context.Context, token string) (*models.EmailVerification, error)
	DeleteEmailVerification(ctx context.Context, id uuid.UUID) error
	DeleteEmailVerificationByUserID(ctx context.Context, userID uuid.UUID) error
	CleanExpiredEmailVerifications(ctx context.Context) error
	
	// 统计操作
	CountUsers(ctx context.Context) (int64, error)
	CountActiveUsers(ctx context.Context, since time.Time) (int64, error)
}

// userRepository 用户仓储实现
type userRepository struct {
	db *gorm.DB
}

// NewUserRepository 创建用户仓储
func NewUserRepository(db *gorm.DB) UserRepository {
	return &userRepository{db: db}
}

// 用户基本操作实现

func (r *userRepository) CreateUser(ctx context.Context, user *models.User) error {
	return r.db.WithContext(ctx).Create(user).Error
}

func (r *userRepository) GetUserByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	var user models.User
	err := r.db.WithContext(ctx).Preload("Profile").First(&user, "id = ?", id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

func (r *userRepository) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User
	err := r.db.WithContext(ctx).Preload("Profile").First(&user, "email = ?", email).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

func (r *userRepository) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	var user models.User
	err := r.db.WithContext(ctx).Preload("Profile").First(&user, "username = ?", username).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

func (r *userRepository) GetUserByOAuth(ctx context.Context, provider, subject string) (*models.User, error) {
	var user models.User
	err := r.db.WithContext(ctx).Preload("Profile").First(&user, "oauth_provider = ? AND oauth_subject = ?", provider, subject).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

func (r *userRepository) UpdateUser(ctx context.Context, user *models.User) error {
	return r.db.WithContext(ctx).Save(user).Error
}

func (r *userRepository) DeleteUser(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Delete(&models.User{}, "id = ?", id).Error
}

// 用户配置操作实现

func (r *userRepository) CreateUserProfile(ctx context.Context, profile *models.UserProfile) error {
	return r.db.WithContext(ctx).Create(profile).Error
}

func (r *userRepository) GetUserProfile(ctx context.Context, userID uuid.UUID) (*models.UserProfile, error) {
	var profile models.UserProfile
	err := r.db.WithContext(ctx).First(&profile, "user_id = ?", userID).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &profile, nil
}

func (r *userRepository) UpdateUserProfile(ctx context.Context, profile *models.UserProfile) error {
	return r.db.WithContext(ctx).Save(profile).Error
}

// 刷新令牌操作实现

func (r *userRepository) CreateRefreshToken(ctx context.Context, token *models.RefreshToken) error {
	return r.db.WithContext(ctx).Create(token).Error
}

func (r *userRepository) GetRefreshToken(ctx context.Context, tokenHash string) (*models.RefreshToken, error) {
	var token models.RefreshToken
	err := r.db.WithContext(ctx).First(&token, "token_hash = ? AND is_revoked = false AND expires_at > ?", tokenHash, time.Now()).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &token, nil
}

func (r *userRepository) UpdateRefreshToken(ctx context.Context, token *models.RefreshToken) error {
	return r.db.WithContext(ctx).Save(token).Error
}

func (r *userRepository) DeleteRefreshToken(ctx context.Context, tokenHash string) error {
	return r.db.WithContext(ctx).Delete(&models.RefreshToken{}, "token_hash = ?", tokenHash).Error
}

func (r *userRepository) DeleteUserRefreshTokens(ctx context.Context, userID uuid.UUID) error {
	return r.db.WithContext(ctx).Delete(&models.RefreshToken{}, "user_id = ?", userID).Error
}

func (r *userRepository) CleanExpiredRefreshTokens(ctx context.Context) error {
	return r.db.WithContext(ctx).Delete(&models.RefreshToken{}, "expires_at < ?", time.Now()).Error
}

// JWT 黑名单操作实现

func (r *userRepository) AddToJWTBlacklist(ctx context.Context, blacklist *models.JWTBlacklist) error {
	return r.db.WithContext(ctx).Create(blacklist).Error
}

func (r *userRepository) IsJWTBlacklisted(ctx context.Context, tokenHash string) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&models.JWTBlacklist{}).Where("token_hash = ? AND expires_at > ?", tokenHash, time.Now()).Count(&count).Error
	return count > 0, err
}

func (r *userRepository) CleanExpiredJWTBlacklist(ctx context.Context) error {
	return r.db.WithContext(ctx).Delete(&models.JWTBlacklist{}, "expires_at < ?", time.Now()).Error
}

// 密码重置令牌操作实现

func (r *userRepository) CreatePasswordResetToken(ctx context.Context, token *models.PasswordResetToken) error {
	return r.db.WithContext(ctx).Create(token).Error
}

func (r *userRepository) GetPasswordResetToken(ctx context.Context, tokenHash string) (*models.PasswordResetToken, error) {
	var token models.PasswordResetToken
	err := r.db.WithContext(ctx).First(&token, "token_hash = ? AND is_used = false AND expires_at > ?", tokenHash, time.Now()).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &token, nil
}

func (r *userRepository) UpdatePasswordResetToken(ctx context.Context, token *models.PasswordResetToken) error {
	return r.db.WithContext(ctx).Save(token).Error
}

func (r *userRepository) DeletePasswordResetToken(ctx context.Context, tokenHash string) error {
	return r.db.WithContext(ctx).Delete(&models.PasswordResetToken{}, "token_hash = ?", tokenHash).Error
}

func (r *userRepository) DeleteUserPasswordResetTokens(ctx context.Context, userID uuid.UUID) error {
	return r.db.WithContext(ctx).Delete(&models.PasswordResetToken{}, "user_id = ?", userID).Error
}

func (r *userRepository) CleanExpiredPasswordResetTokens(ctx context.Context) error {
	return r.db.WithContext(ctx).Delete(&models.PasswordResetToken{}, "expires_at < ?", time.Now()).Error
}

// 登录日志操作实现

func (r *userRepository) CreateLoginLog(ctx context.Context, log *models.UserLoginLog) error {
	return r.db.WithContext(ctx).Create(log).Error
}

func (r *userRepository) GetUserLoginLogs(ctx context.Context, userID uuid.UUID, limit int) ([]models.UserLoginLog, error) {
	var logs []models.UserLoginLog
	err := r.db.WithContext(ctx).Where("user_id = ?", userID).Order("created_at DESC").Limit(limit).Find(&logs).Error
	return logs, err
}

// 统计操作实现

func (r *userRepository) CountUsers(ctx context.Context) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&models.User{}).Where("status = ?", models.UserStatusActive).Count(&count).Error
	return count, err
}

func (r *userRepository) CountActiveUsers(ctx context.Context, since time.Time) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).
		Table("users").
		Joins("JOIN user_login_logs ON users.id = user_login_logs.user_id").
		Where("users.status = ? AND user_login_logs.created_at > ? AND user_login_logs.success = true", models.UserStatusActive, since).
		Distinct("users.id").
		Count(&count).Error
	return count, err
}

// 邮箱验证操作实现

func (r *userRepository) CreateEmailVerification(ctx context.Context, verification *models.EmailVerification) error {
	return r.db.WithContext(ctx).Create(verification).Error
}

func (r *userRepository) GetEmailVerificationByToken(ctx context.Context, token string) (*models.EmailVerification, error) {
	var verification models.EmailVerification
	err := r.db.WithContext(ctx).Where("token = ?", token).First(&verification).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &verification, nil
}

func (r *userRepository) DeleteEmailVerification(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Delete(&models.EmailVerification{}, "id = ?", id).Error
}

func (r *userRepository) DeleteEmailVerificationByUserID(ctx context.Context, userID uuid.UUID) error {
	return r.db.WithContext(ctx).Delete(&models.EmailVerification{}, "user_id = ?", userID).Error
}

func (r *userRepository) CleanExpiredEmailVerifications(ctx context.Context) error {
	return r.db.WithContext(ctx).
		Where("expires_at < ?", time.Now()).
		Delete(&models.EmailVerification{}).Error
}