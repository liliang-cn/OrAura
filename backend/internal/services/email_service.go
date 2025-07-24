package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/OrAura/backend/internal/models"
	"github.com/OrAura/backend/internal/store"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// EmailService 邮件服务接口
type EmailService interface {
	SendVerificationEmail(ctx context.Context, email, token string) error
	SendPasswordResetEmail(ctx context.Context, email, token string) error
	SendWelcomeEmail(ctx context.Context, email, username string) error
}

// EmailProvider 邮件提供商接口
type EmailProvider interface {
	SendEmail(ctx context.Context, to, subject, body string) error
}

type emailService struct {
	provider EmailProvider
	logger   *zap.Logger
}

// NewEmailService 创建邮件服务
func NewEmailService(provider EmailProvider, logger *zap.Logger) EmailService {
	return &emailService{
		provider: provider,
		logger:   logger,
	}
}

// SendVerificationEmail 发送验证邮件
func (s *emailService) SendVerificationEmail(ctx context.Context, email, token string) error {
	subject := "验证您的 OrAura 账户"
	
	// 在生产环境中，这应该是一个HTML模板
	body := fmt.Sprintf(`
尊敬的用户，

感谢您注册 OrAura 账户！

请点击下面的链接验证您的邮箱地址：
https://oraura.app/verify-email?token=%s

此链接将在24小时后失效。

如果您没有注册 OrAura 账户，请忽略此邮件。

祝好，
OrAura 团队
`, token)

	err := s.provider.SendEmail(ctx, email, subject, body)
	if err != nil {
		s.logger.Error("Failed to send verification email", 
			zap.String("email", email), 
			zap.Error(err))
		return fmt.Errorf("failed to send verification email: %w", err)
	}

	s.logger.Info("Verification email sent successfully", zap.String("email", email))
	return nil
}

// SendPasswordResetEmail 发送密码重置邮件
func (s *emailService) SendPasswordResetEmail(ctx context.Context, email, token string) error {
	subject := "重置您的 OrAura 密码"
	
	body := fmt.Sprintf(`
尊敬的用户，

您请求重置 OrAura 账户的密码。

请点击下面的链接重置您的密码：
https://oraura.app/reset-password?token=%s

此链接将在1小时后失效。

如果您没有请求重置密码，请忽略此邮件。

祝好，
OrAura 团队
`, token)

	err := s.provider.SendEmail(ctx, email, subject, body)
	if err != nil {
		s.logger.Error("Failed to send password reset email", 
			zap.String("email", email), 
			zap.Error(err))
		return fmt.Errorf("failed to send password reset email: %w", err)
	}

	s.logger.Info("Password reset email sent successfully", zap.String("email", email))
	return nil
}

// SendWelcomeEmail 发送欢迎邮件
func (s *emailService) SendWelcomeEmail(ctx context.Context, email, username string) error {
	subject := "欢迎加入 OrAura！"
	
	body := fmt.Sprintf(`
尊敬的 %s，

欢迎加入 OrAura 灵性占卜平台！

您的账户已成功创建并验证。现在您可以：
- 探索各种占卜服务
- 咨询专业占卜师
- 管理您的个人档案

开始您的灵性旅程：https://oraura.app/dashboard

如有任何问题，请随时联系我们的客服团队。

祝您占卜愉快，
OrAura 团队
`, username)

	err := s.provider.SendEmail(ctx, email, subject, body)
	if err != nil {
		s.logger.Error("Failed to send welcome email", 
			zap.String("email", email), 
			zap.Error(err))
		return fmt.Errorf("failed to send welcome email: %w", err)
	}

	s.logger.Info("Welcome email sent successfully", zap.String("email", email))
	return nil
}

// MockEmailProvider 模拟邮件提供商（用于开发和测试）
type MockEmailProvider struct {
	logger *zap.Logger
}

// NewMockEmailProvider 创建模拟邮件提供商
func NewMockEmailProvider(logger *zap.Logger) EmailProvider {
	return &MockEmailProvider{logger: logger}
}

// SendEmail 模拟发送邮件
func (p *MockEmailProvider) SendEmail(ctx context.Context, to, subject, body string) error {
	p.logger.Info("Mock email sent", 
		zap.String("to", to),
		zap.String("subject", subject),
		zap.String("body_preview", body[:min(100, len(body))]),
	)
	return nil
}

// min 辅助函数
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// EmailVerificationService 邮箱验证服务
type EmailVerificationService interface {
	GenerateVerificationToken(ctx context.Context, userID uuid.UUID) (string, error)
	VerifyEmailToken(ctx context.Context, token string) (*models.User, error)
	ResendVerificationEmail(ctx context.Context, email string) error
}

type emailVerificationService struct {
	userRepo     store.UserRepository
	emailService EmailService
	logger       *zap.Logger
}

// NewEmailVerificationService 创建邮箱验证服务
func NewEmailVerificationService(userRepo store.UserRepository, emailService EmailService, logger *zap.Logger) EmailVerificationService {
	return &emailVerificationService{
		userRepo:     userRepo,
		emailService: emailService,
		logger:       logger,
	}
}

// GenerateVerificationToken 生成验证令牌
func (s *emailVerificationService) GenerateVerificationToken(ctx context.Context, userID uuid.UUID) (string, error) {
	// 生成32字节随机令牌
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}
	
	token := hex.EncodeToString(tokenBytes)
	
	// 创建验证记录
	verification := &models.EmailVerification{
		UserID:    userID,
		Token:     token,
		ExpiresAt: time.Now().Add(24 * time.Hour), // 24小时后过期
	}
	
	err := s.userRepo.CreateEmailVerification(ctx, verification)
	if err != nil {
		s.logger.Error("Failed to create email verification", zap.Error(err))
		return "", fmt.Errorf("failed to create verification: %w", err)
	}
	
	return token, nil
}

// VerifyEmailToken 验证邮箱令牌
func (s *emailVerificationService) VerifyEmailToken(ctx context.Context, token string) (*models.User, error) {
	// 获取验证记录
	verification, err := s.userRepo.GetEmailVerificationByToken(ctx, token)
	if err != nil {
		s.logger.Error("Failed to get email verification", zap.Error(err))
		return nil, err
	}
	
	if verification == nil {
		return nil, fmt.Errorf("invalid verification token")
	}
	
	// 检查是否过期
	if time.Now().After(verification.ExpiresAt) {
		return nil, fmt.Errorf("verification token expired")
	}
	
	// 获取用户
	user, err := s.userRepo.GetUserByID(ctx, verification.UserID)
	if err != nil {
		s.logger.Error("Failed to get user", zap.Error(err))
		return nil, err
	}
	
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}
	
	// 更新用户邮箱验证状态
	user.EmailVerified = true
	err = s.userRepo.UpdateUser(ctx, user)
	if err != nil {
		s.logger.Error("Failed to update user", zap.Error(err))
		return nil, err
	}
	
	// 删除验证记录
	err = s.userRepo.DeleteEmailVerification(ctx, verification.ID)
	if err != nil {
		s.logger.Error("Failed to delete email verification", zap.Error(err))
		// 不返回错误，因为用户已经验证成功
	}
	
	// 发送欢迎邮件
	go func() {
		if err := s.emailService.SendWelcomeEmail(context.Background(), user.Email, user.Username); err != nil {
			s.logger.Error("Failed to send welcome email", zap.Error(err))
		}
	}()
	
	s.logger.Info("Email verified successfully", zap.String("user_id", user.ID.String()))
	return user, nil
}

// ResendVerificationEmail 重新发送验证邮件
func (s *emailVerificationService) ResendVerificationEmail(ctx context.Context, email string) error {
	// 获取未验证的用户
	user, err := s.userRepo.GetUserByEmail(ctx, email)
	if err != nil {
		s.logger.Error("Failed to get user by email", zap.Error(err))
		return err
	}
	
	if user == nil {
		return fmt.Errorf("user not found")
	}
	
	if user.EmailVerified {
		return fmt.Errorf("email already verified")
	}
	
	// 删除旧的验证记录
	err = s.userRepo.DeleteEmailVerificationByUserID(ctx, user.ID)
	if err != nil {
		s.logger.Error("Failed to delete old verification", zap.Error(err))
		// 继续执行，不返回错误
	}
	
	// 生成新的验证令牌
	token, err := s.GenerateVerificationToken(ctx, user.ID)
	if err != nil {
		return err
	}
	
	// 发送验证邮件
	err = s.emailService.SendVerificationEmail(ctx, user.Email, token)
	if err != nil {
		return err
	}
	
	s.logger.Info("Verification email resent", zap.String("email", email))
	return nil
}