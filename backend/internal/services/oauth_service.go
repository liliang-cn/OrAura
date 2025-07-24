package services

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/OrAura/backend/internal/models"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// OAuthService OAuth服务接口
type OAuthService interface {
	VerifyGoogleToken(ctx context.Context, accessToken string) (*models.OAuthUserProfile, error)
	VerifyAppleToken(ctx context.Context, accessToken string) (*models.OAuthUserProfile, error)
}

type oauthService struct {
	googleConfig *oauth2.Config
	appleConfig  *oauth2.Config
	logger       *zap.Logger
}

// NewOAuthService 创建OAuth服务
func NewOAuthService(googleClientID, googleClientSecret, appleClientID, appleClientSecret string, logger *zap.Logger) OAuthService {
	googleConfig := &oauth2.Config{
		ClientID:     googleClientID,
		ClientSecret: googleClientSecret,
		Endpoint:     google.Endpoint,
		Scopes:       []string{"openid", "profile", "email"},
	}

	// Apple OAuth配置（简化版）
	appleConfig := &oauth2.Config{
		ClientID:     appleClientID,
		ClientSecret: appleClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://appleid.apple.com/auth/authorize",
			TokenURL: "https://appleid.apple.com/auth/token",
		},
		Scopes: []string{"name", "email"},
	}

	return &oauthService{
		googleConfig: googleConfig,
		appleConfig:  appleConfig,
		logger:       logger,
	}
}

// VerifyGoogleToken 验证Google访问令牌
func (s *oauthService) VerifyGoogleToken(ctx context.Context, accessToken string) (*models.OAuthUserProfile, error) {
	// 使用Google的userinfo端点验证令牌
	url := fmt.Sprintf("https://www.googleapis.com/oauth2/v2/userinfo?access_token=%s", accessToken)
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		s.logger.Error("Failed to create Google API request", zap.Error(err))
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		s.logger.Error("Failed to call Google API", zap.Error(err))
		return nil, fmt.Errorf("failed to call Google API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		s.logger.Error("Google API returned error", zap.Int("status", resp.StatusCode))
		return nil, fmt.Errorf("Google API error: status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		s.logger.Error("Failed to read Google API response", zap.Error(err))
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var googleUser struct {
		ID            string `json:"id"`
		Email         string `json:"email"`
		VerifiedEmail bool   `json:"verified_email"`
		Name          string `json:"name"`
		GivenName     string `json:"given_name"`
		FamilyName    string `json:"family_name"`
		Picture       string `json:"picture"`
		Locale        string `json:"locale"`
	}

	if err := json.Unmarshal(body, &googleUser); err != nil {
		s.logger.Error("Failed to parse Google API response", zap.Error(err))
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if !googleUser.VerifiedEmail {
		return nil, fmt.Errorf("Google email not verified")
	}

	oauthUser := &models.OAuthUserProfile{
		Provider:   "google",
		ProviderID: googleUser.ID,
		Email:      googleUser.Email,
		Name: &models.OAuthName{
			FirstName: googleUser.GivenName,
			LastName:  googleUser.FamilyName,
			FullName:  googleUser.Name,
		},
		AvatarURL: googleUser.Picture,
		Locale:    googleUser.Locale,
	}

	s.logger.Info("Successfully verified Google token", 
		zap.String("provider_id", googleUser.ID),
		zap.String("email", googleUser.Email),
	)

	return oauthUser, nil
}

// VerifyAppleToken 验证Apple访问令牌
func (s *oauthService) VerifyAppleToken(ctx context.Context, accessToken string) (*models.OAuthUserProfile, error) {
	// Apple的令牌验证需要JWT解析，这里实现简化版本
	// 在生产环境中，需要验证Apple的JWT令牌签名
	
	// 这里返回一个模拟的实现
	// 实际实现需要解析Apple的Identity Token (JWT)
	s.logger.Warn("Apple OAuth verification is not fully implemented", 
		zap.String("access_token", accessToken[:10]+"..."))
	
	// 模拟实现 - 在生产环境中需要替换为真实的JWT解析
	oauthUser := &models.OAuthUserProfile{
		Provider:   "apple",
		ProviderID: "apple_user_placeholder", // 从JWT中提取
		Email:      "user@privaterelay.appleid.com", // 从JWT中提取
		Name: &models.OAuthName{
			FirstName: "Apple",
			LastName:  "User",
			FullName:  "Apple User",
		},
		AvatarURL: "",
		Locale:    "en",
	}

	return oauthUser, nil
}

// 辅助函数：验证Apple JWT令牌（生产环境实现）
func (s *oauthService) verifyAppleJWT(ctx context.Context, idToken string) (*models.OAuthUserProfile, error) {
	// TODO: 实现Apple JWT令牌验证
	// 1. 从Apple获取公钥
	// 2. 验证JWT签名
	// 3. 解析JWT payload
	// 4. 验证claim（aud, iss, exp等）
	// 5. 返回用户信息
	
	s.logger.Error("Apple JWT verification not implemented")
	return nil, fmt.Errorf("Apple JWT verification not implemented")
}