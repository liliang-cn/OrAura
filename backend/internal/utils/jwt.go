package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// JWT 相关错误
var (
	ErrInvalidToken     = errors.New("invalid token")
	ErrTokenExpired     = errors.New("token expired")
	ErrTokenNotFound    = errors.New("token not found")
	ErrInvalidTokenType = errors.New("invalid token type")
	ErrTokenBlacklisted = errors.New("token is blacklisted")
)

// TokenType 令牌类型
type TokenType string

const (
	TokenTypeAccess  TokenType = "access"
	TokenTypeRefresh TokenType = "refresh" 
	TokenTypeAPI     TokenType = "api"
	TokenTypeReset   TokenType = "reset"
	TokenTypeVerify  TokenType = "verify"
)

// JWTClaims JWT 载荷
type JWTClaims struct {
	UserID    uuid.UUID  `json:"user_id"`
	Email     string     `json:"email"`
	Username  string     `json:"username"`
	Role      string     `json:"role"`
	TokenType TokenType  `json:"token_type"`
	SessionID *uuid.UUID `json:"session_id,omitempty"`
	Scopes    []string   `json:"scopes,omitempty"`
	jwt.RegisteredClaims
}

// JWTManager JWT 管理器
type JWTManager struct {
	secretKey            string
	accessTokenDuration  time.Duration
	refreshTokenDuration time.Duration
	apiTokenDuration     time.Duration
	resetTokenDuration   time.Duration
	verifyTokenDuration  time.Duration
	issuer               string
}

// NewJWTManager 创建 JWT 管理器
func NewJWTManager(secretKey string, accessTokenDuration, refreshTokenDuration time.Duration) *JWTManager {
	return &JWTManager{
		secretKey:            secretKey,
		accessTokenDuration:  accessTokenDuration,
		refreshTokenDuration: refreshTokenDuration,
		apiTokenDuration:     24 * time.Hour,     // 默认24小时
		resetTokenDuration:   15 * time.Minute,   // 默认15分钟
		verifyTokenDuration:  24 * time.Hour,     // 默认24小时
		issuer:               "OrAura",
	}
}

// NewJWTManagerComplete 创建完整配置的 JWT 管理器
func NewJWTManagerComplete(
	secretKey string,
	accessTokenDuration,
	refreshTokenDuration,
	apiTokenDuration,
	resetTokenDuration,
	verifyTokenDuration time.Duration,
	issuer string,
) *JWTManager {
	return &JWTManager{
		secretKey:            secretKey,
		accessTokenDuration:  accessTokenDuration,
		refreshTokenDuration: refreshTokenDuration,
		apiTokenDuration:     apiTokenDuration,
		resetTokenDuration:   resetTokenDuration,
		verifyTokenDuration:  verifyTokenDuration,
		issuer:               issuer,
	}
}

// GenerateAccessToken 生成访问令牌
func (manager *JWTManager) GenerateAccessToken(userID uuid.UUID, email, username string) (string, error) {
	return manager.GenerateAccessTokenWithRole(userID, email, username, "regular", nil)
}

// GenerateAccessTokenWithRole 生成带角色的访问令牌
func (manager *JWTManager) GenerateAccessTokenWithRole(
	userID uuid.UUID,
	email, username, role string,
	sessionID *uuid.UUID,
) (string, error) {
	return manager.generateToken(
		userID, email, username, role,
		TokenTypeAccess,
		manager.accessTokenDuration,
		sessionID,
		nil,
	)
}

// generateToken 通用令牌生成
func (manager *JWTManager) generateToken(
	userID uuid.UUID,
	email, username, role string,
	tokenType TokenType,
	duration time.Duration,
	sessionID *uuid.UUID,
	scopes []string,
) (string, error) {
	claims := &JWTClaims{
		UserID:    userID,
		Email:     email,
		Username:  username,
		Role:      role,
		TokenType: tokenType,
		SessionID: sessionID,
		Scopes:    scopes,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    manager.issuer,
			Subject:   userID.String(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(manager.secretKey))
}

// GenerateAPIToken 生成API令牌
func (manager *JWTManager) GenerateAPIToken(
	userID uuid.UUID,
	email, username, role string,
	scopes []string,
	duration time.Duration,
) (string, error) {
	if duration == 0 {
		duration = manager.apiTokenDuration
	}
	return manager.generateToken(
		userID, email, username, role,
		TokenTypeAPI,
		duration,
		nil,
		scopes,
	)
}

// GenerateResetToken 生成密码重置令牌
func (manager *JWTManager) GenerateResetToken(userID uuid.UUID, email string) (string, error) {
	return manager.generateToken(
		userID, email, "", "",
		TokenTypeReset,
		manager.resetTokenDuration,
		nil,
		nil,
	)
}

// GenerateVerifyToken 生成邮箱验证令牌
func (manager *JWTManager) GenerateVerifyToken(userID uuid.UUID, email string) (string, error) {
	return manager.generateToken(
		userID, email, "", "",
		TokenTypeVerify,
		manager.verifyTokenDuration,
		nil,
		nil,
	)
}

// GenerateRefreshToken 生成刷新令牌
func (manager *JWTManager) GenerateRefreshToken() (string, error) {
	tokenBytes := make([]byte, 32)
	_, err := rand.Read(tokenBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate refresh token: %w", err)
	}
	return hex.EncodeToString(tokenBytes), nil
}

// VerifyAccessToken 验证访问令牌
func (manager *JWTManager) VerifyAccessToken(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(manager.secretKey), nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

// HashToken 对令牌进行哈希
func HashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// HashPassword 对密码进行哈希
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// VerifyPassword 验证密码
func VerifyPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// GenerateRandomToken 生成随机令牌
func GenerateRandomToken(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}