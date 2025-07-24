package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/OrAura/backend/internal/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

// 🎯 简洁的AuthService Mock - 只实现3个方法！
type MockAuthService struct {
	users       map[string]*models.User  // token -> user
	blacklist   map[string]bool          // token -> is_blacklisted  
	permissions map[string]bool          // userID:resource:action -> has_permission
}

func NewMockAuthService() *MockAuthService {
	return &MockAuthService{
		users:       make(map[string]*models.User),
		blacklist:   make(map[string]bool),
		permissions: make(map[string]bool),
	}
}

func (m *MockAuthService) ValidateAccessToken(ctx context.Context, tokenString string) (*models.User, error) {
	if user, exists := m.users[tokenString]; exists {
		return user, nil
	}
	return nil, errors.New("invalid token")
}

func (m *MockAuthService) IsTokenBlacklisted(ctx context.Context, token string) (bool, error) {
	return m.blacklist[token], nil
}

func (m *MockAuthService) HasPermission(ctx context.Context, userID uuid.UUID, resource, action string) (bool, error) {
	key := userID.String() + ":" + resource + ":" + action
	return m.permissions[key], nil
}

// 测试辅助方法
func (m *MockAuthService) AddUser(token string, user *models.User) {
	m.users[token] = user
}

func (m *MockAuthService) BlacklistToken(token string) {
	m.blacklist[token] = true
}

func (m *MockAuthService) GrantPermission(userID uuid.UUID, resource, action string) {
	key := userID.String() + ":" + resource + ":" + action
	m.permissions[key] = true
}

// 测试设置
func setupMiddlewareTest() (*gin.Engine, *MockAuthService) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	
	mockAuth := NewMockAuthService()
	logger := zap.NewNop()
	authMiddleware := NewAuthMiddleware(mockAuth, logger)
	
	// 测试路由
	protected := router.Group("/protected")
	protected.Use(authMiddleware.RequireAuth())
	{
		protected.GET("/profile", func(c *gin.Context) {
			user, _ := GetUserFromGin(c)
			c.JSON(http.StatusOK, gin.H{"user_id": user.ID})
		})
	}
	
	admin := router.Group("/admin")
	admin.Use(authMiddleware.RequireAuth())
	admin.Use(authMiddleware.RequireRole(models.UserRoleAdmin))
	{
		admin.GET("/users", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "admin only"})
		})
	}
	
	permission := router.Group("/permission")
	permission.Use(authMiddleware.RequireAuth())
	permission.Use(authMiddleware.RequirePermission("users", "read"))
	{
		permission.GET("/data", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "permission granted"})
		})
	}
	
	return router, mockAuth
}

// 🧪 清洁的测试用例

func TestAuth_NoToken(t *testing.T) {
	router, _ := setupMiddlewareTest()
	
	req, _ := http.NewRequest("GET", "/protected/profile", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	
	var response models.APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, 40101, response.Code)
}

func TestAuth_InvalidToken(t *testing.T) {
	router, _ := setupMiddlewareTest()
	
	req, _ := http.NewRequest("GET", "/protected/profile", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuth_ValidToken(t *testing.T) {
	router, mockAuth := setupMiddlewareTest()
	
	// 设置测试数据 - 简单直接！
	userID := uuid.New()
	user := &models.User{
		ID:     userID,
		Email:  "test@example.com",
		Status: models.UserStatusActive,
	}
	mockAuth.AddUser("valid-token", user)
	
	req, _ := http.NewRequest("GET", "/protected/profile", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusOK, w.Code)
	
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, userID.String(), response["user_id"])
}

func TestAuth_BlacklistedToken(t *testing.T) {
	router, mockAuth := setupMiddlewareTest()
	
	userID := uuid.New()
	user := &models.User{
		ID:     userID,
		Email:  "test@example.com",
		Status: models.UserStatusActive,
	}
	mockAuth.AddUser("blacklisted-token", user)
	mockAuth.BlacklistToken("blacklisted-token")  // 加入黑名单
	
	req, _ := http.NewRequest("GET", "/protected/profile", nil)
	req.Header.Set("Authorization", "Bearer blacklisted-token")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	
	var response models.APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, 40103, response.Code)
}

func TestAuth_AdminRole(t *testing.T) {
	router, mockAuth := setupMiddlewareTest()
	
	// 创建管理员用户
	adminID := uuid.New()
	admin := &models.User{
		ID:          adminID,
		Email:       "admin@example.com",
		Status:      models.UserStatusActive,
		DefaultRole: models.UserRoleAdmin,
	}
	mockAuth.AddUser("admin-token", admin)
	
	req, _ := http.NewRequest("GET", "/admin/users", nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusOK, w.Code)
	
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "admin only", response["message"])
}

func TestAuth_RegularUserForbidden(t *testing.T) {
	router, mockAuth := setupMiddlewareTest()
	
	// 创建普通用户
	userID := uuid.New()
	user := &models.User{
		ID:          userID,
		Email:       "user@example.com",
		Status:      models.UserStatusActive,
		DefaultRole: models.UserRoleRegular,
	}
	mockAuth.AddUser("user-token", user)
	
	req, _ := http.NewRequest("GET", "/admin/users", nil)
	req.Header.Set("Authorization", "Bearer user-token")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestAuth_Permission_Granted(t *testing.T) {
	router, mockAuth := setupMiddlewareTest()
	
	userID := uuid.New()
	user := &models.User{
		ID:     userID,
		Email:  "user@example.com",
		Status: models.UserStatusActive,
	}
	mockAuth.AddUser("user-token", user)
	mockAuth.GrantPermission(userID, "users", "read")  // 授予权限
	
	req, _ := http.NewRequest("GET", "/permission/data", nil)
	req.Header.Set("Authorization", "Bearer user-token")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusOK, w.Code)
	
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "permission granted", response["message"])
}

func TestAuth_Permission_Denied(t *testing.T) {
	router, mockAuth := setupMiddlewareTest()
	
	userID := uuid.New()
	user := &models.User{
		ID:     userID,
		Email:  "user@example.com",
		Status: models.UserStatusActive,
	}
	mockAuth.AddUser("user-token", user)
	// 不授予权限
	
	req, _ := http.NewRequest("GET", "/permission/data", nil)
	req.Header.Set("Authorization", "Bearer user-token")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusForbidden, w.Code)
}