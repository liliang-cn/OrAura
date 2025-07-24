package middleware

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/OrAura/backend/internal/models"
	"github.com/OrAura/backend/internal/utils"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

// MockUserService 模拟用户服务
type MockUserService struct {
	mock.Mock
}

func (m *MockUserService) ValidateAccessToken(tokenString string) (*models.User, error) {
	args := m.Called(tokenString)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserService) IsTokenBlacklisted(token string) (bool, error) {
	args := m.Called(token)
	return args.Bool(0), args.Error(1)
}

func (m *MockUserService) HasPermission(userID uuid.UUID, resource, action string) (bool, error) {
	args := m.Called(userID, resource, action)
	return args.Bool(0), args.Error(1)
}

// 测试设置
func setupTestRouter() (*gin.Engine, *MockUserService) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	
	mockUserService := new(MockUserService)
	jwtManager := utils.NewJWTManager("test-secret", time.Hour, 24*time.Hour)
	logger := zap.NewNop()
	
	authMiddleware := NewAuthMiddleware(mockUserService, jwtManager, logger)
	
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
	
	member := router.Group("/member")
	member.Use(authMiddleware.RequireAuth())
	member.Use(authMiddleware.RequireMember())
	{
		member.GET("/features", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "member features"})
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
	
	return router, mockUserService
}

func TestAuthMiddleware_RequireAuth_Success(t *testing.T) {
	router, mockUserService := setupTestRouter()
	
	userID := uuid.New()
	user := &models.User{
		ID:     userID,
		Email:  "test@example.com",
		Status: models.UserStatusActive,
	}
	
	// 创建有效的JWT令牌
	jwtManager := utils.NewJWTManager("test-secret", time.Hour, 24*time.Hour)
	token, err := jwtManager.GenerateToken(userID, user.Email)
	assert.NoError(t, err)
	
	// Mock服务调用
	mockUserService.On("ValidateAccessToken", token).Return(user, nil)
	mockUserService.On("IsTokenBlacklisted", mock.AnythingOfType("string")).Return(false, nil)
	
	req, _ := http.NewRequest("GET", "/protected/profile", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusOK, w.Code)
	
	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, userID.String(), response["user_id"])
	
	mockUserService.AssertExpectations(t)
}

func TestAuthMiddleware_RequireAuth_NoToken(t *testing.T) {
	router, _ := setupTestRouter()
	
	req, _ := http.NewRequest("GET", "/protected/profile", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	
	var response models.APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.False(t, response.Success)
	assert.Equal(t, 40101, response.Code)
}

func TestAuthMiddleware_RequireAuth_InvalidToken(t *testing.T) {
	router, mockUserService := setupTestRouter()
	
	// 使用无效的令牌
	invalidToken := "invalid.jwt.token"
	
	mockUserService.On("ValidateAccessToken", invalidToken).Return(nil, errors.New("invalid token"))
	
	req, _ := http.NewRequest("GET", "/protected/profile", nil)
	req.Header.Set("Authorization", "Bearer "+invalidToken)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	
	var response models.APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.False(t, response.Success)
	
	mockUserService.AssertExpectations(t)
}

func TestAuthMiddleware_RequireAuth_BlacklistedToken(t *testing.T) {
	router, mockUserService := setupTestRouter()
	
	userID := uuid.New()
	user := &models.User{
		ID:     userID,
		Email:  "test@example.com",
		Status: models.UserStatusActive,
	}
	
	// 创建有效的JWT令牌
	jwtManager := utils.NewJWTManager("test-secret", time.Hour, 24*time.Hour)
	token, err := jwtManager.GenerateToken(userID, user.Email)
	assert.NoError(t, err)
	
	// Mock服务调用 - 令牌被加入黑名单
	mockUserService.On("ValidateAccessToken", token).Return(user, nil)
	mockUserService.On("IsTokenBlacklisted", mock.AnythingOfType("string")).Return(true, nil)
	
	req, _ := http.NewRequest("GET", "/protected/profile", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	
	var response models.APIResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.False(t, response.Success)
	assert.Equal(t, 40103, response.Code)
	
	mockUserService.AssertExpectations(t)
}

func TestAuthMiddleware_RequireRole_Success(t *testing.T) {
	router, mockUserService := setupTestRouter()
	
	userID := uuid.New()
	// 创建管理员用户
	user := &models.User{
		ID:     userID,
		Email:  "admin@example.com",
		Status: models.UserStatusActive,
		Roles: []*models.UserRoleAssignment{
			{
				UserID: userID,
				Role: &models.Role{
					ID:   uuid.New(),
					Name: "admin",
				},
				IsActive: true,
			},
		},
	}
	
	// 创建有效的JWT令牌
	jwtManager := utils.NewJWTManager("test-secret", time.Hour, 24*time.Hour)
	token, err := jwtManager.GenerateToken(userID, user.Email)
	assert.NoError(t, err)
	
	// Mock服务调用
	mockUserService.On("ValidateAccessToken", token).Return(user, nil)
	mockUserService.On("IsTokenBlacklisted", mock.AnythingOfType("string")).Return(false, nil)
	
	req, _ := http.NewRequest("GET", "/admin/users", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusOK, w.Code)
	
	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "admin only", response["message"])
	
	mockUserService.AssertExpectations(t)
}

func TestAuthMiddleware_RequireRole_Forbidden(t *testing.T) {
	router, mockUserService := setupTestRouter()
	
	userID := uuid.New()
	// 创建普通用户
	user := &models.User{
		ID:     userID,
		Email:  "user@example.com",
		Status: models.UserStatusActive,
		Roles:  []*models.UserRoleAssignment{}, // 没有管理员角色
	}
	
	// 创建有效的JWT令牌
	jwtManager := utils.NewJWTManager("test-secret", time.Hour, 24*time.Hour)
	token, err := jwtManager.GenerateToken(userID, user.Email)
	assert.NoError(t, err)
	
	// Mock服务调用
	mockUserService.On("ValidateAccessToken", token).Return(user, nil)
	mockUserService.On("IsTokenBlacklisted", mock.AnythingOfType("string")).Return(false, nil)
	
	req, _ := http.NewRequest("GET", "/admin/users", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusForbidden, w.Code)
	
	var response models.APIResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.False(t, response.Success)
	assert.Equal(t, 40301, response.Code)
	
	mockUserService.AssertExpectations(t)
}

func TestAuthMiddleware_RequireMember_Success(t *testing.T) {
	router, mockUserService := setupTestRouter()
	
	userID := uuid.New()
	// 创建会员用户
	user := &models.User{
		ID:     userID,
		Email:  "member@example.com",
		Status: models.UserStatusActive,
		Roles: []*models.UserRoleAssignment{
			{
				UserID: userID,
				Role: &models.Role{
					ID:   uuid.New(),
					Name: "member",
				},
				IsActive: true,
			},
		},
	}
	
	// 创建有效的JWT令牌
	jwtManager := utils.NewJWTManager("test-secret", time.Hour, 24*time.Hour)
	token, err := jwtManager.GenerateToken(userID, user.Email)
	assert.NoError(t, err)
	
	// Mock服务调用
	mockUserService.On("ValidateAccessToken", token).Return(user, nil)
	mockUserService.On("IsTokenBlacklisted", mock.AnythingOfType("string")).Return(false, nil)
	
	req, _ := http.NewRequest("GET", "/member/features", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusOK, w.Code)
	
	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "member features", response["message"])
	
	mockUserService.AssertExpectations(t)
}

func TestAuthMiddleware_RequirePermission_Success(t *testing.T) {
	router, mockUserService := setupTestRouter()
	
	userID := uuid.New()
	user := &models.User{
		ID:     userID,
		Email:  "user@example.com",
		Status: models.UserStatusActive,
	}
	
	// 创建有效的JWT令牌
	jwtManager := utils.NewJWTManager("test-secret", time.Hour, 24*time.Hour)
	token, err := jwtManager.GenerateToken(userID, user.Email)
	assert.NoError(t, err)
	
	// Mock服务调用
	mockUserService.On("ValidateAccessToken", token).Return(user, nil)
	mockUserService.On("IsTokenBlacklisted", mock.AnythingOfType("string")).Return(false, nil)
	mockUserService.On("HasPermission", userID, "users", "read").Return(true, nil)
	
	req, _ := http.NewRequest("GET", "/permission/data", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusOK, w.Code)
	
	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "permission granted", response["message"])
	
	mockUserService.AssertExpectations(t)
}

func TestAuthMiddleware_RequirePermission_Forbidden(t *testing.T) {
	router, mockUserService := setupTestRouter()
	
	userID := uuid.New()
	user := &models.User{
		ID:     userID,
		Email:  "user@example.com",
		Status: models.UserStatusActive,
	}
	
	// 创建有效的JWT令牌
	jwtManager := utils.NewJWTManager("test-secret", time.Hour, 24*time.Hour)
	token, err := jwtManager.GenerateToken(userID, user.Email)
	assert.NoError(t, err)
	
	// Mock服务调用
	mockUserService.On("ValidateAccessToken", token).Return(user, nil)
	mockUserService.On("IsTokenBlacklisted", mock.AnythingOfType("string")).Return(false, nil)
	mockUserService.On("HasPermission", userID, "users", "read").Return(false, nil)
	
	req, _ := http.NewRequest("GET", "/permission/data", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusForbidden, w.Code)
	
	var response models.APIResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.False(t, response.Success)
	assert.Equal(t, 40302, response.Code)
	
	mockUserService.AssertExpectations(t)
}

func TestGetUserFromGin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	
	userID := uuid.New()
	user := &models.User{
		ID:    userID,
		Email: "test@example.com",
	}
	
	// 测试设置用户到context
	c.Set("user", user)
	
	retrievedUser, exists := GetUserFromGin(c)
	assert.True(t, exists)
	assert.NotNil(t, retrievedUser)
	assert.Equal(t, user.ID, retrievedUser.ID)
	assert.Equal(t, user.Email, retrievedUser.Email)
	
	// 测试context中没有用户
	c.Set("user", nil)
	retrievedUser, exists = GetUserFromGin(c)
	assert.False(t, exists)
	assert.Nil(t, retrievedUser)
}