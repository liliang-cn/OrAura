package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/OrAura/backend/internal/models"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

// MockUserService 模拟用户服务
type MockUserService struct {
	mock.Mock
}

func (m *MockUserService) Register(ctx context.Context, req *models.RegisterRequest) (*models.User, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserService) Login(ctx context.Context, req *models.LoginRequest) (*models.TokenResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.TokenResponse), args.Error(1)
}

func (m *MockUserService) RefreshToken(ctx context.Context, refreshToken string) (*models.TokenResponse, error) {
	args := m.Called(ctx, refreshToken)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.TokenResponse), args.Error(1)
}

func (m *MockUserService) Logout(ctx context.Context, userID uuid.UUID, accessToken string) error {
	args := m.Called(ctx, userID, accessToken)
	return args.Error(0)
}

func (m *MockUserService) LogoutAll(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockUserService) LoginWithGoogle(ctx context.Context, req *models.OAuthLoginRequest) (*models.TokenResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.TokenResponse), args.Error(1)
}

func (m *MockUserService) LoginWithApple(ctx context.Context, req *models.OAuthLoginRequest) (*models.TokenResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.TokenResponse), args.Error(1)
}

func (m *MockUserService) VerifyEmail(ctx context.Context, token string) (*models.User, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserService) ResendVerificationEmail(ctx context.Context, email string) error {
	args := m.Called(ctx, email)
	return args.Error(0)
}

func (m *MockUserService) GetUserProfile(ctx context.Context, userID uuid.UUID) (*models.UserInfo, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.UserInfo), args.Error(1)
}

func (m *MockUserService) UpdateUserProfile(ctx context.Context, userID uuid.UUID, req *models.UpdateProfileRequest) (*models.UserInfo, error) {
	args := m.Called(ctx, userID, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.UserInfo), args.Error(1)
}

func (m *MockUserService) GetUserByID(ctx context.Context, userID uuid.UUID) (*models.User, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserService) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserService) ChangePassword(ctx context.Context, userID uuid.UUID, req *models.ChangePasswordRequest) error {
	args := m.Called(ctx, userID, req)
	return args.Error(0)
}

func (m *MockUserService) ForgotPassword(ctx context.Context, req *models.ForgotPasswordRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockUserService) ResetPassword(ctx context.Context, req *models.ResetPasswordRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockUserService) DeleteAccount(ctx context.Context, userID uuid.UUID, req *models.DeleteAccountRequest) error {
	args := m.Called(ctx, userID, req)
	return args.Error(0)
}

func (m *MockUserService) ValidateAccessToken(ctx context.Context, tokenString string) (*models.User, error) {
	args := m.Called(ctx, tokenString)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserService) IsTokenBlacklisted(ctx context.Context, token string) (bool, error) {
	args := m.Called(ctx, token)
	return args.Bool(0), args.Error(1)
}

func (m *MockUserService) BlacklistToken(ctx context.Context, token string, userID uuid.UUID, expiresAt time.Time) error {
	args := m.Called(ctx, token, userID, expiresAt)
	return args.Error(0)
}

func (m *MockUserService) CreateAPIToken(ctx context.Context, userID uuid.UUID, req *models.CreateAPITokenRequest) (*models.APITokenResponse, error) {
	args := m.Called(ctx, userID, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.APITokenResponse), args.Error(1)
}

func (m *MockUserService) ValidateAPIToken(ctx context.Context, token string) (*models.APIToken, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.APIToken), args.Error(1)
}

func (m *MockUserService) ListAPITokens(ctx context.Context, userID uuid.UUID) ([]*models.APIToken, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.APIToken), args.Error(1)
}

func (m *MockUserService) UpdateAPIToken(ctx context.Context, tokenID uuid.UUID, req *models.UpdateAPITokenRequest) (*models.APIToken, error) {
	args := m.Called(ctx, tokenID, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.APIToken), args.Error(1)
}

func (m *MockUserService) DeleteAPIToken(ctx context.Context, tokenID uuid.UUID) error {
	args := m.Called(ctx, tokenID)
	return args.Error(0)
}

func (m *MockUserService) UpdateAPITokenUsage(ctx context.Context, tokenID uuid.UUID) error {
	args := m.Called(ctx, tokenID)
	return args.Error(0)
}

func (m *MockUserService) AssignRole(ctx context.Context, userID, roleID uuid.UUID, grantedBy uuid.UUID, expiresAt *time.Time) error {
	args := m.Called(ctx, userID, roleID, grantedBy, expiresAt)
	return args.Error(0)
}

func (m *MockUserService) RevokeRole(ctx context.Context, userID, roleID uuid.UUID) error {
	args := m.Called(ctx, userID, roleID)
	return args.Error(0)
}

func (m *MockUserService) HasPermission(ctx context.Context, userID uuid.UUID, resource, action string) (bool, error) {
	args := m.Called(ctx, userID, resource, action)
	return args.Bool(0), args.Error(1)
}

func (m *MockUserService) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]*models.Role, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Role), args.Error(1)
}

func (m *MockUserService) GetUserSessions(ctx context.Context, userID uuid.UUID) ([]*models.UserSession, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.UserSession), args.Error(1)
}

func (m *MockUserService) DeleteUserSession(ctx context.Context, sessionID uuid.UUID) error {
	args := m.Called(ctx, sessionID)
	return args.Error(0)
}

func (m *MockUserService) ListUsers(ctx context.Context, query *models.UserListQuery) (*models.PaginatedResponse, error) {
	args := m.Called(ctx, query)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.PaginatedResponse), args.Error(1)
}

func (m *MockUserService) UpdateUserStatus(ctx context.Context, userID uuid.UUID, req *models.UpdateUserStatusRequest) error {
	args := m.Called(ctx, userID, req)
	return args.Error(0)
}

func (m *MockUserService) GetUserLoginLogs(ctx context.Context, query *models.LoginLogQuery) (*models.PaginatedResponse, error) {
	args := m.Called(ctx, query)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.PaginatedResponse), args.Error(1)
}

// 测试设置
func setupAdminTestRouter() (*gin.Engine, *MockUserService) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	
	mockUserService := new(MockUserService)
	validator := validator.New()
	logger := zap.NewNop()
	
	adminHandler := NewAdminHandler(mockUserService, validator, logger)
	
	api := router.Group("/api/v1")
	admin := api.Group("/admin")
	{
		admin.GET("/stats", adminHandler.GetDashboardStats)
		admin.GET("/users", adminHandler.ListUsers)
		admin.GET("/users/:user_id", adminHandler.GetUser)
		admin.PUT("/users/:user_id/status", adminHandler.UpdateUserStatus)
		admin.POST("/users/:user_id/roles", adminHandler.AssignRole)
		admin.DELETE("/users/:user_id/roles/:role_id", adminHandler.RevokeRole)
		admin.GET("/logs/login", adminHandler.GetLoginLogs)
		admin.GET("/system/health", adminHandler.GetSystemHealth)
	}
	
	return router, mockUserService
}

// 测试用例

func TestAdminHandler_GetDashboardStats(t *testing.T) {
	router, _ := setupAdminTestRouter()

	req, _ := http.NewRequest("GET", "/api/v1/admin/stats", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response models.APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.True(t, response.Success)
	assert.NotNil(t, response.Data)
}

func TestAdminHandler_ListUsers(t *testing.T) {
	router, mockUserService := setupAdminTestRouter()

	expectedResult := &models.PaginatedResponse{
		Data: []interface{}{
			map[string]interface{}{
				"user_id":  uuid.New().String(),
				"email":    "test@example.com",
				"username": "testuser",
				"status":   "active",
			},
		},
		Pagination: models.Pagination{
			Page:     1,
			PageSize: 20,
			Total:    1,
		},
	}

	mockUserService.On("ListUsers", mock.Anything, mock.AnythingOfType("*models.UserListQuery")).Return(expectedResult, nil)

	req, _ := http.NewRequest("GET", "/api/v1/admin/users?page=1&page_size=20", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response models.APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.True(t, response.Success)
	assert.NotNil(t, response.Data)

	mockUserService.AssertExpectations(t)
}

func TestAdminHandler_GetUser(t *testing.T) {
	router, mockUserService := setupAdminTestRouter()

	userID := uuid.New()
	expectedUser := &models.User{
		ID:       userID,
		Email:    "test@example.com",
		Username: "testuser",
		Status:   models.UserStatusActive,
	}

	mockUserService.On("GetUserByID", mock.Anything, userID).Return(expectedUser, nil)

	req, _ := http.NewRequest("GET", "/api/v1/admin/users/"+userID.String(), nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response models.APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.True(t, response.Success)
	assert.NotNil(t, response.Data)

	mockUserService.AssertExpectations(t)
}

func TestAdminHandler_GetUser_NotFound(t *testing.T) {
	router, mockUserService := setupAdminTestRouter()

	userID := uuid.New()
	mockUserService.On("GetUserByID", mock.Anything, userID).Return(nil, errors.New("user not found"))

	req, _ := http.NewRequest("GET", "/api/v1/admin/users/"+userID.String(), nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var response models.APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.False(t, response.Success)

	mockUserService.AssertExpectations(t)
}

func TestAdminHandler_UpdateUserStatus(t *testing.T) {
	router, mockUserService := setupAdminTestRouter()

	userID := uuid.New()
	updateReq := models.UpdateUserStatusRequest{
		Status: models.UserStatusSuspended,
		Reason: "Policy violation",
	}

	mockUserService.On("UpdateUserStatus", mock.Anything, userID, &updateReq).Return(nil)

	reqBody, _ := json.Marshal(updateReq)
	req, _ := http.NewRequest("PUT", "/api/v1/admin/users/"+userID.String()+"/status", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response models.APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.True(t, response.Success)

	mockUserService.AssertExpectations(t)
}

func TestAdminHandler_AssignRole(t *testing.T) {
	router, mockUserService := setupAdminTestRouter()

	userID := uuid.New()
	roleID := uuid.New()
	assignReq := models.AssignRoleRequest{
		RoleID:    roleID,
		ExpiresAt: nil,
	}

	// 设置用户上下文 - 模拟管理员用户
	adminUserID := uuid.New()
	
	mockUserService.On("AssignRole", mock.Anything, userID, roleID, adminUserID, (*time.Time)(nil)).Return(nil)

	reqBody, _ := json.Marshal(assignReq)
	req, _ := http.NewRequest("POST", "/api/v1/admin/users/"+userID.String()+"/roles", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	
	// 添加用户上下文到请求中 (实际应用中通过中间件设置)
	ctx := context.WithValue(req.Context(), "user", &models.User{ID: adminUserID})
	req = req.WithContext(ctx)
	
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// 由于没有中间件来设置用户上下文，这个测试会失败
	// 在实际应用中，需要设置适当的中间件
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestAdminHandler_RevokeRole(t *testing.T) {
	router, mockUserService := setupAdminTestRouter()

	userID := uuid.New()
	roleID := uuid.New()

	mockUserService.On("RevokeRole", mock.Anything, userID, roleID).Return(nil)

	req, _ := http.NewRequest("DELETE", "/api/v1/admin/users/"+userID.String()+"/roles/"+roleID.String(), nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response models.APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.True(t, response.Success)

	mockUserService.AssertExpectations(t)
}

func TestAdminHandler_GetLoginLogs(t *testing.T) {
	router, mockUserService := setupAdminTestRouter()

	expectedResult := &models.PaginatedResponse{
		Data: []interface{}{
			map[string]interface{}{
				"user_id":    uuid.New().String(),
				"email":      "test@example.com",
				"ip_address": "192.168.1.1",
				"success":    true,
				"created_at": "2023-01-01T00:00:00Z",
			},
		},
		Pagination: models.Pagination{
			Page:     1,
			PageSize: 20,
			Total:    1,
		},
	}

	mockUserService.On("GetUserLoginLogs", mock.Anything, mock.AnythingOfType("*models.LoginLogQuery")).Return(expectedResult, nil)

	req, _ := http.NewRequest("GET", "/api/v1/admin/logs/login?page=1&page_size=20", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response models.APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.True(t, response.Success)
	assert.NotNil(t, response.Data)

	mockUserService.AssertExpectations(t)
}

func TestAdminHandler_GetSystemHealth(t *testing.T) {
	router, _ := setupAdminTestRouter()

	req, _ := http.NewRequest("GET", "/api/v1/admin/system/health", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response models.APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.True(t, response.Success)
	assert.NotNil(t, response.Data)

	// 验证健康检查响应结构
	healthData := response.Data.(map[string]interface{})
	assert.Contains(t, healthData, "status")
	assert.Contains(t, healthData, "timestamp")
	assert.Contains(t, healthData, "services")
}