package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

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

// 测试辅助函数

func setupTestRouter(userHandler *UserHandler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	
	v1 := r.Group("/api/v1")
	{
		auth := v1.Group("/auth")
		{
			auth.POST("/register", userHandler.Register)
			auth.POST("/login", userHandler.Login)
			auth.POST("/refresh", userHandler.RefreshToken)
		}
	}
	
	return r
}

// 测试用例

func TestUserHandler_Register_Success(t *testing.T) {
	mockService := new(MockUserService)
	validator := validator.New()
	logger := zap.NewNop()
	handler := NewUserHandler(mockService, validator, logger)

	// 准备测试数据
	req := models.RegisterRequest{
		Email:    "test@example.com",
		Username: "testuser",
		Password: "password123",
		Timezone: "UTC",
	}

	user := &models.User{
		ID:       uuid.New(),
		Email:    req.Email,
		Username: req.Username,
		Status:   models.UserStatusActive,
	}

	// Mock 服务调用
	mockService.On("Register", mock.Anything, &req).Return(user, nil)

	// 设置路由
	router := setupTestRouter(handler)

	// 准备请求
	reqBody, _ := json.Marshal(req)
	w := httptest.NewRecorder()
	request, _ := http.NewRequest("POST", "/api/v1/auth/register", bytes.NewBuffer(reqBody))
	request.Header.Set("Content-Type", "application/json")

	// 执行请求
	router.ServeHTTP(w, request)

	// 验证响应
	assert.Equal(t, http.StatusCreated, w.Code)
	
	var response models.APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.Code)
	assert.Equal(t, "Registration successful", response.Message)
	assert.NotNil(t, response.Data)

	mockService.AssertExpectations(t)
}

func TestUserHandler_Register_ValidationError(t *testing.T) {
	mockService := new(MockUserService)
	validator := validator.New()
	logger := zap.NewNop()
	handler := NewUserHandler(mockService, validator, logger)

	// 准备无效的测试数据（缺少必需字段）
	req := models.RegisterRequest{
		Email: "invalid-email", // 无效邮箱格式
		// 缺少 Username, Password, Timezone
	}

	// 设置路由
	router := setupTestRouter(handler)

	// 准备请求
	reqBody, _ := json.Marshal(req)
	w := httptest.NewRecorder()
	request, _ := http.NewRequest("POST", "/api/v1/auth/register", bytes.NewBuffer(reqBody))
	request.Header.Set("Content-Type", "application/json")

	// 执行请求
	router.ServeHTTP(w, request)

	// 验证响应
	assert.Equal(t, http.StatusBadRequest, w.Code)
	
	var response models.APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, 40002, response.Code)
	assert.Equal(t, "Validation failed", response.Message)
	assert.NotEmpty(t, response.Errors)

	// 不应该调用服务层
	mockService.AssertNotCalled(t, "Register")
}

func TestUserHandler_Login_Success(t *testing.T) {
	mockService := new(MockUserService)
	validator := validator.New()
	logger := zap.NewNop()
	handler := NewUserHandler(mockService, validator, logger)

	// 准备测试数据
	req := models.LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}

	tokenResponse := &models.TokenResponse{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		User: &models.UserInfo{
			UserID:   uuid.New(),
			Email:    req.Email,
			Username: "testuser",
		},
	}

	// Mock 服务调用
	mockService.On("Login", mock.Anything, &req).Return(tokenResponse, nil)

	// 设置路由
	router := setupTestRouter(handler)

	// 准备请求
	reqBody, _ := json.Marshal(req)
	w := httptest.NewRecorder()
	request, _ := http.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(reqBody))
	request.Header.Set("Content-Type", "application/json")

	// 执行请求
	router.ServeHTTP(w, request)

	// 验证响应
	assert.Equal(t, http.StatusOK, w.Code)
	
	var response models.APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.Code)
	assert.Equal(t, "Login successful", response.Message)
	assert.NotNil(t, response.Data)

	// 验证返回的令牌数据
	dataBytes, _ := json.Marshal(response.Data)
	var returnedTokenResponse models.TokenResponse
	json.Unmarshal(dataBytes, &returnedTokenResponse)
	assert.Equal(t, tokenResponse.AccessToken, returnedTokenResponse.AccessToken)
	assert.Equal(t, tokenResponse.RefreshToken, returnedTokenResponse.RefreshToken)

	mockService.AssertExpectations(t)
}

func TestUserHandler_RefreshToken_Success(t *testing.T) {
	mockService := new(MockUserService)
	validator := validator.New()
	logger := zap.NewNop()
	handler := NewUserHandler(mockService, validator, logger)

	// 准备测试数据
	req := models.RefreshTokenRequest{
		RefreshToken: "refresh-token",
	}

	tokenResponse := &models.TokenResponse{
		AccessToken:  "new-access-token",
		RefreshToken: "refresh-token",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
	}

	// Mock 服务调用
	mockService.On("RefreshToken", mock.Anything, req.RefreshToken).Return(tokenResponse, nil)

	// 设置路由
	router := setupTestRouter(handler)

	// 准备请求
	reqBody, _ := json.Marshal(req)
	w := httptest.NewRecorder()
	request, _ := http.NewRequest("POST", "/api/v1/auth/refresh", bytes.NewBuffer(reqBody))
	request.Header.Set("Content-Type", "application/json")

	// 执行请求
	router.ServeHTTP(w, request)

	// 验证响应
	assert.Equal(t, http.StatusOK, w.Code)
	
	var response models.APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.Code)
	assert.Equal(t, "Token refreshed successfully", response.Message)

	mockService.AssertExpectations(t)
}