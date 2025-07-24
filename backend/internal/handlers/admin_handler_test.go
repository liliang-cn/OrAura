package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/OrAura/backend/internal/models"
	"github.com/OrAura/backend/internal/services"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

// stringPtr returns a pointer to the given string
func stringPtr(s string) *string {
	return &s
}

// 🎯 简洁的AdminService Mock - 只实现6个方法！
type MockAdminService struct {
	users     map[uuid.UUID]*models.User
	loginLogs []models.UserLoginLog
}

func NewMockAdminService() *MockAdminService {
	return &MockAdminService{
		users:     make(map[uuid.UUID]*models.User),
		loginLogs: make([]models.UserLoginLog, 0),
	}
}

func (m *MockAdminService) ListUsers(ctx context.Context, query *models.UserListQuery) (*models.PaginatedResponse, error) {
	users := make([]*models.User, 0)
	for _, user := range m.users {
		users = append(users, user)
	}
	
	return &models.PaginatedResponse{
		Data: users,
		Pagination: &models.Pagination{
			Page:       1,
			PageSize:   10,
			Total:      int64(len(users)),
			TotalPages: 1,
		},
	}, nil
}

func (m *MockAdminService) GetUserByID(ctx context.Context, userID uuid.UUID) (*models.User, error) {
	if user, exists := m.users[userID]; exists {
		return user, nil
	}
	return nil, services.ErrUserNotFound  // 返回正确的服务错误
}

func (m *MockAdminService) UpdateUserStatus(ctx context.Context, userID uuid.UUID, req *models.UpdateUserStatusRequest) error {
	if user, exists := m.users[userID]; exists {
		user.Status = req.Status
		if req.Reason != nil {
			// 模拟更新原因逻辑
		}
		return nil
	}
	return errors.New("user not found")
}

func (m *MockAdminService) GetUserLoginLogs(ctx context.Context, query *models.LoginLogQuery) (*models.PaginatedResponse, error) {
	return &models.PaginatedResponse{
		Data: m.loginLogs,
		Pagination: &models.Pagination{
			Page:       1,
			PageSize:   10,
			Total:      int64(len(m.loginLogs)),
			TotalPages: 1,
		},
	}, nil
}

func (m *MockAdminService) AssignRole(ctx context.Context, userID, roleID uuid.UUID, grantedBy uuid.UUID, expiresAt *time.Time) error {
	if _, exists := m.users[userID]; exists {
		// 模拟角色分配逻辑
		return nil
	}
	return errors.New("user not found")
}

func (m *MockAdminService) RevokeRole(ctx context.Context, userID, roleID uuid.UUID) error {
	if _, exists := m.users[userID]; exists {
		// 模拟角色撤销逻辑
		return nil
	}
	return errors.New("user not found")
}

// 测试辅助方法
func (m *MockAdminService) AddUser(user *models.User) {
	m.users[user.ID] = user
}

func (m *MockAdminService) AddLoginLog(log models.UserLoginLog) {
	m.loginLogs = append(m.loginLogs, log)
}

func setupAdminHandlerTest() (*gin.Engine, *MockAdminService) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	mockAdmin := NewMockAdminService()
	validator := validator.New()
	logger := zap.NewNop()
	
	adminHandler := NewAdminHandler(mockAdmin, validator, logger)

	admin := router.Group("/admin")
	{
		admin.GET("/stats", adminHandler.GetDashboardStats)
		admin.GET("/users", adminHandler.ListUsers)
		admin.GET("/users/:user_id", adminHandler.GetUser)  // 使用正确的参数名
		admin.GET("/login-logs", adminHandler.GetLoginLogs)
	}

	return router, mockAdmin
}

// 测试简单的GET请求，不需要复杂的参数解析

func TestAdminHandler_GetDashboardStats(t *testing.T) {
	router, _ := setupAdminHandlerTest()

	req, _ := http.NewRequest("GET", "/admin/stats", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response models.APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.Code)
}

func TestAdminHandler_ListUsers(t *testing.T) {
	router, mockAdmin := setupAdminHandlerTest()

	// 添加测试用户
	user := &models.User{
		ID:     uuid.New(),
		Email:  "test@example.com",
		Status: models.UserStatusActive,
	}
	mockAdmin.AddUser(user)

	req, _ := http.NewRequest("GET", "/admin/users", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response models.APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.Code)
}

func TestAdminHandler_GetUser_Success(t *testing.T) {
	router, mockAdmin := setupAdminHandlerTest()

	// 添加测试用户
	userID := uuid.New()
	user := &models.User{
		ID:     userID,
		Email:  "test@example.com",
		Status: models.UserStatusActive,
	}
	mockAdmin.AddUser(user)

	req, _ := http.NewRequest("GET", "/admin/users/"+userID.String(), nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response models.APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.Code)
}

func TestAdminHandler_GetUser_NotFound(t *testing.T) {
	router, _ := setupAdminHandlerTest()

	nonExistentID := uuid.New()
	req, _ := http.NewRequest("GET", "/admin/users/"+nonExistentID.String(), nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestAdminHandler_GetLoginLogs(t *testing.T) {
	router, mockAdmin := setupAdminHandlerTest()

	// 添加测试登录日志
	log := models.UserLoginLog{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		LoginType: models.LoginTypePassword,
		IPAddress: stringPtr("192.168.1.1"),
		UserAgent: stringPtr("Test Agent"),
		Success:   true,
		CreatedAt: time.Now(),
	}
	mockAdmin.AddLoginLog(log)

	req, _ := http.NewRequest("GET", "/admin/login-logs", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response models.APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err) 
	assert.Equal(t, 200, response.Code)
}