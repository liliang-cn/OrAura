package handlers

import (
	"net/http"
	"time"

	"github.com/OrAura/backend/internal/middleware"
	"github.com/OrAura/backend/internal/models"
	"github.com/OrAura/backend/internal/services"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// AdminHandler 管理员处理器
type AdminHandler struct {
	adminService services.AdminService  // 只依赖AdminService接口！
	validator    *validator.Validate
	logger       *zap.Logger
}

// NewAdminHandler 创建管理员处理器
func NewAdminHandler(adminService services.AdminService, validator *validator.Validate, logger *zap.Logger) *AdminHandler {
	return &AdminHandler{
		adminService: adminService,
		validator:    validator,
		logger:       logger,
	}
}

// GetDashboardStats 获取仪表板统计信息
// @Summary 获取管理员仪表板统计信息
// @Description 获取用户数量、活跃用户等统计信息
// @Tags 管理员
// @Security BearerAuth
// @Produce json
// @Success 200 {object} models.APIResponse{data=models.AdminStatsResponse}
// @Failure 401 {object} models.APIResponse
// @Failure 403 {object} models.APIResponse
// @Router /admin/stats [get]
func (h *AdminHandler) GetDashboardStats(c *gin.Context) {
	// TODO: 实现统计信息获取
	stats := &models.AdminStatsResponse{
		TotalUsers:    1000,
		ActiveUsers:   850,
		MemberUsers:   200,
		AdminUsers:    5,
		NewUsersToday: 10,
		NewUsersWeek:  50,
		NewUsersMonth: 200,
	}

	response := models.NewSuccessResponse(stats, "Dashboard stats retrieved successfully")
	c.JSON(http.StatusOK, response)
}

// ListUsers 获取用户列表
// @Summary 获取用户列表
// @Description 管理员查看所有用户列表，支持筛选和分页
// @Tags 管理员
// @Security BearerAuth
// @Param query query models.UserListQuery false "查询参数"
// @Produce json
// @Success 200 {object} models.APIResponse{data=models.PaginatedResponse}
// @Failure 400 {object} models.APIResponse
// @Failure 401 {object} models.APIResponse
// @Failure 403 {object} models.APIResponse
// @Router /admin/users [get]
func (h *AdminHandler) ListUsers(c *gin.Context) {
	var query models.UserListQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		h.respondWithValidationError(c, err)
		return
	}

	result, err := h.adminService.ListUsers(c.Request.Context(), &query)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	response := models.NewSuccessResponse(result, "Users retrieved successfully")
	c.JSON(http.StatusOK, response)
}

// GetUser 获取用户详情
// @Summary 获取用户详情
// @Description 管理员查看用户详细信息
// @Tags 管理员
// @Security BearerAuth
// @Param user_id path string true "用户ID"
// @Produce json
// @Success 200 {object} models.APIResponse{data=models.AdminUserInfo}
// @Failure 400 {object} models.APIResponse
// @Failure 401 {object} models.APIResponse
// @Failure 403 {object} models.APIResponse
// @Failure 404 {object} models.APIResponse
// @Router /admin/users/{user_id} [get]
func (h *AdminHandler) GetUser(c *gin.Context) {
	userIDStr := c.Param("user_id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(c, http.StatusBadRequest, 40001, "Invalid user ID format")
		return
	}

	user, err := h.adminService.GetUserByID(c.Request.Context(), userID)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}
	if user == nil {
		h.respondWithError(c, http.StatusNotFound, 40411, "User not found")
		return
	}

	response := models.NewSuccessResponse(user.ToAdminUserInfo(), "User retrieved successfully")
	c.JSON(http.StatusOK, response)
}

// UpdateUserStatus 更新用户状态
// @Summary 更新用户状态
// @Description 管理员更新用户状态（激活/暂停/删除）
// @Tags 管理员
// @Security BearerAuth
// @Param user_id path string true "用户ID"
// @Param request body models.UpdateUserStatusRequest true "状态更新请求"
// @Accept json
// @Produce json
// @Success 200 {object} models.APIResponse
// @Failure 400 {object} models.APIResponse
// @Failure 401 {object} models.APIResponse
// @Failure 403 {object} models.APIResponse
// @Failure 404 {object} models.APIResponse
// @Router /admin/users/{user_id}/status [put]
func (h *AdminHandler) UpdateUserStatus(c *gin.Context) {
	userIDStr := c.Param("user_id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(c, http.StatusBadRequest, 40001, "Invalid user ID format")
		return
	}

	var req models.UpdateUserStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithValidationError(c, err)
		return
	}

	if err := h.validator.Struct(&req); err != nil {
		h.respondWithValidationError(c, err)
		return
	}

	err = h.adminService.UpdateUserStatus(c.Request.Context(), userID, &req)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	adminUser, _ := middleware.GetUserFromGin(c)
	h.logger.Info("User status updated by admin", 
		zap.String("user_id", userID.String()),
		zap.String("new_status", string(req.Status)),
		zap.String("admin_id", adminUser.ID.String()),
	)

	response := models.NewSuccessResponse(nil, "User status updated successfully")
	c.JSON(http.StatusOK, response)
}

// AssignRole 分配角色给用户
// @Summary 分配角色给用户
// @Description 管理员为用户分配角色
// @Tags 管理员
// @Security BearerAuth
// @Param user_id path string true "用户ID"
// @Param request body models.AssignRoleRequest true "角色分配请求"
// @Accept json
// @Produce json
// @Success 200 {object} models.APIResponse
// @Failure 400 {object} models.APIResponse
// @Failure 401 {object} models.APIResponse
// @Failure 403 {object} models.APIResponse
// @Failure 404 {object} models.APIResponse
// @Router /admin/users/{user_id}/roles [post]
func (h *AdminHandler) AssignRole(c *gin.Context) {
	userIDStr := c.Param("user_id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(c, http.StatusBadRequest, 40001, "Invalid user ID format")
		return
	}

	var req models.AssignRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithValidationError(c, err)
		return
	}

	if err := h.validator.Struct(&req); err != nil {
		h.respondWithValidationError(c, err)
		return
	}

	adminUser, _ := middleware.GetUserFromGin(c)
	err = h.adminService.AssignRole(c.Request.Context(), userID, req.RoleID, adminUser.ID, req.ExpiresAt)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	h.logger.Info("Role assigned to user by admin", 
		zap.String("user_id", userID.String()),
		zap.String("role_id", req.RoleID.String()),
		zap.String("admin_id", adminUser.ID.String()),
	)

	response := models.NewSuccessResponse(nil, "Role assigned successfully")
	c.JSON(http.StatusOK, response)
}

// RevokeRole 撤销用户角色
// @Summary 撤销用户角色
// @Description 管理员撤销用户的角色
// @Tags 管理员
// @Security BearerAuth
// @Param user_id path string true "用户ID"
// @Param role_id path string true "角色ID"
// @Produce json
// @Success 200 {object} models.APIResponse
// @Failure 400 {object} models.APIResponse
// @Failure 401 {object} models.APIResponse
// @Failure 403 {object} models.APIResponse
// @Failure 404 {object} models.APIResponse
// @Router /admin/users/{user_id}/roles/{role_id} [delete]
func (h *AdminHandler) RevokeRole(c *gin.Context) {
	userIDStr := c.Param("user_id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(c, http.StatusBadRequest, 40001, "Invalid user ID format")
		return
	}

	roleIDStr := c.Param("role_id")
	roleID, err := uuid.Parse(roleIDStr)
	if err != nil {
		h.respondWithError(c, http.StatusBadRequest, 40001, "Invalid role ID format")
		return
	}

	err = h.adminService.RevokeRole(c.Request.Context(), userID, roleID)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	adminUser, _ := middleware.GetUserFromGin(c)
	h.logger.Info("Role revoked from user by admin", 
		zap.String("user_id", userID.String()),
		zap.String("role_id", roleID.String()),
		zap.String("admin_id", adminUser.ID.String()),
	)

	response := models.NewSuccessResponse(nil, "Role revoked successfully")
	c.JSON(http.StatusOK, response)
}

// GetLoginLogs 获取登录日志
// @Summary 获取登录日志
// @Description 管理员查看系统登录日志
// @Tags 管理员
// @Security BearerAuth
// @Param query query models.LoginLogQuery false "查询参数"
// @Produce json
// @Success 200 {object} models.APIResponse{data=models.PaginatedResponse}
// @Failure 400 {object} models.APIResponse
// @Failure 401 {object} models.APIResponse
// @Failure 403 {object} models.APIResponse
// @Router /admin/logs/login [get]
func (h *AdminHandler) GetLoginLogs(c *gin.Context) {
	var query models.LoginLogQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		h.respondWithValidationError(c, err)
		return
	}

	result, err := h.adminService.GetUserLoginLogs(c.Request.Context(), &query)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	response := models.NewSuccessResponse(result, "Login logs retrieved successfully")
	c.JSON(http.StatusOK, response)
}

// GetSystemHealth 系统健康检查
// @Summary 系统健康检查
// @Description 检查系统各组件的健康状态
// @Tags 管理员
// @Security BearerAuth
// @Produce json
// @Success 200 {object} models.APIResponse{data=models.SystemHealthResponse}
// @Failure 401 {object} models.APIResponse
// @Failure 403 {object} models.APIResponse
// @Router /admin/system/health [get]
func (h *AdminHandler) GetSystemHealth(c *gin.Context) {
	// TODO: 实现真实的健康检查
	health := &models.SystemHealthResponse{
		Status:    "healthy",
		Timestamp: time.Now(),
		Services: map[string]models.ServiceHealth{
			"database": {
				Status:    "healthy",
				Message:   "Database connection is stable",
				CheckedAt: time.Now(),
			},
			"redis": {
				Status:    "healthy", 
				Message:   "Redis connection is stable",
				CheckedAt: time.Now(),
			},
			"email": {
				Status:    "healthy",
				Message:   "Email service is operational",
				CheckedAt: time.Now(),
			},
		},
	}

	response := models.NewSuccessResponse(health, "System health retrieved successfully")
	c.JSON(http.StatusOK, response)
}

// 私有方法

// respondWithValidationError 返回验证错误响应
func (h *AdminHandler) respondWithValidationError(c *gin.Context, err error) {
	h.logger.Warn("Admin validation error", zap.Error(err))
	
	fieldErrors := make([]models.FieldError, 0)
	if validationErrors, ok := err.(validator.ValidationErrors); ok {
		for _, validationError := range validationErrors {
			fieldErrors = append(fieldErrors, models.FieldError{
				Field:   validationError.Field(),
				Message: getValidationMessage(validationError),
			})
		}
	} else {
		fieldErrors = append(fieldErrors, models.FieldError{
			Field:   "request",
			Message: err.Error(),
		})
	}
	
	response := models.NewErrorResponse(40002, "Validation failed", fieldErrors)
	c.JSON(http.StatusBadRequest, response)
}

// handleServiceError 处理服务层错误
func (h *AdminHandler) handleServiceError(c *gin.Context, err error) {
	h.logger.Error("Admin service error", zap.Error(err))
	
	switch err {
	case services.ErrUserNotFound:
		h.respondWithError(c, http.StatusNotFound, 40411, "User not found")
	case services.ErrPermissionDenied:
		h.respondWithError(c, http.StatusForbidden, 40301, "Permission denied")
	default:
		h.respondWithError(c, http.StatusInternalServerError, 50001, "Internal server error")
	}
}

// respondWithError 返回错误响应
func (h *AdminHandler) respondWithError(c *gin.Context, httpStatus, code int, message string) {
	response := models.NewErrorResponse(code, message, nil)
	c.JSON(httpStatus, response)
}

// getValidationMessage 获取验证错误消息
func getValidationMessage(err validator.FieldError) string {
	switch err.Tag() {
	case "required":
		return "This field is required"
	case "email":
		return "Invalid email format"
	case "min":
		return "Value is too short (minimum " + err.Param() + " characters)"
	case "max":
		return "Value is too long (maximum " + err.Param() + " characters)"
	case "oneof":
		return "Value must be one of: " + err.Param()
	default:
		return err.Error()
	}
}