package handlers

import (
	"net/http"
	"strings"

	"github.com/OrAura/backend/internal/middleware"
	"github.com/OrAura/backend/internal/models"
	"github.com/OrAura/backend/internal/services"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// UserHandler 用户处理器
type UserHandler struct {
	userService services.UserService
	validator   *validator.Validate
	logger      *zap.Logger
}

// NewUserHandler 创建用户处理器
func NewUserHandler(userService services.UserService, validator *validator.Validate, logger *zap.Logger) *UserHandler {
	return &UserHandler{
		userService: userService,
		validator:   validator,
		logger:      logger,
	}
}

// Register 用户注册
// @Summary 用户注册
// @Description 创建新用户账户
// @Tags 认证
// @Accept json
// @Produce json
// @Param request body models.RegisterRequest true "注册信息"
// @Success 201 {object} models.APIResponse{data=models.UserInfo}
// @Failure 400 {object} models.APIResponse
// @Router /auth/register [post]
func (h *UserHandler) Register(c *gin.Context) {
	var req models.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithValidationError(c, err)
		return
	}

	if err := h.validator.Struct(&req); err != nil {
		h.respondWithValidationError(c, err)
		return
	}

	user, err := h.userService.Register(c.Request.Context(), &req)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	h.logger.Info("User registered successfully", zap.String("user_id", user.ID.String()))
	response := models.NewSuccessResponse(user.ToUserInfo(), "Registration successful")
	c.JSON(http.StatusCreated, response)
}

// Login 用户登录
// @Summary 用户登录
// @Description 用户邮箱密码登录
// @Tags 认证
// @Accept json
// @Produce json
// @Param request body models.LoginRequest true "登录信息"
// @Success 200 {object} models.APIResponse{data=models.TokenResponse}
// @Failure 400 {object} models.APIResponse
// @Failure 401 {object} models.APIResponse
// @Router /auth/login [post]
func (h *UserHandler) Login(c *gin.Context) {
	var req models.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithValidationError(c, err)
		return
	}

	if err := h.validator.Struct(&req); err != nil {
		h.respondWithValidationError(c, err)
		return
	}

	tokenResponse, err := h.userService.Login(c.Request.Context(), &req)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	h.logger.Info("User logged in successfully", zap.String("email", req.Email))
	response := models.NewSuccessResponse(tokenResponse, "Login successful")
	c.JSON(http.StatusOK, response)
}

// RefreshToken 刷新访问令牌
// @Summary 刷新访问令牌
// @Description 使用刷新令牌获取新的访问令牌
// @Tags 认证
// @Accept json
// @Produce json
// @Param request body models.RefreshTokenRequest true "刷新令牌请求"
// @Success 200 {object} models.APIResponse{data=models.TokenResponse}
// @Failure 400 {object} models.APIResponse
// @Failure 401 {object} models.APIResponse
// @Router /auth/refresh [post]
func (h *UserHandler) RefreshToken(c *gin.Context) {
	var req models.RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithValidationError(c, err)
		return
	}

	if err := h.validator.Struct(&req); err != nil {
		h.respondWithValidationError(c, err)
		return
	}

	tokenResponse, err := h.userService.RefreshToken(c.Request.Context(), req.RefreshToken)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	response := models.NewSuccessResponse(tokenResponse, "Token refreshed successfully")
	c.JSON(http.StatusOK, response)
}

// Logout 用户注销
// @Summary 用户注销
// @Description 注销用户会话，使令牌失效
// @Tags 认证
// @Produce json
// @Security BearerAuth
// @Success 200 {object} models.APIResponse
// @Failure 401 {object} models.APIResponse
// @Router /auth/logout [post]
func (h *UserHandler) Logout(c *gin.Context) {
	userID, exists := middleware.GetUserIDFromGin(c)
	if !exists {
		h.respondWithError(c, http.StatusUnauthorized, 40101, "User not authenticated")
		return
	}

	// 获取访问令牌
	authHeader := c.GetHeader("Authorization")
	accessToken := ""
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 {
			accessToken = parts[1]
		}
	}

	err := h.userService.Logout(c.Request.Context(), userID, accessToken)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	h.logger.Info("User logged out successfully", zap.String("user_id", userID.String()))
	response := models.NewSuccessResponse(nil, "Logout successful")
	c.JSON(http.StatusOK, response)
}

// GetProfile 获取用户信息
// @Summary 获取用户信息
// @Description 获取当前用户的详细信息
// @Tags 用户
// @Produce json
// @Security BearerAuth
// @Success 200 {object} models.APIResponse{data=models.UserInfo}
// @Failure 401 {object} models.APIResponse
// @Failure 404 {object} models.APIResponse
// @Router /users/profile [get]
func (h *UserHandler) GetProfile(c *gin.Context) {
	userID, exists := middleware.GetUserIDFromGin(c)
	if !exists {
		h.respondWithError(c, http.StatusUnauthorized, 40101, "User not authenticated")
		return
	}

	userInfo, err := h.userService.GetUserProfile(c.Request.Context(), userID)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	response := models.NewSuccessResponse(userInfo, "Profile retrieved successfully")
	c.JSON(http.StatusOK, response)
}

// UpdateProfile 更新用户信息
// @Summary 更新用户信息
// @Description 更新当前用户的个人信息
// @Tags 用户
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body models.UpdateProfileRequest true "更新信息"
// @Success 200 {object} models.APIResponse{data=models.UserInfo}
// @Failure 400 {object} models.APIResponse
// @Failure 401 {object} models.APIResponse
// @Router /users/profile [put]
func (h *UserHandler) UpdateProfile(c *gin.Context) {
	userID, exists := middleware.GetUserIDFromGin(c)
	if !exists {
		h.respondWithError(c, http.StatusUnauthorized, 40101, "User not authenticated")
		return
	}

	var req models.UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithValidationError(c, err)
		return
	}

	if err := h.validator.Struct(&req); err != nil {
		h.respondWithValidationError(c, err)
		return
	}

	userInfo, err := h.userService.UpdateUserProfile(c.Request.Context(), userID, &req)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	h.logger.Info("User profile updated successfully", zap.String("user_id", userID.String()))
	response := models.NewSuccessResponse(userInfo, "Profile updated successfully")
	c.JSON(http.StatusOK, response)
}

// ChangePassword 修改密码
// @Summary 修改密码
// @Description 修改当前用户的密码
// @Tags 用户
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body models.ChangePasswordRequest true "修改密码信息"
// @Success 200 {object} models.APIResponse
// @Failure 400 {object} models.APIResponse
// @Failure 401 {object} models.APIResponse
// @Router /users/password [put]
func (h *UserHandler) ChangePassword(c *gin.Context) {
	userID, exists := middleware.GetUserIDFromGin(c)
	if !exists {
		h.respondWithError(c, http.StatusUnauthorized, 40101, "User not authenticated")
		return
	}

	var req models.ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithValidationError(c, err)
		return
	}

	if err := h.validator.Struct(&req); err != nil {
		h.respondWithValidationError(c, err)
		return
	}

	err := h.userService.ChangePassword(c.Request.Context(), userID, &req)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	h.logger.Info("Password changed successfully", zap.String("user_id", userID.String()))
	response := models.NewSuccessResponse(nil, "Password updated successfully")
	c.JSON(http.StatusOK, response)
}

// ForgotPassword 忘记密码
// @Summary 忘记密码
// @Description 发送密码重置邮件
// @Tags 认证
// @Accept json
// @Produce json
// @Param request body models.ForgotPasswordRequest true "忘记密码请求"
// @Success 200 {object} models.APIResponse
// @Failure 400 {object} models.APIResponse
// @Router /auth/forgot-password [post]
func (h *UserHandler) ForgotPassword(c *gin.Context) {
	var req models.ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithValidationError(c, err)
		return
	}

	if err := h.validator.Struct(&req); err != nil {
		h.respondWithValidationError(c, err)
		return
	}

	err := h.userService.ForgotPassword(c.Request.Context(), &req)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	response := models.NewSuccessResponse(nil, "Password reset email sent")
	c.JSON(http.StatusOK, response)
}

// ResetPassword 重置密码
// @Summary 重置密码
// @Description 使用重置令牌重置密码
// @Tags 认证
// @Accept json
// @Produce json
// @Param request body models.ResetPasswordRequest true "重置密码请求"
// @Success 200 {object} models.APIResponse
// @Failure 400 {object} models.APIResponse
// @Router /auth/reset-password [post]
func (h *UserHandler) ResetPassword(c *gin.Context) {
	var req models.ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithValidationError(c, err)
		return
	}

	if err := h.validator.Struct(&req); err != nil {
		h.respondWithValidationError(c, err)
		return
	}

	err := h.userService.ResetPassword(c.Request.Context(), &req)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	response := models.NewSuccessResponse(nil, "Password reset successfully")
	c.JSON(http.StatusOK, response)
}

// LoginWithGoogle Google OAuth 登录
// @Summary Google OAuth 登录
// @Description 使用 Google 账户登录
// @Tags OAuth
// @Accept json
// @Produce json
// @Param request body models.OAuthLoginRequest true "Google OAuth 登录请求"
// @Success 200 {object} models.APIResponse{data=models.TokenResponse}
// @Failure 400 {object} models.APIResponse
// @Router /auth/oauth/google [post]
func (h *UserHandler) LoginWithGoogle(c *gin.Context) {
	var req models.OAuthLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithValidationError(c, err)
		return
	}

	if err := h.validator.Struct(&req); err != nil {
		h.respondWithValidationError(c, err)
		return
	}

	tokenResponse, err := h.userService.LoginWithGoogle(c.Request.Context(), &req)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	response := models.NewSuccessResponse(tokenResponse, "OAuth login successful")
	c.JSON(http.StatusOK, response)
}

// LoginWithApple Apple OAuth 登录
// @Summary Apple OAuth 登录
// @Description 使用 Apple 账户登录
// @Tags OAuth
// @Accept json
// @Produce json
// @Param request body models.OAuthLoginRequest true "Apple OAuth 登录请求"
// @Success 200 {object} models.APIResponse{data=models.TokenResponse}
// @Failure 400 {object} models.APIResponse
// @Router /auth/oauth/apple [post]
func (h *UserHandler) LoginWithApple(c *gin.Context) {
	var req models.OAuthLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithValidationError(c, err)
		return
	}

	if err := h.validator.Struct(&req); err != nil {
		h.respondWithValidationError(c, err)
		return
	}

	tokenResponse, err := h.userService.LoginWithApple(c.Request.Context(), &req)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	response := models.NewSuccessResponse(tokenResponse, "OAuth login successful")
	c.JSON(http.StatusOK, response)
}

// DeleteAccount 删除账户
// @Summary 删除账户
// @Description 永久删除用户账户及所有相关数据
// @Tags 用户
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body models.DeleteAccountRequest true "删除账户确认"
// @Success 200 {object} models.APIResponse
// @Failure 400 {object} models.APIResponse
// @Failure 401 {object} models.APIResponse
// @Router /users/account [delete]
func (h *UserHandler) DeleteAccount(c *gin.Context) {
	userID, exists := middleware.GetUserIDFromGin(c)
	if !exists {
		h.respondWithError(c, http.StatusUnauthorized, 40101, "User not authenticated")
		return
	}

	var req models.DeleteAccountRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithValidationError(c, err)
		return
	}

	if err := h.validator.Struct(&req); err != nil {
		h.respondWithValidationError(c, err)
		return
	}

	err := h.userService.DeleteAccount(c.Request.Context(), userID, &req)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	h.logger.Info("Account deleted successfully", zap.String("user_id", userID.String()))
	response := models.NewSuccessResponse(nil, "Account deleted successfully")
	c.JSON(http.StatusOK, response)
}

// UploadAvatar 上传头像
// @Summary 上传头像
// @Description 上传用户头像图片
// @Tags 用户
// @Accept multipart/form-data
// @Produce json
// @Security BearerAuth
// @Param avatar formData file true "头像文件"
// @Success 200 {object} models.APIResponse{data=models.AvatarUploadResponse}
// @Failure 400 {object} models.APIResponse
// @Failure 401 {object} models.APIResponse
// @Router /users/avatar [post]
func (h *UserHandler) UploadAvatar(c *gin.Context) {
	userID, exists := middleware.GetUserIDFromGin(c)
	if !exists {
		h.respondWithError(c, http.StatusUnauthorized, 40101, "User not authenticated")
		return
	}

	// 获取上传的文件
	file, header, err := c.Request.FormFile("avatar")
	if err != nil {
		h.respondWithError(c, http.StatusBadRequest, 40001, "Invalid file upload")
		return
	}
	defer file.Close()

	// 验证文件类型和大小
	if header.Size > 5*1024*1024 { // 5MB 限制
		h.respondWithError(c, http.StatusBadRequest, 40001, "File size too large (max 5MB)")
		return
	}

	// TODO: 实现文件上传到云存储
	// 这里应该实现文件上传到 S3 或其他云存储服务
	// 暂时返回一个模拟的 URL
	avatarURL := "https://cdn.example.com/avatars/" + userID.String() + ".jpg"

	h.logger.Info("Avatar uploaded successfully", zap.String("user_id", userID.String()))
	response := models.NewSuccessResponse(&models.AvatarUploadResponse{
		AvatarURL: avatarURL,
	}, "Avatar uploaded successfully")
	c.JSON(http.StatusOK, response)
}

// VerifyEmail 验证邮箱
// @Summary 验证邮箱
// @Description 使用验证令牌验证用户邮箱
// @Tags 认证
// @Accept json
// @Produce json
// @Param request body models.VerifyEmailRequest true "验证邮箱请求"
// @Success 200 {object} models.APIResponse{data=models.UserInfo}
// @Failure 400 {object} models.APIResponse
// @Router /auth/verify-email [post]
func (h *UserHandler) VerifyEmail(c *gin.Context) {
	var req models.VerifyEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithValidationError(c, err)
		return
	}

	if err := h.validator.Struct(&req); err != nil {
		h.respondWithValidationError(c, err)
		return
	}

	user, err := h.userService.VerifyEmail(c.Request.Context(), req.Token)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	h.logger.Info("Email verified successfully", zap.String("user_id", user.ID.String()))
	response := models.NewSuccessResponse(user.ToUserInfo(), "Email verified successfully")
	c.JSON(http.StatusOK, response)
}

// ResendVerificationEmail 重新发送验证邮件
// @Summary 重新发送验证邮件
// @Description 重新发送邮箱验证邮件
// @Tags 认证
// @Accept json
// @Produce json
// @Param request body models.ResendVerificationRequest true "重新发送验证邮件请求"
// @Success 200 {object} models.APIResponse
// @Failure 400 {object} models.APIResponse
// @Router /auth/resend-verification [post]
func (h *UserHandler) ResendVerificationEmail(c *gin.Context) {
	var req models.ResendVerificationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithValidationError(c, err)
		return
	}

	if err := h.validator.Struct(&req); err != nil {
		h.respondWithValidationError(c, err)
		return
	}

	err := h.userService.ResendVerificationEmail(c.Request.Context(), req.Email)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	h.logger.Info("Verification email resent", zap.String("email", req.Email))
	response := models.NewSuccessResponse(nil, "Verification email sent successfully")
	c.JSON(http.StatusOK, response)
}

// 私有方法

// respondWithValidationError 返回验证错误响应
func (h *UserHandler) respondWithValidationError(c *gin.Context, err error) {
	h.logger.Warn("Validation error", zap.Error(err))
	
	fieldErrors := make([]models.FieldError, 0)
	if validationErrors, ok := err.(validator.ValidationErrors); ok {
		for _, validationError := range validationErrors {
			fieldErrors = append(fieldErrors, models.FieldError{
				Field:   validationError.Field(),
				Message: getValidationErrorMessage(validationError),
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
func (h *UserHandler) handleServiceError(c *gin.Context, err error) {
	h.logger.Error("Service error", zap.Error(err))
	
	switch err {
	case services.ErrUserNotFound:
		h.respondWithError(c, http.StatusNotFound, 40411, "User not found")
	case services.ErrEmailAlreadyExists:
		h.respondWithError(c, http.StatusBadRequest, 40011, "Email already exists")
	case services.ErrUsernameAlreadyExists:
		h.respondWithError(c, http.StatusBadRequest, 40012, "Username already exists")
	case services.ErrInvalidCredentials:
		h.respondWithError(c, http.StatusUnauthorized, 40111, "Invalid credentials")
	case services.ErrInvalidPassword:
		h.respondWithError(c, http.StatusBadRequest, 40012, "Current password incorrect")
	case services.ErrUserNotActive:
		h.respondWithError(c, http.StatusForbidden, 40113, "Account suspended")
	case services.ErrTokenExpired:
		h.respondWithError(c, http.StatusUnauthorized, 40102, "Token expired")
	case services.ErrTokenInvalid:
		h.respondWithError(c, http.StatusUnauthorized, 40103, "Invalid token")
	default:
		h.respondWithError(c, http.StatusInternalServerError, 50001, "Internal server error")
	}
}

// respondWithError 返回错误响应
func (h *UserHandler) respondWithError(c *gin.Context, httpStatus, code int, message string) {
	response := models.NewErrorResponse(code, message, nil)
	c.JSON(httpStatus, response)
}

// getValidationErrorMessage 获取验证错误消息
func getValidationErrorMessage(err validator.FieldError) string {
	switch err.Tag() {
	case "required":
		return "This field is required"
	case "email":
		return "Invalid email format"
	case "min":
		return "Value is too short (minimum " + err.Param() + " characters)"
	case "max":
		return "Value is too long (maximum " + err.Param() + " characters)"
	case "alphanum":
		return "Only alphanumeric characters are allowed"
	case "eqfield":
		return "Value must match " + err.Param()
	case "eq":
		return "Value must equal " + err.Param()
	default:
		return err.Error()
	}
}

// 辅助方法

// getCurrentUser 从上下文中获取当前用户
func (h *UserHandler) getCurrentUser(c *gin.Context) *models.User {
	value, exists := c.Get("user")
	if !exists {
		response := models.NewErrorResponse(401, "Authentication required", nil)
		c.JSON(http.StatusUnauthorized, response)
		return nil
	}

	user, ok := value.(*models.User)
	if !ok {
		response := models.NewErrorResponse(401, "Invalid user context", nil)
		c.JSON(http.StatusUnauthorized, response)
		return nil
	}

	return user
}

// 增强认证功能方法

// LogoutAll 登出所有会话
// @Summary 登出所有会话
// @Description 登出用户的所有会话
// @Tags 认证
// @Security BearerAuth
// @Produce json
// @Success 200 {object} models.APIResponse
// @Failure 401 {object} models.APIResponse
// @Router /auth/logout/all [post]
func (h *UserHandler) LogoutAll(c *gin.Context) {
	user := h.getCurrentUser(c)
	if user == nil {
		return
	}

	err := h.userService.LogoutAll(c.Request.Context(), user.ID)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	h.logger.Info("User logged out from all sessions", zap.String("user_id", user.ID.String()))
	response := models.NewSuccessResponse(nil, "Logged out from all sessions successfully")
	c.JSON(http.StatusOK, response)
}

// GetUserSessions 获取用户会话
// @Summary 获取用户会话
// @Description 获取当前用户的所有活跃会话
// @Tags 用户
// @Security BearerAuth
// @Produce json
// @Success 200 {object} models.APIResponse{data=[]models.UserSession}
// @Failure 401 {object} models.APIResponse
// @Router /user/sessions [get]
func (h *UserHandler) GetUserSessions(c *gin.Context) {
	user := h.getCurrentUser(c)
	if user == nil {
		return
	}

	sessions, err := h.userService.GetUserSessions(c.Request.Context(), user.ID)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	response := models.NewSuccessResponse(sessions, "Sessions retrieved successfully")
	c.JSON(http.StatusOK, response)
}

// DeleteUserSession 删除用户会话
// @Summary 删除用户会话
// @Description 删除指定的用户会话
// @Tags 用户
// @Security BearerAuth
// @Param session_id path string true "会话ID"
// @Produce json
// @Success 200 {object} models.APIResponse
// @Failure 401 {object} models.APIResponse
// @Failure 404 {object} models.APIResponse
// @Router /user/sessions/{session_id} [delete]
func (h *UserHandler) DeleteUserSession(c *gin.Context) {
	user := h.getCurrentUser(c)
	if user == nil {
		return
	}

	sessionIDStr := c.Param("session_id")
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		response := models.NewErrorResponse(400, "Invalid session ID format", nil)
		c.JSON(http.StatusBadRequest, response)
		return
	}

	err = h.userService.DeleteUserSession(c.Request.Context(), sessionID)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	h.logger.Info("User session deleted", 
		zap.String("user_id", user.ID.String()),
		zap.String("session_id", sessionID.String()))
	response := models.NewSuccessResponse(nil, "Session deleted successfully")
	c.JSON(http.StatusOK, response)
}

// ListAPITokens 列出API令牌
// @Summary 列出API令牌
// @Description 获取当前用户的所有API令牌
// @Tags API令牌
// @Security BearerAuth
// @Produce json
// @Success 200 {object} models.APIResponse{data=[]models.APIToken}
// @Failure 401 {object} models.APIResponse
// @Router /user/api-tokens [get]
func (h *UserHandler) ListAPITokens(c *gin.Context) {
	user := h.getCurrentUser(c)
	if user == nil {
		return
	}

	tokens, err := h.userService.ListAPITokens(c.Request.Context(), user.ID)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	response := models.NewSuccessResponse(tokens, "API tokens retrieved successfully")
	c.JSON(http.StatusOK, response)
}

// CreateAPIToken 创建API令牌
// @Summary 创建API令牌
// @Description 为当前用户创建新的API令牌
// @Tags API令牌
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body models.CreateAPITokenRequest true "API令牌创建请求"
// @Success 201 {object} models.APIResponse{data=models.APITokenResponse}
// @Failure 400 {object} models.APIResponse
// @Failure 401 {object} models.APIResponse
// @Router /user/api-tokens [post]
func (h *UserHandler) CreateAPIToken(c *gin.Context) {
	user := h.getCurrentUser(c)
	if user == nil {
		return
	}

	var req models.CreateAPITokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithValidationError(c, err)
		return
	}

	if err := h.validator.Struct(&req); err != nil {
		h.respondWithValidationError(c, err)
		return
	}

	tokenResponse, err := h.userService.CreateAPIToken(c.Request.Context(), user.ID, &req)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	h.logger.Info("API token created", 
		zap.String("user_id", user.ID.String()),
		zap.String("token_name", req.Name))
	response := models.NewSuccessResponse(tokenResponse, "API token created successfully")
	c.JSON(http.StatusCreated, response)
}

// DeleteAPIToken 删除API令牌
// @Summary 删除API令牌
// @Description 删除指定的API令牌
// @Tags API令牌
// @Security BearerAuth
// @Param token_id path string true "令牌ID"
// @Produce json
// @Success 200 {object} models.APIResponse
// @Failure 401 {object} models.APIResponse
// @Failure 404 {object} models.APIResponse
// @Router /user/api-tokens/{token_id} [delete]
func (h *UserHandler) DeleteAPIToken(c *gin.Context) {
	user := h.getCurrentUser(c)
	if user == nil {
		return
	}

	tokenIDStr := c.Param("token_id")
	tokenID, err := uuid.Parse(tokenIDStr)
	if err != nil {
		response := models.NewErrorResponse(400, "Invalid token ID format", nil)
		c.JSON(http.StatusBadRequest, response)
		return
	}

	err = h.userService.DeleteAPIToken(c.Request.Context(), tokenID)
	if err != nil {
		h.handleServiceError(c, err)
		return
	}

	h.logger.Info("API token deleted", 
		zap.String("user_id", user.ID.String()),
		zap.String("token_id", tokenID.String()))
	response := models.NewSuccessResponse(nil, "API token deleted successfully")
	c.JSON(http.StatusOK, response)
}