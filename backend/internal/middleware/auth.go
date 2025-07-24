package middleware

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/OrAura/backend/internal/models"
	"github.com/OrAura/backend/internal/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// UserContextKey 用户上下文键
type UserContextKey string

const (
	UserKey UserContextKey = "user"
)

// AuthMiddleware 认证中间件
type AuthMiddleware struct {
	userService services.UserService
	logger      *zap.Logger
}

// NewAuthMiddleware 创建认证中间件
func NewAuthMiddleware(userService services.UserService, logger *zap.Logger) *AuthMiddleware {
	return &AuthMiddleware{
		userService: userService,
		logger:      logger,
	}
}

// RequireAuth 需要认证的中间件
func (m *AuthMiddleware) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 提取 Authorization 头
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			m.respondWithError(c, http.StatusUnauthorized, 40101, "Authorization header required")
			return
		}

		// 检查 Bearer 前缀
		tokenParts := strings.SplitN(authHeader, " ", 2)
		if len(tokenParts) != 2 || strings.ToLower(tokenParts[0]) != "bearer" {
			m.respondWithError(c, http.StatusUnauthorized, 40101, "Invalid authorization header format")
			return
		}

		accessToken := tokenParts[1]
		if accessToken == "" {
			m.respondWithError(c, http.StatusUnauthorized, 40101, "Access token required")
			return
		}

		// 验证访问令牌
		user, err := m.userService.ValidateAccessToken(c.Request.Context(), accessToken)
		if err != nil {
			m.logger.Warn("Invalid access token", zap.Error(err))
			
			switch err {
			case services.ErrTokenExpired:
				m.respondWithError(c, http.StatusUnauthorized, 40102, "Token expired")
			case services.ErrTokenInvalid:
				m.respondWithError(c, http.StatusUnauthorized, 40103, "Invalid token")
			case services.ErrUserNotActive:
				m.respondWithError(c, http.StatusForbidden, 40301, "User account is not active")
			default:
				m.respondWithError(c, http.StatusUnauthorized, 40101, "Unauthorized")
			}
			return
		}

		// 将用户信息存储到上下文中
		ctx := context.WithValue(c.Request.Context(), UserKey, user)
		c.Request = c.Request.WithContext(ctx)
		
		// 设置 Gin 上下文中的用户信息（便于后续处理器使用）
		c.Set("user", user)
		c.Set("user_id", user.ID.String())

		c.Next()
	}
}

// OptionalAuth 可选认证的中间件
func (m *AuthMiddleware) OptionalAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.Next()
			return
		}

		tokenParts := strings.SplitN(authHeader, " ", 2)
		if len(tokenParts) != 2 || strings.ToLower(tokenParts[0]) != "bearer" {
			c.Next()
			return
		}

		accessToken := tokenParts[1]
		if accessToken == "" {
			c.Next()
			return
		}

		// 尝试验证访问令牌
		user, err := m.userService.ValidateAccessToken(c.Request.Context(), accessToken)
		if err != nil {
			// 记录错误但不阻止请求
			m.logger.Debug("Optional auth failed", zap.Error(err))
			c.Next()
			return
		}

		// 将用户信息存储到上下文中
		ctx := context.WithValue(c.Request.Context(), UserKey, user)
		c.Request = c.Request.WithContext(ctx)
		
		c.Set("user", user)
		c.Set("user_id", user.ID.String())

		c.Next()
	}
}

// RequireRole 需要特定角色的中间件
func (m *AuthMiddleware) RequireRole(roles ...models.UserRole) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, exists := GetUserFromGin(c)
		if !exists {
			m.respondWithError(c, http.StatusUnauthorized, 40101, "Authentication required")
			return
		}

		// 检查用户是否有任一所需角色
		userHighestRole := user.GetHighestRole()
		for _, requiredRole := range roles {
			if user.HasRole(requiredRole) || userHighestRole == requiredRole {
				c.Next()
				return
			}
		}

		m.logger.Warn("User lacks required role", 
			zap.String("user_id", user.ID.String()),
			zap.String("user_role", string(userHighestRole)),
			zap.Any("required_roles", roles),
		)
		m.respondWithError(c, http.StatusForbidden, 40301, "Insufficient permissions")
	}
}

// RequirePermission 需要特定权限的中间件
func (m *AuthMiddleware) RequirePermission(resource, action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, exists := GetUserFromGin(c)
		if !exists {
			m.respondWithError(c, http.StatusUnauthorized, 40101, "Authentication required")
			return
		}

		// 检查用户是否有所需权限
		hasPermission, err := m.userService.HasPermission(c.Request.Context(), user.ID, resource, action)
		if err != nil {
			m.logger.Error("Failed to check user permission", 
				zap.Error(err),
				zap.String("user_id", user.ID.String()),
				zap.String("resource", resource),
				zap.String("action", action),
			)
			m.respondWithError(c, http.StatusInternalServerError, 50001, "Internal server error")
			return
		}

		if !hasPermission {
			m.logger.Warn("User lacks required permission", 
				zap.String("user_id", user.ID.String()),
				zap.String("resource", resource),
				zap.String("action", action),
			)
			m.respondWithError(c, http.StatusForbidden, 40301, "Insufficient permissions")
			return
		}

		c.Next()
	}
}

// RequireAdmin 需要管理员权限的中间件
func (m *AuthMiddleware) RequireAdmin() gin.HandlerFunc {
	return m.RequireRole(models.UserRoleAdmin, models.UserRoleSuperAdmin)
}

// RequireSuperAdmin 需要超级管理员权限的中间件
func (m *AuthMiddleware) RequireSuperAdmin() gin.HandlerFunc {
	return m.RequireRole(models.UserRoleSuperAdmin)
}

// RequireMember 需要会员权限的中间件
func (m *AuthMiddleware) RequireMember() gin.HandlerFunc {
	return func(c *gin.Context) {
		user, exists := GetUserFromGin(c)
		if !exists {
			m.respondWithError(c, http.StatusUnauthorized, 40101, "Authentication required")
			return
		}

		// 检查用户是否是会员或更高级别
		userRole := user.GetHighestRole()
		if userRole == models.UserRoleRegular {
			// 还可以检查会员是否过期
			if !user.IsMembershipActive() {
				m.respondWithError(c, http.StatusForbidden, 40302, "Membership required")
				return
			}
		}

		c.Next()
	}
}

// RequireActiveUser 需要活跃用户的中间件（排除暂停账户）
func (m *AuthMiddleware) RequireActiveUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		user, exists := GetUserFromGin(c)
		if !exists {
			m.respondWithError(c, http.StatusUnauthorized, 40101, "Authentication required")
			return
		}

		if !user.IsActive() {
			m.respondWithError(c, http.StatusForbidden, 40303, "Account suspended")
			return
		}

		c.Next()
	}
}

// GetUserFromContext 从上下文中获取用户信息
func GetUserFromContext(ctx context.Context) (*models.User, bool) {
	user, ok := ctx.Value(UserKey).(*models.User)
	return user, ok
}

// GetUserFromGin 从 Gin 上下文中获取用户信息
func GetUserFromGin(c *gin.Context) (*models.User, bool) {
	user, exists := c.Get("user")
	if !exists {
		return nil, false
	}
	
	u, ok := user.(*models.User)
	return u, ok
}

// GetUserIDFromGin 从 Gin 上下文中获取用户 ID
func GetUserIDFromGin(c *gin.Context) (uuid.UUID, bool) {
	userIDStr, exists := c.Get("user_id")
	if !exists {
		return uuid.Nil, false
	}
	
	userIDString, ok := userIDStr.(string)
	if !ok {
		return uuid.Nil, false
	}
	
	userID, err := uuid.Parse(userIDString)
	if err != nil {
		return uuid.Nil, false
	}
	
	return userID, true
}

// respondWithError 返回错误响应
func (m *AuthMiddleware) respondWithError(c *gin.Context, httpStatus, code int, message string) {
	response := models.NewErrorResponse(code, message, nil)
	c.JSON(httpStatus, response)
	c.Abort()
}

// CORS 跨域中间件
func CORS() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		
		// 允许的域名列表（生产环境中应该配置具体的域名）
		allowedOrigins := []string{
			"http://localhost:3000",
			"https://oraura.app",
			"https://app.oraura.com",
		}
		
		// 检查是否是允许的域名
		isAllowed := false
		for _, allowedOrigin := range allowedOrigins {
			if origin == allowedOrigin {
				isAllowed = true
				break
			}
		}
		
		if isAllowed {
			c.Header("Access-Control-Allow-Origin", origin)
		}
		
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Max-Age", "86400")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// RateLimitMiddleware 限流中间件
type RateLimitMiddleware struct {
	logger *zap.Logger
	// 这里应该使用 Redis 实现分布式限流，简化示例使用内存实现
	requests map[string][]time.Time
}

// NewRateLimitMiddleware 创建限流中间件
func NewRateLimitMiddleware(logger *zap.Logger) *RateLimitMiddleware {
	return &RateLimitMiddleware{
		logger:   logger,
		requests: make(map[string][]time.Time),
	}
}

// GlobalRateLimit 全局限流：每 IP 每分钟 100 请求
func (m *RateLimitMiddleware) GlobalRateLimit() gin.HandlerFunc {
	return m.rateLimitByIP(100, time.Minute)
}

// LoginRateLimit 登录限流：每 IP 每分钟 5 次登录尝试
func (m *RateLimitMiddleware) LoginRateLimit() gin.HandlerFunc {
	return m.rateLimitByIP(5, time.Minute)
}

// UserRateLimit 用户限流：每用户每分钟 60 请求
func (m *RateLimitMiddleware) UserRateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		user, exists := GetUserFromGin(c)
		if !exists {
			c.Next()
			return
		}
		
		key := "user:" + user.ID.String()
		if !m.checkRateLimit(key, 60, time.Minute) {
			m.respondWithError(c, http.StatusTooManyRequests, 42901, "Too many requests")
			return
		}
		
		c.Next()
	}
}

// rateLimitByIP 按 IP 限流
func (m *RateLimitMiddleware) rateLimitByIP(limit int, window time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		key := "ip:" + clientIP
		
		if !m.checkRateLimit(key, limit, window) {
			m.logger.Warn("Rate limit exceeded", zap.String("ip", clientIP))
			m.respondWithError(c, http.StatusTooManyRequests, 42901, "Too many requests")
			return
		}
		
		c.Next()
	}
}

// checkRateLimit 检查是否超过限流
func (m *RateLimitMiddleware) checkRateLimit(key string, limit int, window time.Duration) bool {
	now := time.Now()
	cutoff := now.Add(-window)
	
	// 清理过期的请求记录
	if requests, exists := m.requests[key]; exists {
		validRequests := make([]time.Time, 0)
		for _, reqTime := range requests {
			if reqTime.After(cutoff) {
				validRequests = append(validRequests, reqTime)
			}
		}
		m.requests[key] = validRequests
	} else {
		m.requests[key] = make([]time.Time, 0)
	}
	
	// 检查是否超过限制
	if len(m.requests[key]) >= limit {
		return false
	}
	
	// 记录当前请求
	m.requests[key] = append(m.requests[key], now)
	return true
}

// RequestLoggerMiddleware 请求日志中间件
func RequestLoggerMiddleware(logger *zap.Logger) gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		logger.Info("HTTP Request",
			zap.String("method", param.Method),
			zap.String("path", param.Path),
			zap.Int("status", param.StatusCode),
			zap.Duration("latency", param.Latency),
			zap.String("client_ip", param.ClientIP),
			zap.String("user_agent", param.Request.UserAgent()),
		)
		return ""
	})
}

// ErrorHandlerMiddleware 错误处理中间件
func ErrorHandlerMiddleware(logger *zap.Logger) gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		logger.Error("Panic recovered",
			zap.Any("error", recovered),
			zap.String("path", c.Request.URL.Path),
			zap.String("method", c.Request.Method),
		)
		
		response := models.NewErrorResponse(50001, "Internal server error", nil)
		c.JSON(http.StatusInternalServerError, response)
	})
}

// ValidationErrorMiddleware 验证错误处理中间件
func ValidationErrorMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		
		// 处理验证错误
		if len(c.Errors) > 0 {
			err := c.Errors.Last()
			
			fieldErrors := make([]models.FieldError, 0)
			fieldErrors = append(fieldErrors, models.FieldError{
				Field:   "validation",
				Message: err.Error(),
			})
			
			response := models.NewErrorResponse(40002, "Validation failed", fieldErrors)
			c.JSON(http.StatusBadRequest, response)
			return
		}
	}
}

// respondWithError 返回错误响应（限流中间件使用）
func (m *RateLimitMiddleware) respondWithError(c *gin.Context, httpStatus, code int, message string) {
	response := models.NewErrorResponse(code, message, nil)
	c.JSON(httpStatus, response)
	c.Abort()
}