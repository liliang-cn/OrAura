package routes

import (
	"github.com/OrAura/backend/internal/handlers"
	"github.com/OrAura/backend/internal/middleware"
	"github.com/gin-gonic/gin"
)

// SetupAdminRoutes 设置管理员相关路由
func SetupAdminRoutes(r *gin.RouterGroup, adminHandler *handlers.AdminHandler, authMiddleware *middleware.AuthMiddleware, rateLimitMiddleware *middleware.RateLimitMiddleware) {
	// 管理员路由组 - 需要管理员权限
	admin := r.Group("/admin")
	admin.Use(authMiddleware.RequireAuth())
	admin.Use(authMiddleware.RequireAdmin()) // 需要管理员或超级管理员权限
	admin.Use(rateLimitMiddleware.UserRateLimit())
	{
		// 仪表板统计
		admin.GET("/stats", adminHandler.GetDashboardStats)
		
		// 用户管理
		users := admin.Group("/users")
		{
			users.GET("", adminHandler.ListUsers)
			users.GET("/:user_id", adminHandler.GetUser)
			users.PUT("/:user_id/status", adminHandler.UpdateUserStatus)
			
			// 角色管理
			users.POST("/:user_id/roles", adminHandler.AssignRole)
			users.DELETE("/:user_id/roles/:role_id", adminHandler.RevokeRole)
		}
		
		// 日志管理
		logs := admin.Group("/logs")
		{
			logs.GET("/login", adminHandler.GetLoginLogs)
		}
		
		// 系统管理 - 需要超级管理员权限
		system := admin.Group("/system")
		system.Use(authMiddleware.RequireSuperAdmin())
		{
			system.GET("/health", adminHandler.GetSystemHealth)
		}
	}
}