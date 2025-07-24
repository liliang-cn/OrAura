package routes

import (
	"github.com/OrAura/backend/internal/handlers"
	"github.com/OrAura/backend/internal/middleware"
	"github.com/gin-gonic/gin"
)

// SetupUserRoutes 设置用户相关路由
func SetupUserRoutes(r *gin.RouterGroup, userHandler *handlers.UserHandler, authMiddleware *middleware.AuthMiddleware, rateLimitMiddleware *middleware.RateLimitMiddleware) {
	// 认证相关路由（无需认证）
	auth := r.Group("/auth")
	{
		// 用户注册
		auth.POST("/register", 
			rateLimitMiddleware.GlobalRateLimit(),
			userHandler.Register,
		)
		
		// 用户登录
		auth.POST("/login", 
			rateLimitMiddleware.LoginRateLimit(),
			userHandler.Login,
		)
		
		// 刷新令牌
		auth.POST("/refresh", 
			rateLimitMiddleware.GlobalRateLimit(),
			userHandler.RefreshToken,
		)
		
		// 忘记密码
		auth.POST("/forgot-password", 
			rateLimitMiddleware.LoginRateLimit(),
			userHandler.ForgotPassword,
		)
		
		// 重置密码
		auth.POST("/reset-password", 
			rateLimitMiddleware.LoginRateLimit(),
			userHandler.ResetPassword,
		)
		
		// 邮箱验证
		auth.POST("/verify-email", 
			rateLimitMiddleware.GlobalRateLimit(),
			userHandler.VerifyEmail,
		)
		
		// 重新发送验证邮件
		auth.POST("/resend-verification", 
			rateLimitMiddleware.LoginRateLimit(),
			userHandler.ResendVerificationEmail,
		)
		
		// OAuth 登录路由
		oauth := auth.Group("/oauth")
		{
			oauth.POST("/google", 
				rateLimitMiddleware.GlobalRateLimit(),
				userHandler.LoginWithGoogle,
			)
			
			oauth.POST("/apple", 
				rateLimitMiddleware.GlobalRateLimit(),
				userHandler.LoginWithApple,
			)
		}
	}
	
	// 需要认证的路由
	authenticated := r.Group("")
	authenticated.Use(authMiddleware.RequireAuth())
	authenticated.Use(rateLimitMiddleware.UserRateLimit())
	{
		// 用户注销
		authenticated.POST("/auth/logout", userHandler.Logout)
		
		// 用户信息管理
		users := authenticated.Group("/users")
		{
			// 获取用户信息
			users.GET("/profile", userHandler.GetProfile)
			
			// 更新用户信息
			users.PUT("/profile", userHandler.UpdateProfile)
			
			// 修改密码
			users.PUT("/password", userHandler.ChangePassword)
			
			// 上传头像
			users.POST("/avatar", userHandler.UploadAvatar)
			
			// 删除账户
			users.DELETE("/account", userHandler.DeleteAccount)
		}
	}
}