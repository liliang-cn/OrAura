// Package main OrAura Backend Service
// @title OrAura Backend API
// @version 1.0
// @description OrAura spiritual divination application backend service with user management
// @termsOfService https://oraura.app/terms
// @contact.name OrAura API Support
// @contact.url https://oraura.app/support
// @contact.email support@oraura.app
// @license.name MIT
// @license.url https://opensource.org/licenses/MIT
// @host localhost:8080
// @BasePath /api/v1
// @schemes http https
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token.
package main

import (
	"errors"
	"log"
	"time"

	"github.com/OrAura/backend/internal/config"
	"github.com/OrAura/backend/internal/handlers"
	"github.com/OrAura/backend/internal/middleware"
	"github.com/OrAura/backend/internal/models"
	"github.com/OrAura/backend/internal/routes"
	"github.com/OrAura/backend/internal/services"
	"github.com/OrAura/backend/internal/store"
	"github.com/OrAura/backend/internal/utils"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"go.uber.org/zap"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	_ "github.com/OrAura/backend/docs" // Import generated docs
)

func main() {
	// 加载配置
	cfg, err := config.LoadConfig("./configs")
	if err != nil {
		log.Fatal("cannot load config:", err)
	}

	// 初始化日志
	zapLogger, err := zap.NewProduction()
	if err != nil {
		log.Fatal("cannot initialize logger:", err)
	}
	defer zapLogger.Sync()

	// 连接数据库
	dsn := cfg.GetDatabaseDSN()
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
		NowFunc: func() time.Time {
			return time.Now().UTC()
		},
	})
	if err != nil {
		zapLogger.Fatal("cannot connect to database", zap.Error(err))
	}

	// 自动迁移数据库表
	err = db.AutoMigrate(
		&models.User{},
		&models.UserProfile{},
		&models.RefreshToken{},
		&models.JWTBlacklist{},
		&models.PasswordResetToken{},
		&models.UserLoginLog{},
		&models.EmailVerification{},
		// 新增角色相关表
		&models.Role{},
		&models.Permission{},
		&models.RolePermission{},
		&models.UserRoleAssignment{},
		&models.APIToken{},
		&models.UserSession{},
	)
	if err != nil {
		zapLogger.Fatal("cannot migrate database", zap.Error(err))
	}

	// 初始化默认角色和权限
	if err := initializeRolesAndPermissions(db, zapLogger); err != nil {
		zapLogger.Fatal("cannot initialize roles and permissions", zap.Error(err))
	}

	// 创建超级管理员（如果不存在）
	if err := initializeSuperAdmin(db, cfg, zapLogger); err != nil {
		zapLogger.Fatal("cannot initialize super admin", zap.Error(err))
	}

	// 初始化 JWT 管理器
	jwtManager := utils.NewJWTManager(
		cfg.JWT.Secret,
		cfg.JWT.AccessTokenExpire,
		cfg.JWT.RefreshTokenExpire,
	)

	// 初始化验证器
	validate := validator.New()

	// 初始化仓储层
	userRepo := store.NewUserRepository(db)

	// 初始化OAuth服务
	oauthService := services.NewOAuthService(
		cfg.OAuth.Google.ClientID,
		cfg.OAuth.Google.ClientSecret,
		cfg.OAuth.Apple.ClientID,
		cfg.OAuth.Apple.ClientSecret,
		zapLogger,
	)

	// 初始化邮件服务
	emailProvider := services.NewMockEmailProvider(zapLogger)
	emailService := services.NewEmailService(emailProvider, zapLogger)
	emailVerificationService := services.NewEmailVerificationService(userRepo, emailService, zapLogger)

	// 初始化服务层
	userService := services.NewUserServiceComplete(userRepo, oauthService, emailVerificationService, jwtManager, zapLogger)

	// 初始化处理器
	userHandler := handlers.NewUserHandler(userService, validate, zapLogger)
	adminHandler := handlers.NewAdminHandler(userService, validate, zapLogger)

	// 初始化中间件
	authMiddleware := middleware.NewAuthMiddleware(userService, zapLogger)
	rateLimitMiddleware := middleware.NewRateLimitMiddleware(zapLogger)

	// 设置 Gin 模式
	if cfg.Server.Mode == "release" {
		gin.SetMode(gin.ReleaseMode)
	}

	// 初始化路由
	r := gin.New()

	// 添加全局中间件
	r.Use(middleware.CORS())
	r.Use(middleware.RequestLoggerMiddleware(zapLogger))
	r.Use(middleware.ErrorHandlerMiddleware(zapLogger))
	r.Use(middleware.ValidationErrorMiddleware())

	// 健康检查
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":  "ok",
			"service": "OrAura Backend",
			"time":    time.Now().UTC(),
		})
	})

	// API v1 路由
	apiV1 := r.Group("/api/v1")
	routes.SetupUserRoutes(apiV1, userHandler, authMiddleware, rateLimitMiddleware)
	routes.SetupAdminRoutes(apiV1, adminHandler, authMiddleware, rateLimitMiddleware)

	// Swagger 文档路由
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// 启动服务器
	serverAddr := cfg.GetServerAddress()
	zapLogger.Info("Starting OrAura Backend Service", 
		zap.String("address", serverAddr),
		zap.String("mode", cfg.Server.Mode),
	)

	if err := r.Run(serverAddr); err != nil {
		zapLogger.Fatal("cannot start server", zap.Error(err))
	}
}

// initializeRolesAndPermissions 初始化默认角色和权限
func initializeRolesAndPermissions(db *gorm.DB, logger *zap.Logger) error {
	// 创建默认角色
	defaultRoles := []models.Role{
		{
			Name:        models.UserRoleRegular,
			DisplayName: "Regular User",
			Description: "普通用户",
			Level:       0,
			IsSystem:    true,
			IsActive:    true,
		},
		{
			Name:        models.UserRoleMember,
			DisplayName: "Member",
			Description: "会员用户",
			Level:       1,
			IsSystem:    true,
			IsActive:    true,
		},
		{
			Name:        models.UserRoleAdmin,
			DisplayName: "Administrator",
			Description: "管理员",
			Level:       2,
			IsSystem:    true,
			IsActive:    true,
		},
		{
			Name:        models.UserRoleSuperAdmin,
			DisplayName: "Super Administrator",
			Description: "超级管理员",
			Level:       3,
			IsSystem:    true,
			IsActive:    true,
		},
	}

	for _, role := range defaultRoles {
		var existingRole models.Role
		if err := db.Where("name = ?", role.Name).First(&existingRole).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				if err := db.Create(&role).Error; err != nil {
					return err
				}
				logger.Info("Created default role", zap.String("role", string(role.Name)))
			} else {
				return err
			}
		}
	}

	// 创建基础权限
	defaultPermissions := []models.Permission{
		{Name: "user.read", Description: "读取用户信息", Resource: "user", Action: "read"},
		{Name: "user.write", Description: "修改用户信息", Resource: "user", Action: "write"},
		{Name: "admin.users.read", Description: "管理员查看用户", Resource: "admin.users", Action: "read"},
		{Name: "admin.users.write", Description: "管理员管理用户", Resource: "admin.users", Action: "write"},
		{Name: "admin.roles.read", Description: "管理员查看角色", Resource: "admin.roles", Action: "read"},
		{Name: "admin.roles.write", Description: "管理员管理角色", Resource: "admin.roles", Action: "write"},
		{Name: "super.admin", Description: "超级管理员权限", Resource: "super", Action: "admin"},
	}

	for _, permission := range defaultPermissions {
		var existingPermission models.Permission
		if err := db.Where("name = ?", permission.Name).First(&existingPermission).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				if err := db.Create(&permission).Error; err != nil {
					return err
				}
				logger.Info("Created default permission", zap.String("permission", permission.Name))
			} else {
				return err
			}
		}
	}

	return nil
}

// initializeSuperAdmin 初始化超级管理员
func initializeSuperAdmin(db *gorm.DB, cfg *config.Config, logger *zap.Logger) error {
	// 检查是否已存在超级管理员
	var superAdminCount int64
	if err := db.Model(&models.User{}).Where("default_role = ?", models.UserRoleSuperAdmin).Count(&superAdminCount).Error; err != nil {
		return err
	}

	if superAdminCount > 0 {
		logger.Info("Super admin already exists")
		return nil
	}

	// 从配置读取超级管理员信息
	adminEmail := cfg.SuperAdmin.Email
	adminUsername := cfg.SuperAdmin.Username
	adminPassword := cfg.SuperAdmin.Password

	// 创建超级管理员用户
	hashedPassword, err := utils.HashPassword(adminPassword)
	if err != nil {
		return err
	}

	superAdmin := &models.User{
		Email:         adminEmail,
		Username:      adminUsername,
		PasswordHash:  &hashedPassword,
		EmailVerified: true,
		Status:        models.UserStatusActive,
		DefaultRole:   models.UserRoleSuperAdmin,
	}

	if err := db.Create(superAdmin).Error; err != nil {
		return err
	}

	// 创建用户配置
	profile := &models.UserProfile{
		UserID:   superAdmin.ID,
		Timezone: "UTC",
		Preferences: models.UserPreferences{
			Language: "en-US",
			Theme:    "light",
			Notifications: models.NotificationSettings{
				Email: true,
				Push:  true,
			},
		},
	}

	if err := db.Create(profile).Error; err != nil {
		return err
	}

	logger.Info("Super admin created successfully", 
		zap.String("email", adminEmail),
		zap.String("username", adminUsername))

	return nil
}