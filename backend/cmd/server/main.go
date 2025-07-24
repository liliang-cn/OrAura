package main

import (
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
	"go.uber.org/zap"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
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
	)
	if err != nil {
		zapLogger.Fatal("cannot migrate database", zap.Error(err))
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

	// 初始化服务层
	userService := services.NewUserService(userRepo, jwtManager, zapLogger)

	// 初始化处理器
	userHandler := handlers.NewUserHandler(userService, validate, zapLogger)

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