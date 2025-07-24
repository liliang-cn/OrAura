package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/OrAura/backend/internal/models"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// UserRepositoryTestSuite 用户仓储测试套件
type UserRepositoryTestSuite struct {
	suite.Suite
	db   *gorm.DB
	repo UserRepository
}

// SetupSuite 设置测试套件
func (suite *UserRepositoryTestSuite) SetupSuite() {
	// 使用SQLite内存数据库进行测试
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	assert.NoError(suite.T(), err)

	// 自动迁移数据库表
	err = db.AutoMigrate(
		&models.User{},
		&models.UserProfile{},
		&models.Role{},
		&models.Permission{},
		&models.RolePermission{},
		&models.UserRoleAssignment{},
		&models.RefreshToken{},
		&models.JWTBlacklist{},
		&models.PasswordResetToken{},
		&models.UserLoginLog{},
		&models.EmailVerification{},
		&models.APIToken{},
		&models.UserSession{},
	)
	assert.NoError(suite.T(), err)

	suite.db = db
	suite.repo = NewUserRepository(db)
}

// TearDownSuite 清理测试套件
func (suite *UserRepositoryTestSuite) TearDownSuite() {
	sqlDB, _ := suite.db.DB()
	sqlDB.Close()
}

// SetupTest 每个测试前的设置
func (suite *UserRepositoryTestSuite) SetupTest() {
	// 清理所有表的数据
	suite.db.Exec("DELETE FROM user_role_assignments")
	suite.db.Exec("DELETE FROM role_permissions")
	suite.db.Exec("DELETE FROM user_profiles")
	suite.db.Exec("DELETE FROM refresh_tokens")
	suite.db.Exec("DELETE FROM jwt_blacklist")
	suite.db.Exec("DELETE FROM password_reset_tokens")
	suite.db.Exec("DELETE FROM user_login_logs")
	suite.db.Exec("DELETE FROM email_verifications")
	suite.db.Exec("DELETE FROM api_tokens")
	suite.db.Exec("DELETE FROM user_sessions")
	suite.db.Exec("DELETE FROM users")
	suite.db.Exec("DELETE FROM roles")
	suite.db.Exec("DELETE FROM permissions")
}

// TestCreateAndGetUser 测试创建和获取用户
func (suite *UserRepositoryTestSuite) TestCreateAndGetUser() {
	ctx := context.Background()
	
	user := &models.User{
		ID:       uuid.New(),
		Email:    "test@example.com",
		Username: "testuser",
		Status:   models.UserStatusActive,
		CreateTime: time.Now(),
		UpdateTime: time.Now(),
	}
	
	// 测试创建用户
	err := suite.repo.CreateUser(ctx, user)
	assert.NoError(suite.T(), err)
	
	// 测试通过ID获取用户
	retrievedUser, err := suite.repo.GetUserByID(ctx, user.ID)
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), retrievedUser)
	assert.Equal(suite.T(), user.Email, retrievedUser.Email)
	assert.Equal(suite.T(), user.Username, retrievedUser.Username)
	
	// 测试通过邮箱获取用户
	retrievedUser, err = suite.repo.GetUserByEmail(ctx, user.Email)
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), retrievedUser)
	assert.Equal(suite.T(), user.ID, retrievedUser.ID)
	
	// 测试通过用户名获取用户
	retrievedUser, err = suite.repo.GetUserByUsername(ctx, user.Username)
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), retrievedUser)
	assert.Equal(suite.T(), user.ID, retrievedUser.ID)
}

// TestUpdateUser 测试更新用户
func (suite *UserRepositoryTestSuite) TestUpdateUser() {
	ctx := context.Background()
	
	user := &models.User{
		ID:       uuid.New(),
		Email:    "test@example.com",
		Username: "testuser",
		Status:   models.UserStatusActive,
		CreateTime: time.Now(),
		UpdateTime: time.Now(),
	}
	
	// 创建用户
	err := suite.repo.CreateUser(ctx, user)
	assert.NoError(suite.T(), err)
	
	// 更新用户信息
	user.Username = "newtestuser"
	user.Status = models.UserStatusSuspended
	user.UpdateTime = time.Now()
	
	err = suite.repo.UpdateUser(ctx, user)
	assert.NoError(suite.T(), err)
	
	// 验证更新
	retrievedUser, err := suite.repo.GetUserByID(ctx, user.ID)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), "newtestuser", retrievedUser.Username)
	assert.Equal(suite.T(), models.UserStatusSuspended, retrievedUser.Status)
}

// TestDeleteUser 测试删除用户
func (suite *UserRepositoryTestSuite) TestDeleteUser() {
	ctx := context.Background()
	
	user := &models.User{
		ID:       uuid.New(),
		Email:    "test@example.com",
		Username: "testuser",
		Status:   models.UserStatusActive,
		CreateTime: time.Now(),
		UpdateTime: time.Now(),
	}
	
	// 创建用户
	err := suite.repo.CreateUser(ctx, user)
	assert.NoError(suite.T(), err)
	
	// 删除用户
	err = suite.repo.DeleteUser(ctx, user.ID)
	assert.NoError(suite.T(), err)
	
	// 验证用户已删除
	retrievedUser, err := suite.repo.GetUserByID(ctx, user.ID)
	assert.Error(suite.T(), err) // 应该返回错误
	assert.Nil(suite.T(), retrievedUser)
}

// TestUserProfile 测试用户配置管理
func (suite *UserRepositoryTestSuite) TestUserProfile() {
	ctx := context.Background()
	
	userID := uuid.New()
	user := &models.User{
		ID:       userID,
		Email:    "test@example.com",
		Username: "testuser",
		Status:   models.UserStatusActive,
		CreateTime: time.Now(),
		UpdateTime: time.Now(),
	}
	
	// 创建用户
	err := suite.repo.CreateUser(ctx, user)
	assert.NoError(suite.T(), err)
	
	profile := &models.UserProfile{
		ID:       uuid.New(),
		UserID:   userID,
		Timezone: "UTC",
		Preferences: models.UserPreferences{
			Language: "en-US",
			Theme:    "light",
		},
		CreateTime: time.Now(),
		UpdateTime: time.Now(),
	}
	
	// 创建用户配置
	err = suite.repo.CreateUserProfile(ctx, profile)
	assert.NoError(suite.T(), err)
	
	// 获取用户配置
	retrievedProfile, err := suite.repo.GetUserProfile(ctx, userID)
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), retrievedProfile)
	assert.Equal(suite.T(), profile.Timezone, retrievedProfile.Timezone)
	assert.Equal(suite.T(), profile.Preferences.Language, retrievedProfile.Preferences.Language)
	
	// 更新用户配置
	retrievedProfile.Timezone = "America/New_York"
	retrievedProfile.Preferences.Theme = "dark"
	retrievedProfile.UpdateTime = time.Now()
	
	err = suite.repo.UpdateUserProfile(ctx, retrievedProfile)
	assert.NoError(suite.T(), err)
	
	// 验证更新
	updatedProfile, err := suite.repo.GetUserProfile(ctx, userID)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), "America/New_York", updatedProfile.Timezone)
	assert.Equal(suite.T(), "dark", updatedProfile.Preferences.Theme)
}

// TestRoleManagement 测试角色管理
func (suite *UserRepositoryTestSuite) TestRoleManagement() {
	ctx := context.Background()
	
	// 创建角色
	role := &models.Role{
		ID:          uuid.New(),
		Name:        "admin",
		DisplayName: "管理员",
		Description: "系统管理员",
		Level:       20,
		IsSystem:    true,
		IsActive:    true,
		CreateTime:  time.Now(),
		UpdateTime:  time.Now(),
	}
	
	err := suite.db.Create(role).Error
	assert.NoError(suite.T(), err)
	
	// 测试通过名称获取角色
	retrievedRole, err := suite.repo.GetRoleByName(ctx, "admin")
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), retrievedRole)
	assert.Equal(suite.T(), role.DisplayName, retrievedRole.DisplayName)
	
	// 测试通过ID获取角色
	retrievedRole, err = suite.repo.GetRoleByID(ctx, role.ID)
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), retrievedRole)
	assert.Equal(suite.T(), role.Name, retrievedRole.Name)
}

// TestUserRoleAssignment 测试用户角色分配
func (suite *UserRepositoryTestSuite) TestUserRoleAssignment() {
	ctx := context.Background()
	
	// 创建用户
	userID := uuid.New()
	user := &models.User{
		ID:         userID,
		Email:      "test@example.com",
		Username:   "testuser",
		Status:     models.UserStatusActive,
		CreateTime: time.Now(),
		UpdateTime: time.Now(),
	}
	err := suite.repo.CreateUser(ctx, user)
	assert.NoError(suite.T(), err)
	
	// 创建角色
	roleID := uuid.New()
	role := &models.Role{
		ID:          roleID,
		Name:        "admin",
		DisplayName: "管理员",
		Level:       20,
		IsSystem:    true,
		IsActive:    true,
		CreateTime:  time.Now(),
		UpdateTime:  time.Now(),
	}
	err = suite.db.Create(role).Error
	assert.NoError(suite.T(), err)
	
	// 分配角色给用户
	assignment := &models.UserRoleAssignment{
		ID:         uuid.New(),
		UserID:     userID,
		RoleID:     roleID,
		GrantedBy:  userID, // 自己分配给自己（测试场景）
		IsActive:   true,
		CreateTime: time.Now(),
		UpdateTime: time.Now(),
	}
	
	err = suite.repo.AssignRoleToUser(ctx, assignment)
	assert.NoError(suite.T(), err)
	
	// 获取用户角色
	roles, err := suite.repo.GetUserRoles(ctx, userID)
	assert.NoError(suite.T(), err)
	assert.Len(suite.T(), roles, 1)
	assert.Equal(suite.T(), role.Name, roles[0].Name)
	
	// 撤销用户角色
	err = suite.repo.RevokeRoleFromUser(ctx, userID, roleID)
	assert.NoError(suite.T(), err)
	
	// 验证角色已撤销
	roles, err = suite.repo.GetUserRoles(ctx, userID)
	assert.NoError(suite.T(), err)
	assert.Len(suite.T(), roles, 0)
}

// TestRefreshToken 测试刷新令牌管理
func (suite *UserRepositoryTestSuite) TestRefreshToken() {
	ctx := context.Background()
	
	userID := uuid.New()
	user := &models.User{
		ID:         userID,
		Email:      "test@example.com",
		Username:   "testuser",
		Status:     models.UserStatusActive,
		CreateTime: time.Now(),
		UpdateTime: time.Now(),
	}
	err := suite.repo.CreateUser(ctx, user)
	assert.NoError(suite.T(), err)
	
	tokenHash := "test-token-hash"
	refreshToken := &models.RefreshToken{
		ID:         uuid.New(),
		UserID:     userID,
		TokenHash:  tokenHash,
		ExpiresAt:  time.Now().Add(24 * time.Hour),
		IsActive:   true,
		CreateTime: time.Now(),
		UpdateTime: time.Now(),
	}
	
	// 创建刷新令牌
	err = suite.repo.CreateRefreshToken(ctx, refreshToken)
	assert.NoError(suite.T(), err)
	
	// 获取刷新令牌
	retrievedToken, err := suite.repo.GetRefreshToken(ctx, tokenHash)
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), retrievedToken)
	assert.Equal(suite.T(), userID, retrievedToken.UserID)
	
	// 更新刷新令牌
	retrievedToken.IsActive = false
	retrievedToken.UpdateTime = time.Now()
	
	err = suite.repo.UpdateRefreshToken(ctx, retrievedToken)
	assert.NoError(suite.T(), err)
	
	// 验证更新
	updatedToken, err := suite.repo.GetRefreshToken(ctx, tokenHash)
	assert.NoError(suite.T(), err)
	assert.False(suite.T(), updatedToken.IsActive)
	
	// 删除刷新令牌
	err = suite.repo.DeleteRefreshToken(ctx, tokenHash)
	assert.NoError(suite.T(), err)
	
	// 验证删除
	deletedToken, err := suite.repo.GetRefreshToken(ctx, tokenHash)
	assert.Error(suite.T(), err)
	assert.Nil(suite.T(), deletedToken)
}

// TestLoginLog 测试登录日志
func (suite *UserRepositoryTestSuite) TestLoginLog() {
	ctx := context.Background()
	
	userID := uuid.New()
	user := &models.User{
		ID:         userID,
		Email:      "test@example.com",
		Username:   "testuser",
		Status:     models.UserStatusActive,
		CreateTime: time.Now(),
		UpdateTime: time.Now(),
	}
	err := suite.repo.CreateUser(ctx, user)
	assert.NoError(suite.T(), err)
	
	loginLog := &models.UserLoginLog{
		ID:        uuid.New(),
		UserID:    userID,
		Email:     user.Email,
		IPAddress: "192.168.1.1",
		UserAgent: "Test Agent",
		Success:   true,
		CreateTime: time.Now(),
	}
	
	// 创建登录日志
	err = suite.repo.CreateLoginLog(ctx, loginLog)
	assert.NoError(suite.T(), err)
	
	// 获取用户登录日志
	logs, err := suite.repo.GetUserLoginLogs(ctx, userID, 10)
	assert.NoError(suite.T(), err)
	assert.Len(suite.T(), logs, 1)
	assert.Equal(suite.T(), loginLog.IPAddress, logs[0].IPAddress)
	assert.True(suite.T(), logs[0].Success)
}

// TestUserCounts 测试用户统计
func (suite *UserRepositoryTestSuite) TestUserCounts() {
	ctx := context.Background()
	
	// 创建多个用户
	for i := 0; i < 5; i++ {
		user := &models.User{
			ID:         uuid.New(),
			Email:      fmt.Sprintf("user%d@example.com", i),
			Username:   fmt.Sprintf("user%d", i),
			Status:     models.UserStatusActive,
			CreateTime: time.Now(),
			UpdateTime: time.Now(),
		}
		err := suite.repo.CreateUser(ctx, user)
		assert.NoError(suite.T(), err)
	}
	
	// 测试总用户数
	totalUsers, err := suite.repo.CountUsers(ctx)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), int64(5), totalUsers)
	
	// 测试活跃用户数
	since := time.Now().Add(-1 * time.Hour)
	activeUsers, err := suite.repo.CountActiveUsers(ctx, since)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), int64(5), activeUsers)
}

// 运行测试套件
func TestUserRepositoryTestSuite(t *testing.T) {
	suite.Run(t, new(UserRepositoryTestSuite))
}