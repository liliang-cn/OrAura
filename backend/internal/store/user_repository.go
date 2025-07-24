package store

import (
	"context"
	"errors"
	"time"

	"github.com/OrAura/backend/internal/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// UserRepository 用户仓储接口
type UserRepository interface {
	// 用户基本操作
	CreateUser(ctx context.Context, user *models.User) error
	GetUserByID(ctx context.Context, id uuid.UUID) (*models.User, error)
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
	GetUserByUsername(ctx context.Context, username string) (*models.User, error)
	GetUserByOAuth(ctx context.Context, provider, subject string) (*models.User, error)
	UpdateUser(ctx context.Context, user *models.User) error
	DeleteUser(ctx context.Context, id uuid.UUID) error
	ListUsers(ctx context.Context, query *models.UserListQuery) (*models.PaginatedResponse, error)
	
	// 用户配置操作
	CreateUserProfile(ctx context.Context, profile *models.UserProfile) error
	GetUserProfile(ctx context.Context, userID uuid.UUID) (*models.UserProfile, error)
	UpdateUserProfile(ctx context.Context, profile *models.UserProfile) error
	
	// 刷新令牌操作
	CreateRefreshToken(ctx context.Context, token *models.RefreshToken) error
	GetRefreshToken(ctx context.Context, tokenHash string) (*models.RefreshToken, error)
	UpdateRefreshToken(ctx context.Context, token *models.RefreshToken) error
	DeleteRefreshToken(ctx context.Context, tokenHash string) error
	DeleteUserRefreshTokens(ctx context.Context, userID uuid.UUID) error
	DeleteAllRefreshTokens(ctx context.Context, userID uuid.UUID) error  // 添加此方法
	CleanExpiredRefreshTokens(ctx context.Context) error
	
	// JWT 黑名单操作
	AddToJWTBlacklist(ctx context.Context, blacklist *models.JWTBlacklist) error
	IsJWTBlacklisted(ctx context.Context, tokenHash string) (bool, error)
	IsTokenBlacklisted(ctx context.Context, token string) (bool, error)  // 添加此方法
	BlacklistToken(ctx context.Context, token string, userID uuid.UUID, expiresAt time.Time) error  // 添加此方法
	CleanExpiredJWTBlacklist(ctx context.Context) error
	
	// 密码重置令牌操作
	CreatePasswordResetToken(ctx context.Context, token *models.PasswordResetToken) error
	GetPasswordResetToken(ctx context.Context, tokenHash string) (*models.PasswordResetToken, error)
	UpdatePasswordResetToken(ctx context.Context, token *models.PasswordResetToken) error
	DeletePasswordResetToken(ctx context.Context, tokenHash string) error
	DeleteUserPasswordResetTokens(ctx context.Context, userID uuid.UUID) error
	CleanExpiredPasswordResetTokens(ctx context.Context) error
	
	// 登录日志操作
	CreateLoginLog(ctx context.Context, log *models.UserLoginLog) error
	GetUserLoginLogs(ctx context.Context, query *models.LoginLogQuery) (*models.PaginatedResponse, error)
	
	// 邮箱验证操作
	CreateEmailVerification(ctx context.Context, verification *models.EmailVerification) error
	GetEmailVerificationByToken(ctx context.Context, token string) (*models.EmailVerification, error)
	DeleteEmailVerification(ctx context.Context, id uuid.UUID) error
	DeleteEmailVerificationByUserID(ctx context.Context, userID uuid.UUID) error
	CleanExpiredEmailVerifications(ctx context.Context) error
	
	// 角色权限操作
	GetRoleByName(ctx context.Context, name models.UserRole) (*models.Role, error)
	GetRoleByID(ctx context.Context, id uuid.UUID) (*models.Role, error)
	GetAllRoles(ctx context.Context) ([]*models.Role, error)
	CreateRole(ctx context.Context, role *models.Role) error
	UpdateRole(ctx context.Context, role *models.Role) error
	DeleteRole(ctx context.Context, id uuid.UUID) error
	
	GetPermissionByName(ctx context.Context, name string) (*models.Permission, error)
	GetAllPermissions(ctx context.Context) ([]*models.Permission, error)
	CreatePermission(ctx context.Context, permission *models.Permission) error
	
	AssignRoleToUser(ctx context.Context, assignment *models.UserRoleAssignment) error
	RevokeRoleFromUser(ctx context.Context, userID, roleID uuid.UUID) error
	GetUserRoles(ctx context.Context, userID uuid.UUID) ([]*models.Role, error)
	GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]*models.Permission, error)
	
	AssignPermissionToRole(ctx context.Context, rolePermission *models.RolePermission) error
	RevokePermissionFromRole(ctx context.Context, roleID, permissionID uuid.UUID) error
	GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]*models.Permission, error)
	
	// 统计操作
	GetAdminDashboardStats(ctx context.Context) (*models.AdminStatsResponse, error)
	GetSystemHealth(ctx context.Context) (*models.SystemHealthResponse, error)
	CountUsers(ctx context.Context) (int64, error)
	CountActiveUsers(ctx context.Context, since time.Time) (int64, error)
}

// userRepository 用户仓储实现
type userRepository struct {
	db *gorm.DB
}

// NewUserRepository 创建用户仓储
func NewUserRepository(db *gorm.DB) UserRepository {
	return &userRepository{db: db}
}

// 用户基本操作实现

func (r *userRepository) CreateUser(ctx context.Context, user *models.User) error {
	return r.db.WithContext(ctx).Create(user).Error
}

func (r *userRepository) GetUserByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	var user models.User
	err := r.db.WithContext(ctx).
		Preload("Profile").
		Preload("RoleAssignments.Role").
		First(&user, "id = ?", id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

func (r *userRepository) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User
	err := r.db.WithContext(ctx).Preload("Profile").First(&user, "email = ?", email).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

func (r *userRepository) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	var user models.User
	err := r.db.WithContext(ctx).Preload("Profile").First(&user, "username = ?", username).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

func (r *userRepository) GetUserByOAuth(ctx context.Context, provider, subject string) (*models.User, error) {
	var user models.User
	err := r.db.WithContext(ctx).Preload("Profile").First(&user, "oauth_provider = ? AND oauth_subject = ?", provider, subject).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

func (r *userRepository) UpdateUser(ctx context.Context, user *models.User) error {
	return r.db.WithContext(ctx).Save(user).Error
}

func (r *userRepository) DeleteUser(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Delete(&models.User{}, "id = ?", id).Error
}

// ListUsers 列出用户
func (r *userRepository) ListUsers(ctx context.Context, query *models.UserListQuery) (*models.PaginatedResponse, error) {
	var users []*models.AdminUserInfo
	var total int64

	db := r.db.WithContext(ctx).Model(&models.User{}) 

	// 构建查询
	if query.Search != "" {
		search := "%" + query.Search + "%"
		db = db.Where("username LIKE ? OR email LIKE ?", search, search)
	}
	if query.Status != nil {
		db = db.Where("status = ?", *query.Status)
	}
	if query.Role != nil {
		db = db.Joins("JOIN user_role_assignments ON users.id = user_role_assignments.user_id").
			Joins("JOIN roles ON user_role_assignments.role_id = roles.id").
			Where("roles.name = ?", *query.Role)
	}

	// 计算总数
	if err := db.Count(&total).Error; err != nil {
		return nil, err
	}

	// 分页和排序
	db = db.Offset((query.Page - 1) * query.PerPage).Limit(query.PerPage)
	if query.SortBy != "" {
		order := "ASC"
		if query.SortDesc {
			order = "DESC"
		}
		db = db.Order(query.SortBy + " " + order)
	} else {
		db = db.Order("created_at DESC")
	}

	if err := db.Find(&users).Error; err != nil {
		return nil, err
	}

	return &models.PaginatedResponse{
		Data: users,
		Pagination: &models.Pagination{
			Page:       query.Page,
			PageSize:   query.PerPage,
			Total:      total,
			TotalPages: (int(total) + query.PerPage - 1) / query.PerPage,
		},
	}, nil
}

// 用户配置操作实现

func (r *userRepository) CreateUserProfile(ctx context.Context, profile *models.UserProfile) error {
	return r.db.WithContext(ctx).Create(profile).Error
}

func (r *userRepository) GetUserProfile(ctx context.Context, userID uuid.UUID) (*models.UserProfile, error) {
	var profile models.UserProfile
	err := r.db.WithContext(ctx).First(&profile, "user_id = ?", userID).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &profile, nil
}

func (r *userRepository) UpdateUserProfile(ctx context.Context, profile *models.UserProfile) error {
	return r.db.WithContext(ctx).Save(profile).Error
}

// 刷新令牌操作实现

func (r *userRepository) CreateRefreshToken(ctx context.Context, token *models.RefreshToken) error {
	return r.db.WithContext(ctx).Create(token).Error
}

func (r *userRepository) GetRefreshToken(ctx context.Context, tokenHash string) (*models.RefreshToken, error) {
	var token models.RefreshToken
	err := r.db.WithContext(ctx).First(&token, "token_hash = ? AND is_revoked = false AND expires_at > ?", tokenHash, time.Now()).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &token, nil
}

func (r *userRepository) UpdateRefreshToken(ctx context.Context, token *models.RefreshToken) error {
	return r.db.WithContext(ctx).Save(token).Error
}

func (r *userRepository) DeleteRefreshToken(ctx context.Context, tokenHash string) error {
	return r.db.WithContext(ctx).Delete(&models.RefreshToken{}, "token_hash = ?", tokenHash).Error
}

func (r *userRepository) DeleteUserRefreshTokens(ctx context.Context, userID uuid.UUID) error {
	return r.db.WithContext(ctx).Delete(&models.RefreshToken{}, "user_id = ?", userID).Error
}

func (r *userRepository) CleanExpiredRefreshTokens(ctx context.Context) error {
	return r.db.WithContext(ctx).Delete(&models.RefreshToken{}, "expires_at < ?", time.Now()).Error
}

// JWT 黑名单操作实现

func (r *userRepository) AddToJWTBlacklist(ctx context.Context, blacklist *models.JWTBlacklist) error {
	return r.db.WithContext(ctx).Create(blacklist).Error
}

func (r *userRepository) IsJWTBlacklisted(ctx context.Context, tokenHash string) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&models.JWTBlacklist{}).Where("token_hash = ? AND expires_at > ?", tokenHash, time.Now()).Count(&count).Error
	return count > 0, err
}

func (r *userRepository) CleanExpiredJWTBlacklist(ctx context.Context) error {
	return r.db.WithContext(ctx).Delete(&models.JWTBlacklist{}, "expires_at < ?", time.Now()).Error
}

// 密码重置令牌操作实现

func (r *userRepository) CreatePasswordResetToken(ctx context.Context, token *models.PasswordResetToken) error {
	return r.db.WithContext(ctx).Create(token).Error
}

func (r *userRepository) GetPasswordResetToken(ctx context.Context, tokenHash string) (*models.PasswordResetToken, error) {
	var token models.PasswordResetToken
	err := r.db.WithContext(ctx).First(&token, "token_hash = ? AND is_used = false AND expires_at > ?", tokenHash, time.Now()).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &token, nil
}

func (r *userRepository) UpdatePasswordResetToken(ctx context.Context, token *models.PasswordResetToken) error {
	return r.db.WithContext(ctx).Save(token).Error
}

func (r *userRepository) DeletePasswordResetToken(ctx context.Context, tokenHash string) error {
	return r.db.WithContext(ctx).Delete(&models.PasswordResetToken{}, "token_hash = ?", tokenHash).Error
}

func (r *userRepository) DeleteUserPasswordResetTokens(ctx context.Context, userID uuid.UUID) error {
	return r.db.WithContext(ctx).Delete(&models.PasswordResetToken{}, "user_id = ?", userID).Error
}

func (r *userRepository) CleanExpiredPasswordResetTokens(ctx context.Context) error {
	return r.db.WithContext(ctx).Delete(&models.PasswordResetToken{}, "expires_at < ?", time.Now()).Error
}

// 登录日志操作实现

func (r *userRepository) CreateLoginLog(ctx context.Context, log *models.UserLoginLog) error {
	return r.db.WithContext(ctx).Create(log).Error
}

// GetUserLoginLogs 获取用户登录日志
func (r *userRepository) GetUserLoginLogs(ctx context.Context, query *models.LoginLogQuery) (*models.PaginatedResponse, error) {
	var logs []models.UserLoginLog
	var total int64

	db := r.db.WithContext(ctx).Model(&models.UserLoginLog{})

	// 构建查询
	if query.UserID != nil {
		db = db.Where("user_id = ?", *query.UserID)
	}
	if query.IPAddress != "" {
		db = db.Where("ip_address = ?", query.IPAddress)
	}
	if query.Success != nil {
		db = db.Where("success = ?", *query.Success)
	}
	if query.StartDate != nil {
		db = db.Where("created_at >= ?", *query.StartDate)
	}
	if query.EndDate != nil {
		db = db.Where("created_at <= ?", *query.EndDate)
	}

	// 计算总数
	if err := db.Count(&total).Error; err != nil {
		return nil, err
	}

	// 分页和排序
	db = db.Offset((query.Page - 1) * query.PerPage).Limit(query.PerPage)
	order := "ASC"
	if query.SortDesc {
		order = "DESC"
	}
	db = db.Order("created_at " + order)

	if err := db.Find(&logs).Error; err != nil {
		return nil, err
	}

	return &models.PaginatedResponse{
		Data: logs,
		Pagination: &models.Pagination{
			Page:       query.Page,
			PageSize:   query.PerPage,
			Total:      total,
			TotalPages: (int(total) + query.PerPage - 1) / query.PerPage,
		},
	}, nil
}

// 统计操作实现

func (r *userRepository) CountUsers(ctx context.Context) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&models.User{}).Where("status = ?", models.UserStatusActive).Count(&count).Error
	return count, err
}

func (r *userRepository) CountActiveUsers(ctx context.Context, since time.Time) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).
		Table("users").
		Joins("JOIN user_login_logs ON users.id = user_login_logs.user_id").
		Where("users.status = ? AND user_login_logs.created_at > ? AND user_login_logs.success = true", models.UserStatusActive, since).
		Distinct("users.id").
		Count(&count).Error
	return count, err
}

// GetAdminDashboardStats 获取管理员仪表板统计信息
func (r *userRepository) GetAdminDashboardStats(ctx context.Context) (*models.AdminStatsResponse, error) {
	var stats models.AdminStatsResponse

	// 获取总用户数
	if err := r.db.WithContext(ctx).Model(&models.User{}).Count(&stats.TotalUsers).Error; err != nil {
		return nil, err
	}

	// 获取活跃用户数（过去30天内登录过的）
	if err := r.db.WithContext(ctx).Model(&models.User{}).Where("last_login_at > ?", time.Now().AddDate(0, -1, 0)).Count(&stats.ActiveUsers).Error; err != nil {
		return nil, err
	}

	// 获取会员用户数
	if err := r.db.WithContext(ctx).Model(&models.User{}).Where("default_role = ?", models.UserRoleMember).Count(&stats.MemberUsers).Error; err != nil {
		return nil, err
	}

	// 获取管理员用户数
	if err := r.db.WithContext(ctx).Model(&models.User{}).Where("default_role = ?", models.UserRoleAdmin).Count(&stats.AdminUsers).Error; err != nil {
		return nil, err
	}

	// 获取今日新增用户
	today := time.Now().Truncate(24 * time.Hour)
	if err := r.db.WithContext(ctx).Model(&models.User{}).Where("created_at >= ?", today).Count(&stats.NewUsersToday).Error; err != nil {
		return nil, err
	}

	// 获取本周新增用户
	startOfWeek := today.AddDate(0, 0, -int(today.Weekday()))
	if err := r.db.WithContext(ctx).Model(&models.User{}).Where("created_at >= ?", startOfWeek).Count(&stats.NewUsersWeek).Error; err != nil {
		return nil, err
	}

	// 获取本月新增用户
	startOfMonth := time.Date(today.Year(), today.Month(), 1, 0, 0, 0, 0, today.Location())
	if err := r.db.WithContext(ctx).Model(&models.User{}).Where("created_at >= ?", startOfMonth).Count(&stats.NewUsersMonth).Error; err != nil {
		return nil, err
	}

	return &stats, nil
}

// GetSystemHealth 获取系统健康状况
func (r *userRepository) GetSystemHealth(ctx context.Context) (*models.SystemHealthResponse, error) {
	health := &models.SystemHealthResponse{
		Status:    "healthy",
		Timestamp: time.Now(),
		Services:  make(map[string]models.ServiceHealth),
	}

	// 检查数据库
	db, err := r.db.DB()
	if err != nil {
		health.Status = "unhealthy"
		health.Services["database"] = models.ServiceHealth{
			Status:    "unhealthy",
			Message:   "Failed to get database instance: " + err.Error(),
			CheckedAt: time.Now(),
		}
		return health, nil // 返回部分健康信息
	}

	if err := db.PingContext(ctx); err != nil {
		health.Status = "unhealthy"
		health.Services["database"] = models.ServiceHealth{
			Status:    "unhealthy",
			Message:   "Database ping failed: " + err.Error(),
			CheckedAt: time.Now(),
		}
	} else {
		health.Services["database"] = models.ServiceHealth{
			Status:    "healthy",
			Message:   "Database connection is stable",
			CheckedAt: time.Now(),
		}
	}

	// TODO: 检查其他服务，例如 Redis, Email 等

	return health, nil
}

// 邮箱验证操作实现

func (r *userRepository) CreateEmailVerification(ctx context.Context, verification *models.EmailVerification) error {
	return r.db.WithContext(ctx).Create(verification).Error
}

func (r *userRepository) GetEmailVerificationByToken(ctx context.Context, token string) (*models.EmailVerification, error) {
	var verification models.EmailVerification
	err := r.db.WithContext(ctx).Where("token = ?", token).First(&verification).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &verification, nil
}

func (r *userRepository) DeleteEmailVerification(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Delete(&models.EmailVerification{}, "id = ?", id).Error
}

func (r *userRepository) DeleteEmailVerificationByUserID(ctx context.Context, userID uuid.UUID) error {
	return r.db.WithContext(ctx).Delete(&models.EmailVerification{}, "user_id = ?", userID).Error
}

func (r *userRepository) CleanExpiredEmailVerifications(ctx context.Context) error {
	return r.db.WithContext(ctx).
		Where("expires_at < ?", time.Now()).
		Delete(&models.EmailVerification{}).Error
}

// 添加缺失的方法实现

func (r *userRepository) DeleteAllRefreshTokens(ctx context.Context, userID uuid.UUID) error {
	return r.db.WithContext(ctx).Delete(&models.RefreshToken{}, "user_id = ?", userID).Error
}

func (r *userRepository) IsTokenBlacklisted(ctx context.Context, token string) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&models.JWTBlacklist{}).
		Where("token_hash = ? AND expires_at > ?", token, time.Now()).
		Count(&count).Error
	return count > 0, err
}

func (r *userRepository) BlacklistToken(ctx context.Context, token string, userID uuid.UUID, expiresAt time.Time) error {
	blacklist := &models.JWTBlacklist{
		TokenHash: token,
		UserID:    userID,
		ExpiresAt: expiresAt,
	}
	return r.db.WithContext(ctx).Create(blacklist).Error
}

// 角色权限操作实现

func (r *userRepository) GetRoleByName(ctx context.Context, name models.UserRole) (*models.Role, error) {
	var role models.Role
	err := r.db.WithContext(ctx).
		Preload("RolePermissions.Permission").
		First(&role, "name = ?", name).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &role, nil
}

func (r *userRepository) GetRoleByID(ctx context.Context, id uuid.UUID) (*models.Role, error) {
	var role models.Role
	err := r.db.WithContext(ctx).
		Preload("RolePermissions.Permission").
		First(&role, "id = ?", id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &role, nil
}

func (r *userRepository) GetAllRoles(ctx context.Context) ([]*models.Role, error) {
	var roles []*models.Role
	err := r.db.WithContext(ctx).
		Preload("RolePermissions.Permission").
		Where("is_active = ?", true).
		Order("level ASC").
		Find(&roles).Error
	return roles, err
}

func (r *userRepository) CreateRole(ctx context.Context, role *models.Role) error {
	return r.db.WithContext(ctx).Create(role).Error
}

func (r *userRepository) UpdateRole(ctx context.Context, role *models.Role) error {
	return r.db.WithContext(ctx).Save(role).Error
}

func (r *userRepository) DeleteRole(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// 删除角色权限关联
		if err := tx.Delete(&models.RolePermission{}, "role_id = ?", id).Error; err != nil {
			return err
		}
		// 删除用户角色分配
		if err := tx.Delete(&models.UserRoleAssignment{}, "role_id = ?", id).Error; err != nil {
			return err
		}
		// 删除角色
		return tx.Delete(&models.Role{}, "id = ? AND is_system = false", id).Error
	})
}

func (r *userRepository) GetPermissionByName(ctx context.Context, name string) (*models.Permission, error) {
	var permission models.Permission
	err := r.db.WithContext(ctx).First(&permission, "name = ?", name).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &permission, nil
}

func (r *userRepository) GetAllPermissions(ctx context.Context) ([]*models.Permission, error) {
	var permissions []*models.Permission
	err := r.db.WithContext(ctx).Order("resource, action").Find(&permissions).Error
	return permissions, err
}

func (r *userRepository) CreatePermission(ctx context.Context, permission *models.Permission) error {
	return r.db.WithContext(ctx).Create(permission).Error
}

func (r *userRepository) AssignRoleToUser(ctx context.Context, assignment *models.UserRoleAssignment) error {
	// 检查是否已存在相同的分配
	var existing models.UserRoleAssignment
	err := r.db.WithContext(ctx).First(&existing, "user_id = ? AND role_id = ? AND is_active = true", 
		assignment.UserID, assignment.RoleID).Error
	
	if err == nil {
		// 已存在，更新过期时间
		existing.ExpiresAt = assignment.ExpiresAt
		existing.GrantedBy = assignment.GrantedBy
		return r.db.WithContext(ctx).Save(&existing).Error
	}
	
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	
	// 不存在，创建新分配
	return r.db.WithContext(ctx).Create(assignment).Error
}

func (r *userRepository) RevokeRoleFromUser(ctx context.Context, userID, roleID uuid.UUID) error {
	return r.db.WithContext(ctx).
		Model(&models.UserRoleAssignment{}).
		Where("user_id = ? AND role_id = ?", userID, roleID).
		Update("is_active", false).Error
}

func (r *userRepository) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]*models.Role, error) {
	var roles []*models.Role
	err := r.db.WithContext(ctx).
		Joins("JOIN user_role_assignments ON roles.id = user_role_assignments.role_id").
		Where("user_role_assignments.user_id = ? AND user_role_assignments.is_active = true", userID).
		Where("user_role_assignments.expires_at IS NULL OR user_role_assignments.expires_at > ?", time.Now()).
		Preload("RolePermissions.Permission").
		Find(&roles).Error
	return roles, err
}

func (r *userRepository) GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]*models.Permission, error) {
	var permissions []*models.Permission
	
	// 获取用户通过角色获得的权限
	err := r.db.WithContext(ctx).
		Joins(`JOIN role_permissions ON permissions.id = role_permissions.permission_id`).
		Joins(`JOIN user_role_assignments ON role_permissions.role_id = user_role_assignments.role_id`).
		Where(`user_role_assignments.user_id = ? AND user_role_assignments.is_active = true`, userID).
		Where(`user_role_assignments.expires_at IS NULL OR user_role_assignments.expires_at > ?`, time.Now()).
		Distinct().
		Find(&permissions).Error
	
	return permissions, err
}

func (r *userRepository) AssignPermissionToRole(ctx context.Context, rolePermission *models.RolePermission) error {
	// 检查是否已存在
	var existing models.RolePermission
	err := r.db.WithContext(ctx).First(&existing, "role_id = ? AND permission_id = ?", 
		rolePermission.RoleID, rolePermission.PermissionID).Error
	
	if err == nil {
		// 已存在，无需操作
		return nil
	}
	
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	
	// 不存在，创建新关联
	return r.db.WithContext(ctx).Create(rolePermission).Error
}

func (r *userRepository) RevokePermissionFromRole(ctx context.Context, roleID, permissionID uuid.UUID) error {
	return r.db.WithContext(ctx).
		Delete(&models.RolePermission{}, "role_id = ? AND permission_id = ?", roleID, permissionID).Error
}

func (r *userRepository) GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]*models.Permission, error) {
	var permissions []*models.Permission
	err := r.db.WithContext(ctx).
		Joins("JOIN role_permissions ON permissions.id = role_permissions.permission_id").
		Where("role_permissions.role_id = ?", roleID).
		Find(&permissions).Error
	return permissions, err
}