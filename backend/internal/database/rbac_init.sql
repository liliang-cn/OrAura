-- RBAC系统初始化数据
-- 创建基础角色和权限

-- 插入基础角色
INSERT INTO roles (id, name, display_name, description, level, is_system, is_active) VALUES
    (gen_random_uuid(), 'regular', '普通用户', '系统注册的基础用户', 0, true, true),
    (gen_random_uuid(), 'member', '会员用户', '付费会员，享有高级功能', 10, true, true),
    (gen_random_uuid(), 'admin', '管理员', '系统管理员，可管理用户和内容', 20, true, true),
    (gen_random_uuid(), 'super_admin', '超级管理员', '系统超级管理员，拥有所有权限', 30, true, true)
ON CONFLICT (name) DO NOTHING;

-- 插入基础权限
INSERT INTO permissions (id, name, description, resource, action) VALUES
    -- 用户管理权限
    (gen_random_uuid(), 'users.read', '查看用户信息', 'users', 'read'),
    (gen_random_uuid(), 'users.update', '更新用户信息', 'users', 'update'),
    (gen_random_uuid(), 'users.delete', '删除用户', 'users', 'delete'),
    (gen_random_uuid(), 'users.list', '列出用户', 'users', 'list'),
    (gen_random_uuid(), 'users.create', '创建用户', 'users', 'create'),
    
    -- 内容管理权限
    (gen_random_uuid(), 'content.read', '查看内容', 'content', 'read'),
    (gen_random_uuid(), 'content.create', '创建内容', 'content', 'create'),
    (gen_random_uuid(), 'content.update', '更新内容', 'content', 'update'),
    (gen_random_uuid(), 'content.delete', '删除内容', 'content', 'delete'),
    
    -- 会员功能权限
    (gen_random_uuid(), 'member.premium_features', '访问高级功能', 'member', 'access_premium'),
    (gen_random_uuid(), 'member.exclusive_content', '访问专属内容', 'member', 'access_exclusive'),
    
    -- 管理员权限
    (gen_random_uuid(), 'admin.access', '访问管理后台', 'admin', 'access'),
    (gen_random_uuid(), 'admin.manage_users', '管理用户', 'admin', 'manage_users'),
    (gen_random_uuid(), 'admin.manage_roles', '管理角色权限', 'admin', 'manage_roles'),
    (gen_random_uuid(), 'admin.system_settings', '系统设置', 'admin', 'system_settings'),
    
    -- 系统权限
    (gen_random_uuid(), 'system.maintenance', '系统维护', 'system', 'maintenance'),
    (gen_random_uuid(), 'system.logs', '查看系统日志', 'system', 'logs')
ON CONFLICT (name) DO NOTHING;

-- 为角色分配权限
-- 普通用户权限
INSERT INTO role_permissions (id, role_id, permission_id)
SELECT 
    gen_random_uuid(),
    r.id,
    p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'regular' 
AND p.name IN ('content.read')
ON CONFLICT DO NOTHING;

-- 会员用户权限（继承普通用户 + 会员专属）
INSERT INTO role_permissions (id, role_id, permission_id)
SELECT 
    gen_random_uuid(),
    r.id,
    p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'member' 
AND p.name IN (
    'content.read',
    'content.create',
    'member.premium_features',
    'member.exclusive_content'
)
ON CONFLICT DO NOTHING;

-- 管理员权限（继承会员 + 管理权限）
INSERT INTO role_permissions (id, role_id, permission_id)
SELECT 
    gen_random_uuid(),
    r.id,
    p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'admin' 
AND p.name IN (
    'content.read',
    'content.create',
    'content.update',
    'content.delete',
    'member.premium_features',
    'member.exclusive_content',
    'users.read',
    'users.update',
    'users.list',
    'admin.access',
    'admin.manage_users'
)
ON CONFLICT DO NOTHING;

-- 超级管理员权限（所有权限）
INSERT INTO role_permissions (id, role_id, permission_id)
SELECT 
    gen_random_uuid(),
    r.id,
    p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'super_admin'
ON CONFLICT DO NOTHING;