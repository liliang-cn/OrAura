# OrAura Backend - 环境变量配置

## 快速开始

1. 复制环境变量模板：
```bash
cp configs/app.env.example configs/app.env
```

2. 编辑 `configs/app.env` 文件，设置你的配置：
```bash
# 数据库配置
DB_HOST=localhost
DB_USER=postgres
DB_PASSWORD=your-db-password
DB_NAME=oraura
DB_PORT=5432

# JWT配置
JWT_SECRET=your-super-secret-jwt-key
JWT_ACCESS_TOKEN_EXPIRE=1h
JWT_REFRESH_TOKEN_EXPIRE=720h

# 超级管理员配置
ORAURA_SUPER_ADMIN_EMAIL=admin@yourdomain.com
ORAURA_SUPER_ADMIN_USERNAME=superadmin
ORAURA_SUPER_ADMIN_PASSWORD=YourSecurePassword123!
```

## 环境变量说明

### 数据库配置
- `DB_HOST`: 数据库主机地址
- `DB_USER`: 数据库用户名
- `DB_PASSWORD`: 数据库密码
- `DB_NAME`: 数据库名称
- `DB_PORT`: 数据库端口

### JWT配置
- `JWT_SECRET`: JWT签名密钥（生产环境必须更改）
- `JWT_ACCESS_TOKEN_EXPIRE`: 访问令牌过期时间
- `JWT_REFRESH_TOKEN_EXPIRE`: 刷新令牌过期时间

### 超级管理员配置
- `ORAURA_SUPER_ADMIN_EMAIL`: 超级管理员邮箱
- `ORAURA_SUPER_ADMIN_USERNAME`: 超级管理员用户名
- `ORAURA_SUPER_ADMIN_PASSWORD`: 超级管理员密码

## 安全注意事项

⚠️ **重要**: 
- `configs/app.env` 文件已被添加到 `.gitignore`，不会被提交到代码仓库
- 生产环境必须使用强密码和安全的JWT密钥
- 定期更换敏感信息

## 角色权限系统

系统包含4个角色层级：
- `super_admin`: 超级管理员，拥有所有权限
- `admin`: 管理员，可管理用户和内容
- `member`: 会员用户，享有高级功能
- `regular`: 普通用户，基础功能

## 管理员API

启动服务器后，超级管理员可以访问：
- `GET /api/v1/admin/stats` - 仪表板统计
- `GET /api/v1/admin/users` - 用户管理
- `POST /api/v1/admin/users/:id/roles` - 角色分配
- `GET /api/v1/admin/logs/login` - 登录日志
- `GET /api/v1/admin/system/health` - 系统健康检查

## 构建和运行

```bash
# 构建
go build -o bin/server ./cmd/server

# 运行
./bin/server
```

服务器默认启动在 `http://localhost:8080`，Swagger文档可在 `http://localhost:8080/swagger/index.html` 访问。