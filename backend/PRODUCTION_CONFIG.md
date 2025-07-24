# 生产环境配置指南

## 环境变量设置

在生产环境中，你需要设置以下环境变量：

### 数据库配置
```bash
export ORAURA_DATABASE_HOST=your-db-host
export ORAURA_DATABASE_USER=your-db-user
export ORAURA_DATABASE_PASSWORD=your-secure-db-password
export ORAURA_DATABASE_NAME=oraura_prod
export ORAURA_DATABASE_PORT=5432
```

### 服务器配置
```bash
export ORAURA_SERVER_HOST=0.0.0.0
export ORAURA_SERVER_PORT=8080
export ORAURA_SERVER_MODE=release
```

### JWT配置
```bash
export ORAURA_JWT_SECRET=your-super-secure-jwt-secret-key-min-256-bits
export ORAURA_JWT_ACCESS_TOKEN_EXPIRE=1h
export ORAURA_JWT_REFRESH_TOKEN_EXPIRE=720h
```

### 超级管理员配置
```bash
export ORAURA_SUPER_ADMIN_EMAIL=admin@yourdomain.com
export ORAURA_SUPER_ADMIN_USERNAME=superadmin
export ORAURA_SUPER_ADMIN_PASSWORD=VerySecurePassword123!@#
```

### OAuth配置（可选）
```bash
export ORAURA_OAUTH_GOOGLE_CLIENT_ID=your-google-client-id
export ORAURA_OAUTH_GOOGLE_CLIENT_SECRET=your-google-client-secret
export ORAURA_OAUTH_APPLE_CLIENT_ID=your-apple-client-id
export ORAURA_OAUTH_APPLE_CLIENT_SECRET=your-apple-client-secret
```

## 安全建议

1. **JWT密钥**: 使用至少256位的随机密钥
2. **管理员密码**: 使用强密码，包含大小写字母、数字和特殊字符
3. **数据库密码**: 使用强密码，定期轮换
4. **环境变量**: 永远不要将生产环境的密钥提交到代码仓库
5. **HTTPS**: 生产环境必须使用HTTPS

## Docker环境变量

如果使用Docker，可以通过以下方式设置：

```bash
docker run -d \
  -e ORAURA_DATABASE_HOST=db-host \
  -e ORAURA_DATABASE_PASSWORD=secure-password \
  -e ORAURA_JWT_SECRET=your-jwt-secret \
  -e ORAURA_SUPER_ADMIN_PASSWORD=admin-password \
  your-image:tag
```

或者使用docker-compose.yml中的environment配置。