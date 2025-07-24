# OrAura 灵性占卜应用后端系统设计文档

## 1. 系统概述

OrAura 是一个支持移动 App 的后端服务，专注于灵性占卜、冥想、白噪音播放和用户情绪记录。系统采用微服务架构设计，使用 Go 语言开发，支持高并发和可扩展性。

### 1.1 技术栈选择

| 组件 | 技术选型 | 选择理由 |
|------|----------|----------|
| 编程语言 | Go 1.22+ | 高性能、并发友好、部署简单 |
| Web 框架 | Gin | 轻量级、性能优异、生态丰富 |
| 数据库 | PostgreSQL | ACID 特性、JSON 支持、扩展性强 |
| 缓存 | Redis | 高性能、数据结构丰富、集群支持 |
| ORM | GORM | Go 生态成熟、特性完善、迁移友好 |
| 身份验证 | JWT + OAuth2 | 无状态、跨平台、标准协议 |
| 日志 | Zap | 高性能、结构化、配置灵活 |
| 配置管理 | Viper | 多格式支持、环境变量、热重载 |
| 测试框架 | Go test + Testify | 官方支持、断言丰富、Mock 友好 |

## 2. 系统架构设计

### 2.1 整体架构图（文字描述）

```
┌─────────────────────────────────────────────────┐
│                 客户端层                          │
│  React Native App (iOS/Android)                │
└─────────────────┬───────────────────────────────┘
                  │ HTTPS/WebSocket
┌─────────────────▼───────────────────────────────┐
│                 网关层                          │
│  Nginx + Rate Limiting + CORS                  │
└─────────────────┬───────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────┐
│              应用服务层                         │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐│
│  │用户模块 │ │占卜模块 │ │音频模块 │ │订阅模块 ││
│  │User     │ │Divination│ │Audio   │ │Subscription││
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘│
│  ┌─────────────────────────────────────────────┐│
│  │           通用服务层                        ││
│  │  Auth | Logger | Config | Validator       ││
│  └─────────────────────────────────────────────┘│
└─────────────────┬───────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────┐
│               数据持久层                        │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐│
│  │ PostgreSQL  │ │   Redis     │ │   S3/OSS    ││
│  │  主数据库   │ │   缓存      │ │  文件存储   ││
│  └─────────────┘ └─────────────┘ └─────────────┘│
└─────────────────────────────────────────────────┘
```

### 2.2 数据流架构

1. **请求流**：Client → Gateway → Auth Middleware → Business Logic → Database
2. **响应流**：Database → Business Logic → Response Formatter → Client
3. **缓存策略**：热数据 Redis 缓存，冷数据数据库查询
4. **文件流**：音频文件通过 CDN 分发，元数据存储在数据库

## 3. 模块划分设计

### 3.1 用户模块 (User Module)

**职责边界：**
- 用户注册、登录、注销
- JWT Token 签发与刷新
- OAuth2 第三方登录（Google、Apple）
- 用户信息管理（头像、昵称、偏好设置）
- 用户会话管理

**核心接口：**
- `POST /api/v1/auth/register` - 用户注册
- `POST /api/v1/auth/login` - 用户登录
- `POST /api/v1/auth/refresh` - Token 刷新
- `GET /api/v1/users/profile` - 获取用户信息
- `PUT /api/v1/users/profile` - 更新用户信息

### 3.2 AI 占卜模块 (Divination Module)

**职责边界：**
- 占卜问题接收与处理
- OpenAI GPT-4o API 集成
- 占卜历史记录管理
- 占卜结果缓存策略
- 请求限流与计费

**核心接口：**
- `POST /api/v1/divination/ask` - 提交占卜问题
- `GET /api/v1/divination/history` - 获取占卜历史
- `GET /api/v1/divination/{id}` - 获取特定占卜结果

### 3.3 音频模块 (Audio Module)

**职责边界：**
- 冥想音频元数据管理
- 白噪音分类与搜索
- 音频播放记录统计
- 文件上传与 CDN 集成
- 播放列表管理

**核心接口：**
- `GET /api/v1/audio/meditations` - 获取冥想音频列表
- `GET /api/v1/audio/whitenoise` - 获取白噪音列表
- `POST /api/v1/audio/play-record` - 记录播放行为
- `GET /api/v1/audio/playlists` - 获取播放列表

### 3.4 订阅模块 (Subscription Module)

**职责边界：**
- 订阅计划管理
- 支付回调处理（Apple、Google、Stripe）
- 订阅状态维护与校验
- 会员权限控制
- 订阅到期提醒

**核心接口：**
- `GET /api/v1/subscriptions/plans` - 获取订阅计划
- `POST /api/v1/subscriptions/purchase` - 创建订阅
- `POST /api/v1/subscriptions/webhook` - 支付回调
- `GET /api/v1/subscriptions/status` - 查询订阅状态

### 3.5 通用服务模块 (Common Module)

**职责边界：**
- 统一错误处理与响应格式
- 日志记录与链路追踪
- 配置管理与环境变量
- 数据验证与参数校验
- 中间件管理（CORS、限流、认证）

## 4. 服务依赖关系

### 4.1 模块间依赖

```
用户模块 ←→ 通用服务模块
    ↑
占卜模块 ←→ 通用服务模块
    ↑
音频模块 ←→ 通用服务模块
    ↑
订阅模块 ←→ 通用服务模块
```

### 4.2 外部服务依赖

- **OpenAI API**: GPT-4o 模型调用
- **OAuth 提供商**: Google OAuth, Apple Sign-In
- **支付网关**: Apple App Store, Google Play, Stripe
- **云存储**: AWS S3 或阿里云 OSS
- **邮件服务**: SendGrid 或阿里云邮件推送

## 5. 数据库关系设计

### 5.1 核心表结构概览

```sql
-- 用户表
users (id, email, username, password_hash, oauth_provider, created_at, updated_at)

-- 用户配置表
user_profiles (user_id, avatar_url, nickname, preferences, timezone)

-- 占卜记录表
divination_records (id, user_id, question, response, tokens_used, created_at)

-- 音频元数据表
audio_tracks (id, title, category, duration, file_url, thumbnail_url)

-- 播放记录表
play_records (id, user_id, track_id, played_at, duration_played)

-- 订阅计划表
subscription_plans (id, name, price, duration_days, features)

-- 用户订阅表
user_subscriptions (id, user_id, plan_id, status, expires_at, created_at)
```

### 5.2 索引策略

- 用户表：email, username 唯一索引
- 占卜记录：user_id, created_at 复合索引
- 播放记录：user_id, played_at 复合索引
- 订阅表：user_id, status, expires_at 复合索引

## 6. 性能与扩展性考虑

### 6.1 缓存策略

- **用户会话**：Redis 存储 JWT 黑名单
- **音频元数据**：Redis 缓存热门音频信息
- **订阅状态**：Redis 缓存用户订阅状态
- **占卜历史**：Redis 缓存最近 10 条记录

### 6.2 限流策略

- **全局限流**：每 IP 每分钟 100 请求
- **用户限流**：每用户每分钟 60 请求
- **占卜限流**：免费用户每日 3 次，会员无限制
- **API 限流**：敏感接口独立限流配置

### 6.3 扩展性设计

- 水平扩展：无状态服务设计，支持负载均衡
- 数据库分片：按用户 ID 分片，支持读写分离
- 微服务拆分：模块间通过 HTTP/gRPC 通信
- 异步处理：使用消息队列处理重任务

## 7. 安全性考虑

### 7.1 认证授权

- JWT Token 过期时间：Access Token 1小时，Refresh Token 30天
- OAuth2 PKCE 流程确保安全
- API 接口全面权限校验
- 敏感操作二次验证

### 7.2 数据安全

- 密码使用 bcrypt 加密存储
- 敏感数据传输 HTTPS 加密
- 数据库连接加密
- API 参数严格校验防注入

### 7.3 业务安全

- 请求频率限制防刷
- 异常请求监控告警
- 用户行为审计日志
- 支付回调签名验证

## 8. 监控与日志

### 8.1 日志策略

- **访问日志**：请求响应时间、状态码、用户 ID
- **业务日志**：关键业务操作记录
- **错误日志**：异常堆栈、错误上下文
- **性能日志**：数据库查询时间、外部 API 调用时间

### 8.2 监控指标

- **系统指标**：CPU、内存、磁盘、网络
- **应用指标**：QPS、响应时间、错误率
- **业务指标**：用户活跃度、订阅转化率、占卜使用量

## 9. 下一步计划

1. **第2阶段**：搭建项目结构和开发规范
2. **第3阶段**：用户模块详细设计与实现
3. **第4阶段**：AI 占卜模块开发
4. **第5-8阶段**：其他模块开发与部署配置

---

*此文档将根据开发进展持续更新完善*