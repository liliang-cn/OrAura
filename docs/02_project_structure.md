# OrAura 项目结构与开发规范

## 1. 项目目录结构

```
OrAura/
├── cmd/                        # 应用程序入口
│   └── server/
│       └── main.go            # 主程序入口
├── internal/                   # 内部应用代码
│   ├── auth/                  # 认证模块
│   │   ├── handler.go
│   │   ├── service.go
│   │   ├── repository.go
│   │   └── model.go
│   ├── user/                  # 用户模块
│   │   ├── handler.go
│   │   ├── service.go
│   │   ├── repository.go
│   │   └── model.go
│   ├── divination/            # 占卜模块
│   │   ├── handler.go
│   │   ├── service.go
│   │   ├── repository.go
│   │   └── model.go
│   ├── audio/                 # 音频模块
│   │   ├── handler.go
│   │   ├── service.go
│   │   ├── repository.go
│   │   └── model.go
│   ├── subscription/          # 订阅模块
│   │   ├── handler.go
│   │   ├── service.go
│   │   ├── repository.go
│   │   └── model.go
│   ├── common/                # 通用组件
│   │   ├── config/            # 配置管理
│   │   ├── database/          # 数据库连接
│   │   ├── logger/            # 日志组件
│   │   ├── middleware/        # 中间件
│   │   ├── response/          # 统一响应格式
│   │   ├── validator/         # 参数验证
│   │   └── utils/             # 工具函数
│   └── server/                # 服务器配置
│       ├── router.go          # 路由配置
│       └── server.go          # 服务器启动
├── pkg/                       # 可重用的库代码
│   ├── jwt/                   # JWT 工具
│   ├── oauth/                 # OAuth 客户端
│   ├── openai/                # OpenAI 客户端
│   ├── payment/               # 支付集成
│   └── storage/               # 文件存储
├── configs/                   # 配置文件
│   ├── config.yaml
│   ├── config.dev.yaml
│   └── config.prod.yaml
├── migrations/                # 数据库迁移文件
│   ├── 001_create_users_table.up.sql
│   ├── 001_create_users_table.down.sql
│   └── ...
├── tests/                     # 测试文件
│   ├── integration/           # 集成测试
│   ├── testdata/             # 测试数据
│   └── mocks/                # Mock 文件
├── scripts/                   # 脚本文件
│   ├── build.sh
│   ├── deploy.sh
│   └── migrate.sh
├── docs/                      # 文档
│   ├── api/                   # API 文档
│   └── ...
├── docker/                    # Docker 相关文件
│   ├── Dockerfile
│   └── docker-compose.yml
├── .github/                   # GitHub Actions
│   └── workflows/
│       ├── ci.yml
│       └── cd.yml
├── go.mod                     # Go 模块文件
├── go.sum
├── Makefile                   # 构建脚本
└── README.md                  # 项目说明
```

## 2. 分层架构设计

### 2.1 架构层次

```
┌─────────────────────────────────────────┐
│                Handler                   │  ← HTTP 请求处理
│  (接收请求、参数验证、调用 Service)         │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│                Service                   │  ← 业务逻辑处理
│  (业务规则、事务管理、调用 Repository)      │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│              Repository                  │  ← 数据访问层
│  (数据库操作、缓存操作、外部 API 调用)      │
└─────────────────────────────────────────┘
```

### 2.2 依赖注入原则

- Handler 依赖 Service 接口
- Service 依赖 Repository 接口
- 使用接口隔离，便于测试和替换实现

## 3. Makefile 工具

```makefile
# OrAura Makefile

# 变量定义
APP_NAME := oraura-server
BUILD_DIR := ./build
CMD_DIR := ./cmd/server

# Go 相关变量
GO := go
GOFMT := gofmt
GOLINT := golangci-lint

# Docker 相关变量
DOCKER_IMAGE := oraura/server
DOCKER_TAG := latest

# 默认目标
.PHONY: help
help: ## 显示帮助信息
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = \":.*?## \"}; {printf \"\\033[36m%-15s\\033[0m %s\\n\", $$1, $$2}'

# 开发相关
.PHONY: dev
dev: ## 启动开发服务器
	@echo \"Starting development server...\"
	air -c .air.toml

.PHONY: run
run: ## 运行应用
	@echo \"Running application...\"
	$(GO) run $(CMD_DIR)/main.go

# 构建相关
.PHONY: build
build: ## 构建应用
	@echo \"Building application...\"
	@mkdir -p $(BUILD_DIR)
	$(GO) build -o $(BUILD_DIR)/$(APP_NAME) $(CMD_DIR)/main.go

.PHONY: build-linux
build-linux: ## 构建 Linux 版本
	@echo \"Building Linux application...\"
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 $(GO) build -o $(BUILD_DIR)/$(APP_NAME)-linux $(CMD_DIR)/main.go

# 测试相关
.PHONY: test
test: ## 运行所有测试
	@echo \"Running tests...\"
	$(GO) test -v -cover ./...

.PHONY: test-coverage
test-coverage: ## 运行测试并生成覆盖率报告
	@echo \"Running tests with coverage...\"
	$(GO) test -v -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html

.PHONY: test-unit
test-unit: ## 运行单元测试
	@echo \"Running unit tests...\"
	$(GO) test -v -short ./...

# 代码质量
.PHONY: fmt
fmt: ## 格式化代码
	@echo \"Formatting code...\"
	$(GOFMT) -w .

.PHONY: lint
lint: ## 运行代码检查
	@echo \"Running linter...\"
	$(GOLINT) run

.PHONY: vet
vet: ## 运行 go vet
	@echo \"Running go vet...\"
	$(GO) vet ./...

# 数据库相关
.PHONY: migrate-up
migrate-up: ## 执行数据库迁移
	@echo \"Running database migrations...\"
	migrate -path migrations -database \"postgres://username:password@localhost/oraura?sslmode=disable\" up

.PHONY: migrate-down
migrate-down: ## 回滚数据库迁移
	@echo \"Rolling back database migrations...\"
	migrate -path migrations -database \"postgres://username:password@localhost/oraura?sslmode=disable\" down

.PHONY: migrate-create
migrate-create: ## 创建新迁移文件
	@echo \"Creating migration: $(name)\"
	migrate create -ext sql -dir migrations -seq $(name)

# Docker 相关
.PHONY: docker-build
docker-build: ## 构建 Docker 镜像
	@echo \"Building Docker image...\"
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

.PHONY: docker-run
docker-run: ## 运行 Docker 容器
	@echo \"Running Docker container...\"
	docker run -p 8080:8080 $(DOCKER_IMAGE):$(DOCKER_TAG)

.PHONY: docker-compose-up
docker-compose-up: ## 启动 Docker Compose
	@echo \"Starting services with Docker Compose...\"
	docker-compose up -d

.PHONY: docker-compose-down
docker-compose-down: ## 停止 Docker Compose
	@echo \"Stopping services with Docker Compose...\"
	docker-compose down

# 清理
.PHONY: clean
clean: ## 清理构建文件
	@echo \"Cleaning build files...\"
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html

# 依赖管理
.PHONY: deps
deps: ## 下载依赖
	@echo \"Downloading dependencies...\"
	$(GO) mod download

.PHONY: deps-update
deps-update: ## 更新依赖
	@echo \"Updating dependencies...\"
	$(GO) mod tidy

# 生成相关
.PHONY: gen
gen: ## 生成代码
	@echo \"Generating code...\"
	$(GO) generate ./...

.PHONY: swagger
swagger: ## 生成 Swagger 文档
	@echo \"Generating Swagger documentation...\"
	swaggo fmt
	swaggo gen

# 完整检查
.PHONY: check
check: fmt vet lint test ## 运行所有检查

# 生产部署
.PHONY: deploy
deploy: build-linux ## 部署到生产环境
	@echo \"Deploying to production...\"
	./scripts/deploy.sh
```

## 4. 配置管理 (Viper)

### 4.1 配置文件结构

```yaml
# configs/config.yaml
server:
  host: \"0.0.0.0\"
  port: 8080
  mode: \"debug\"  # debug, release, test
  read_timeout: 60s
  write_timeout: 60s

database:
  driver: \"postgres\"
  host: \"localhost\"
  port: 5432
  user: \"oraura\"
  password: \"password\"
  name: \"oraura_db\"
  ssl_mode: \"disable\"
  max_open_conns: 25
  max_idle_conns: 10
  conn_max_lifetime: 5m

redis:
  host: \"localhost\"
  port: 6379
  password: \"\"
  database: 0
  pool_size: 10

jwt:
  secret: \"your-super-secret-key\"
  access_token_expire: 1h
  refresh_token_expire: 720h

oauth:
  google:
    client_id: \"your-google-client-id\"
    client_secret: \"your-google-client-secret\"
  apple:
    client_id: \"your-apple-client-id\"
    client_secret: \"your-apple-client-secret\"

openai:
  api_key: \"your-openai-api-key\"
  model: \"gpt-4o\"
  max_tokens: 1000
  temperature: 0.7

storage:
  provider: \"s3\"  # s3, oss, local
  bucket: \"oraura-media\"
  region: \"us-west-2\"
  access_key: \"your-access-key\"
  secret_key: \"your-secret-key\"

logging:
  level: \"info\"  # debug, info, warn, error
  format: \"json\"  # json, text
  output: \"stdout\"  # stdout, file
  file_path: \"logs/app.log\"
```

### 4.2 配置加载代码

```go
// internal/common/config/config.go
package config

import (
    \"fmt\"
    \"time\"
    
    \"github.com/spf13/viper\"
)

type Config struct {
    Server   ServerConfig   `mapstructure:\"server\"`
    Database DatabaseConfig `mapstructure:\"database\"`
    Redis    RedisConfig    `mapstructure:\"redis\"`
    JWT      JWTConfig      `mapstructure:\"jwt\"`
    OAuth    OAuthConfig    `mapstructure:\"oauth\"`
    OpenAI   OpenAIConfig   `mapstructure:\"openai\"`
    Storage  StorageConfig  `mapstructure:\"storage\"`
    Logging  LoggingConfig  `mapstructure:\"logging\"`
}

type ServerConfig struct {
    Host         string        `mapstructure:\"host\"`
    Port         int           `mapstructure:\"port\"`
    Mode         string        `mapstructure:\"mode\"`
    ReadTimeout  time.Duration `mapstructure:\"read_timeout\"`
    WriteTimeout time.Duration `mapstructure:\"write_timeout\"`
}

type DatabaseConfig struct {
    Driver          string        `mapstructure:\"driver\"`
    Host            string        `mapstructure:\"host\"`
    Port            int           `mapstructure:\"port\"`
    User            string        `mapstructure:\"user\"`
    Password        string        `mapstructure:\"password\"`
    Name            string        `mapstructure:\"name\"`
    SSLMode         string        `mapstructure:\"ssl_mode\"`
    MaxOpenConns    int           `mapstructure:\"max_open_conns\"`
    MaxIdleConns    int           `mapstructure:\"max_idle_conns\"`
    ConnMaxLifetime time.Duration `mapstructure:\"conn_max_lifetime\"`
}

type RedisConfig struct {
    Host     string `mapstructure:\"host\"`
    Port     int    `mapstructure:\"port\"`
    Password string `mapstructure:\"password\"`
    Database int    `mapstructure:\"database\"`
    PoolSize int    `mapstructure:\"pool_size\"`
}

type JWTConfig struct {
    Secret              string        `mapstructure:\"secret\"`
    AccessTokenExpire   time.Duration `mapstructure:\"access_token_expire\"`
    RefreshTokenExpire  time.Duration `mapstructure:\"refresh_token_expire\"`
}

type OAuthConfig struct {
    Google GoogleOAuthConfig `mapstructure:\"google\"`
    Apple  AppleOAuthConfig  `mapstructure:\"apple\"`
}

type GoogleOAuthConfig struct {
    ClientID     string `mapstructure:\"client_id\"`
    ClientSecret string `mapstructure:\"client_secret\"`
}

type AppleOAuthConfig struct {
    ClientID     string `mapstructure:\"client_id\"`
    ClientSecret string `mapstructure:\"client_secret\"`
}

type OpenAIConfig struct {
    APIKey      string  `mapstructure:\"api_key\"`
    Model       string  `mapstructure:\"model\"`
    MaxTokens   int     `mapstructure:\"max_tokens\"`
    Temperature float64 `mapstructure:\"temperature\"`
}

type StorageConfig struct {
    Provider  string `mapstructure:\"provider\"`
    Bucket    string `mapstructure:\"bucket\"`
    Region    string `mapstructure:\"region\"`
    AccessKey string `mapstructure:\"access_key\"`
    SecretKey string `mapstructure:\"secret_key\"`
}

type LoggingConfig struct {
    Level    string `mapstructure:\"level\"`
    Format   string `mapstructure:\"format\"`
    Output   string `mapstructure:\"output\"`
    FilePath string `mapstructure:\"file_path\"`
}

func Load() (*Config, error) {
    viper.SetConfigName(\"config\")
    viper.SetConfigType(\"yaml\")
    viper.AddConfigPath(\"./configs\")
    viper.AddConfigPath(\".\")
    
    // 环境变量支持
    viper.AutomaticEnv()
    viper.SetEnvPrefix(\"ORAURA\")
    
    if err := viper.ReadInConfig(); err != nil {
        return nil, fmt.Errorf(\"failed to read config: %w\", err)
    }
    
    var config Config
    if err := viper.Unmarshal(&config); err != nil {
        return nil, fmt.Errorf(\"failed to unmarshal config: %w\", err)
    }
    
    return &config, nil
}

func (c *Config) GetServerAddress() string {
    return fmt.Sprintf(\"%s:%d\", c.Server.Host, c.Server.Port)
}

func (c *Config) GetDatabaseDSN() string {
    return fmt.Sprintf(\"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s\",
        c.Database.Host, c.Database.Port, c.Database.User, 
        c.Database.Password, c.Database.Name, c.Database.SSLMode)
}

func (c *Config) GetRedisAddress() string {
    return fmt.Sprintf(\"%s:%d\", c.Redis.Host, c.Redis.Port)
}
```

## 5. 环境变量管理

### 5.1 环境变量命名规范

```bash
# 服务器配置
ORAURA_SERVER_HOST=0.0.0.0
ORAURA_SERVER_PORT=8080
ORAURA_SERVER_MODE=debug

# 数据库配置
ORAURA_DATABASE_HOST=localhost
ORAURA_DATABASE_PORT=5432
ORAURA_DATABASE_USER=oraura
ORAURA_DATABASE_PASSWORD=password
ORAURA_DATABASE_NAME=oraura_db

# Redis 配置
ORAURA_REDIS_HOST=localhost
ORAURA_REDIS_PORT=6379
ORAURA_REDIS_PASSWORD=

# JWT 配置
ORAURA_JWT_SECRET=your-super-secret-key

# OpenAI 配置
ORAURA_OPENAI_API_KEY=your-openai-api-key

# OAuth 配置
ORAURA_OAUTH_GOOGLE_CLIENT_ID=your-google-client-id
ORAURA_OAUTH_GOOGLE_CLIENT_SECRET=your-google-client-secret
```

### 5.2 环境文件示例

```bash
# .env.development
ORAURA_SERVER_MODE=debug
ORAURA_DATABASE_HOST=localhost
ORAURA_REDIS_HOST=localhost
ORAURA_JWT_SECRET=dev-secret-key

# .env.production
ORAURA_SERVER_MODE=release
ORAURA_DATABASE_HOST=prod-db-host
ORAURA_REDIS_HOST=prod-redis-host
ORAURA_JWT_SECRET=prod-super-secret-key
```

## 6. 开发工具配置

### 6.1 Air 热重载配置

```toml
# .air.toml
root = \".\"
testdata_dir = \"testdata\"
tmp_dir = \"tmp\"

[build]
args_bin = []
bin = \"./tmp/main\"
cmd = \"go build -o ./tmp/main ./cmd/server\"
delay = 1000
exclude_dir = [\"assets\", \"tmp\", \"vendor\", \"testdata\", \"build\", \"docs\"]
exclude_file = []
exclude_regex = [\"_test.go\"]
exclude_unchanged = false
follow_symlink = false
full_bin = \"\"
include_dir = []
include_ext = [\"go\", \"tpl\", \"tmpl\", \"html\", \"yaml\", \"yml\"]
kill_delay = \"0s\"
log = \"build-errors.log\"
send_interrupt = false
stop_on_root = false

[color]
app = \"\"
build = \"yellow\"
main = \"magenta\"
runner = \"green\"
watcher = \"cyan\"

[log]
time = false

[misc]
clean_on_exit = false
```

### 6.2 VSCode 配置

```json
// .vscode/settings.json
{
    \"go.toolsManagement.checkForUpdates\": \"local\",
    \"go.useLanguageServer\": true,
    \"go.formatTool\": \"goimports\",
    \"go.lintTool\": \"golangci-lint\",
    \"go.testFlags\": [\"-v\"],
    \"go.coverOnSave\": true,
    \"go.coverOnSingleTest\": true,
    \"go.coverageDecorator\": {
        \"type\": \"gutter\",
        \"coveredHighlightColor\": \"rgba(64,128,64,0.5)\",
        \"uncoveredHighlightColor\": \"rgba(128,64,64,0.25)\"
    },
    \"files.exclude\": {
        \"tmp/\": true,
        \"build/\": true,
        \"coverage.html\": true,
        \"coverage.out\": true
    }
}
```

## 7. Git 工作流规范

### 7.1 分支策略

- `main`: 生产分支，只接受 PR 合并
- `develop`: 开发分支，所有功能开发的基础分支
- `feature/*`: 功能分支，从 develop 分出
- `hotfix/*`: 热修复分支，从 main 分出
- `release/*`: 发布分支，发布前的最终测试

### 7.2 提交信息规范

```
type(scope): subject

body

footer
```

**类型说明:**
- `feat`: 新功能
- `fix`: 修复 Bug
- `docs`: 文档更新
- `style`: 代码格式调整
- `refactor`: 重构
- `test`: 测试相关
- `chore`: 构建工具、辅助工具的变动

**示例:**
```
feat(user): add user registration API

- Add user registration endpoint
- Implement email validation
- Add password hashing

Closes #123
```

## 8. 代码规范

### 8.1 命名规范

- **包名**: 全小写，简短有意义
- **变量名**: 驼峰命名，首字母小写
- **常量名**: 全大写，下划线分隔
- **函数名**: 驼峰命名，首字母大写（导出）或小写（内部）
- **接口名**: 以 -er 结尾，如 UserRepository

### 8.2 错误处理规范

```go
// 统一错误定义
var (
    ErrUserNotFound     = errors.New(\"user not found\")
    ErrInvalidPassword  = errors.New(\"invalid password\")
    ErrTokenExpired     = errors.New(\"token expired\")
)

// 错误包装
func (s *userService) GetUser(id string) (*User, error) {
    user, err := s.repo.GetByID(id)
    if err != nil {
        return nil, fmt.Errorf(\"failed to get user %s: %w\", id, err)
    }
    return user, nil
}
```

### 8.3 日志规范

```go
// 使用结构化日志
logger.Info(\"user login\",
    zap.String(\"user_id\", userID),
    zap.String(\"ip\", clientIP),
    zap.Duration(\"duration\", time.Since(start)),
)

logger.Error(\"database connection failed\",
    zap.Error(err),
    zap.String(\"host\", dbHost),
    zap.Int(\"port\", dbPort),
)
```

## 9. 下一步计划

接下来将开始用户模块的详细设计与实现，包括：

1. 用户模块功能分析与接口设计
2. 数据模型定义
3. 三层架构实现
4. 单元测试编写
5. Swagger 文档生成

---

*此文档定义了整个项目的基础结构和开发规范，为后续模块开发提供统一标准。*