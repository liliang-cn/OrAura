# OrAura CI/CD 流程设计文档

## 📋 文档概览

本文档详细描述 OrAura 项目的持续集成和持续部署(CI/CD)流程设计，包括 GitHub Actions 工作流配置、分支策略、自动化测试、构建部署和监控策略。

---

## 🌳 Git 分支策略

### 1. **分支模型设计**

```
main (生产环境)
├── release/v1.0.x (发布分支)
├── develop (开发环境)
│   ├── feature/divination-api (功能分支)
│   ├── feature/meditation-player (功能分支)
│   └── feature/emotion-tracking (功能分支)
├── hotfix/critical-bug-fix (热修复分支)
└── docs/architecture-update (文档分支)
```

### 2. **分支规则与保护**

```yaml
# .github/branch-protection.yml
branch_protection_rules:
  main:
    required_status_checks:
      - "test-backend"
      - "test-frontend"
      - "security-scan"
      - "build-docker"
    enforce_admins: true
    required_pull_request_reviews:
      required_approving_review_count: 2
      dismiss_stale_reviews: true
      require_code_owner_reviews: true
    restrictions:
      users: []
      teams: ["senior-developers"]

  develop:
    required_status_checks:
      - "test-backend"
      - "test-frontend"
    required_pull_request_reviews:
      required_approving_review_count: 1

  "release/*":
    required_status_checks:
      - "test-backend"
      - "test-frontend"
      - "integration-tests"
      - "performance-tests"
    required_pull_request_reviews:
      required_approving_review_count: 2
```

### 3. **提交规范**

```bash
# 提交信息格式
<type>(<scope>): <description>

[optional body]

[optional footer(s)]

# 示例
feat(auth): add Google OAuth integration
fix(api): resolve divination endpoint timeout issue
docs(readme): update installation instructions
test(emotion): add unit tests for emotion tracking
refactor(ui): optimize button component performance
```

---

## 🔄 GitHub Actions 工作流

### 1. **主工作流配置**

```yaml
# .github/workflows/main.yml
name: OrAura CI/CD Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]
  release:
    types: [published]

env:
  NODE_VERSION: "18"
  GO_VERSION: "1.21"
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  # 代码质量检查
  code-quality:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: ${{ env.NODE_VERSION }}
          cache: "npm"
          cache-dependency-path: "frontend/package-lock.json"

      - name: Setup Go
        uses: actions/setup-go@v4
        with:
          go-version: ${{ env.GO_VERSION }}
          cache-dependency-path: "backend/go.sum"

      - name: Install frontend dependencies
        working-directory: ./frontend
        run: npm ci

      - name: Install backend dependencies
        working-directory: ./backend
        run: go mod download

      - name: Run ESLint (Frontend)
        working-directory: ./frontend
        run: npm run lint

      - name: Run golangci-lint (Backend)
        uses: golangci/golangci-lint-action@v3
        with:
          version: latest
          working-directory: ./backend

      - name: Check TypeScript types
        working-directory: ./frontend
        run: npm run type-check

  # 后端测试
  test-backend:
    runs-on: ubuntu-latest
    needs: code-quality

    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: postgres
          POSTGRES_DB: oraura_test
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432

      redis:
        image: redis:7
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 6379:6379

    steps:
      - uses: actions/checkout@v4

      - name: Setup Go
        uses: actions/setup-go@v4
        with:
          go-version: ${{ env.GO_VERSION }}
          cache-dependency-path: "backend/go.sum"

      - name: Install dependencies
        working-directory: ./backend
        run: go mod download

      - name: Run database migrations
        working-directory: ./backend
        env:
          DATABASE_URL: postgres://postgres:postgres@localhost:5432/oraura_test?sslmode=disable
        run: |
          go install github.com/pressly/goose/v3/cmd/goose@latest
          goose -dir migrations postgres "$DATABASE_URL" up

      - name: Run unit tests
        working-directory: ./backend
        env:
          DATABASE_URL: postgres://postgres:postgres@localhost:5432/oraura_test?sslmode=disable
          REDIS_URL: redis://localhost:6379
        run: |
          go test -v -race -coverprofile=coverage.out ./...
          go tool cover -func=coverage.out

      - name: Check test coverage
        working-directory: ./backend
        run: |
          COVERAGE=$(go tool cover -func=coverage.out | grep total | awk '{print substr($3, 1, length($3)-1)}')
          echo "Coverage: $COVERAGE%"
          if (( $(echo "$COVERAGE < 80" | bc -l) )); then
            echo "Error: Test coverage is below 80%"
            exit 1
          fi

      - name: Upload coverage to Codecov
        uses: codecov/codecov-action@v3
        with:
          file: ./backend/coverage.out
          flags: backend

  # 前端测试
  test-frontend:
    runs-on: ubuntu-latest
    needs: code-quality

    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: ${{ env.NODE_VERSION }}
          cache: "npm"
          cache-dependency-path: "frontend/package-lock.json"

      - name: Install dependencies
        working-directory: ./frontend
        run: npm ci

      - name: Run unit tests
        working-directory: ./frontend
        run: npm run test:coverage

      - name: Check test coverage
        working-directory: ./frontend
        run: |
          COVERAGE=$(npm run test:coverage --silent | grep "All files" | awk '{print $10}' | sed 's/%//')
          echo "Coverage: $COVERAGE%"
          if (( $(echo "$COVERAGE < 80" | bc -l) )); then
            echo "Error: Test coverage is below 80%"
            exit 1
          fi

      - name: Upload coverage to Codecov
        uses: codecov/codecov-action@v3
        with:
          directory: ./frontend/coverage
          flags: frontend

  # 安全扫描
  security-scan:
    runs-on: ubuntu-latest
    needs: code-quality

    steps:
      - uses: actions/checkout@v4

      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: "fs"
          scan-ref: "."
          format: "sarif"
          output: "trivy-results.sarif"

      - name: Upload Trivy scan results to GitHub Security tab
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: "trivy-results.sarif"

      - name: Run Snyk to check for vulnerabilities
        uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        with:
          args: --severity-threshold=high
          command: test

  # Docker 构建
  build-docker:
    runs-on: ubuntu-latest
    needs: [test-backend, test-frontend]
    if: github.event_name != 'pull_request'

    steps:
      - uses: actions/checkout@v4

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Log in to Container Registry
        uses: docker/login-action@v3
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Extract metadata (tags, labels) for Docker
        id: meta
        uses: docker/metadata-action@v5
        with:
          images: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
          tags: |
            type=ref,event=branch
            type=ref,event=pr
            type=semver,pattern={{version}}
            type=semver,pattern={{major}}.{{minor}}
            type=sha

      - name: Build and push Docker image
        uses: docker/build-push-action@v5
        with:
          context: .
          file: ./Dockerfile
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          cache-from: type=gha
          cache-to: type=gha,mode=max

  # 集成测试
  integration-tests:
    runs-on: ubuntu-latest
    needs: build-docker
    if: github.ref == 'refs/heads/main' || github.ref == 'refs/heads/develop'

    steps:
      - uses: actions/checkout@v4

      - name: Setup test environment
        run: |
          docker-compose -f docker-compose.test.yml up -d
          sleep 30

      - name: Run integration tests
        run: |
          docker-compose -f docker-compose.test.yml exec -T api go test -v ./tests/integration/...

      - name: Cleanup
        if: always()
        run: docker-compose -f docker-compose.test.yml down -v

  # 部署到开发环境
  deploy-dev:
    runs-on: ubuntu-latest
    needs: [integration-tests]
    if: github.ref == 'refs/heads/develop'
    environment: development

    steps:
      - uses: actions/checkout@v4

      - name: Deploy to development
        env:
          DEV_SERVER_HOST: ${{ secrets.DEV_SERVER_HOST }}
          DEV_SERVER_USER: ${{ secrets.DEV_SERVER_USER }}
          DEV_SERVER_KEY: ${{ secrets.DEV_SERVER_KEY }}
        run: |
          echo "$DEV_SERVER_KEY" > private_key
          chmod 600 private_key

          scp -i private_key -o StrictHostKeyChecking=no \
            docker-compose.dev.yml $DEV_SERVER_USER@$DEV_SERVER_HOST:~/oraura/

          ssh -i private_key -o StrictHostKeyChecking=no \
            $DEV_SERVER_USER@$DEV_SERVER_HOST \
            "cd ~/oraura && docker-compose -f docker-compose.dev.yml pull && docker-compose -f docker-compose.dev.yml up -d"

  # 部署到生产环境
  deploy-prod:
    runs-on: ubuntu-latest
    needs: [integration-tests]
    if: github.ref == 'refs/heads/main'
    environment: production

    steps:
      - uses: actions/checkout@v4

      - name: Deploy to production
        env:
          PROD_SERVER_HOST: ${{ secrets.PROD_SERVER_HOST }}
          PROD_SERVER_USER: ${{ secrets.PROD_SERVER_USER }}
          PROD_SERVER_KEY: ${{ secrets.PROD_SERVER_KEY }}
        run: |
          echo "$PROD_SERVER_KEY" > private_key
          chmod 600 private_key

          # 蓝绿部署脚本
          ssh -i private_key -o StrictHostKeyChecking=no \
            $PROD_SERVER_USER@$PROD_SERVER_HOST \
            "cd ~/oraura && ./scripts/blue-green-deploy.sh"

  # 移动端构建 (React Native)
  build-mobile:
    runs-on: ubuntu-latest
    needs: test-frontend
    if: github.event_name == 'release'

    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: ${{ env.NODE_VERSION }}
          cache: "npm"
          cache-dependency-path: "mobile/package-lock.json"

      - name: Setup EAS CLI
        run: npm install -g @expo/eas-cli

      - name: Install dependencies
        working-directory: ./mobile
        run: npm ci

      - name: Build with EAS
        working-directory: ./mobile
        env:
          EXPO_TOKEN: ${{ secrets.EXPO_TOKEN }}
        run: |
          eas build --platform all --non-interactive
```

### 2. **专门的工作流**

```yaml
# .github/workflows/mobile-e2e.yml
name: Mobile E2E Tests

on:
  schedule:
    - cron: "0 2 * * *" # 每天凌晨2点运行
  workflow_dispatch:

jobs:
  mobile-e2e:
    runs-on: macos-latest

    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: "18"
          cache: "npm"
          cache-dependency-path: "mobile/package-lock.json"

      - name: Install dependencies
        working-directory: ./mobile
        run: npm ci

      - name: Setup iOS Simulator
        run: |
          xcrun simctl create "iPhone 14" "iPhone 14" "iOS16.0"
          xcrun simctl boot "iPhone 14"

      - name: Build for testing
        working-directory: ./mobile
        run: npx detox build --configuration ios.sim.debug

      - name: Run E2E tests
        working-directory: ./mobile
        run: npx detox test --configuration ios.sim.debug

      - name: Upload test results
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: detox-screenshots
          path: mobile/artifacts/
```

```yaml
# .github/workflows/performance.yml
name: Performance Tests

on:
  schedule:
    - cron: "0 1 * * 1" # 每周一凌晨1点
  workflow_dispatch:

jobs:
  lighthouse:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: "18"

      - name: Install Lighthouse CI
        run: npm install -g @lhci/cli@0.12.x

      - name: Run Lighthouse
        run: lhci autorun
        env:
          LHCI_GITHUB_APP_TOKEN: ${{ secrets.LHCI_GITHUB_APP_TOKEN }}

  load-testing:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Setup K6
        run: |
          curl https://github.com/grafana/k6/releases/download/v0.47.0/k6-v0.47.0-linux-amd64.tar.gz -L | tar xvz --strip-components 1

      - name: Run load tests
        run: ./k6 run tests/performance/load-test.js
```

---

## 🐳 Docker 配置

### 1. **多阶段构建 Dockerfile**

```dockerfile
# Dockerfile
# Stage 1: Build frontend
FROM node:18-alpine AS frontend-builder

WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci --only=production

COPY frontend/ ./
RUN npm run build

# Stage 2: Build backend
FROM golang:1.21-alpine AS backend-builder

WORKDIR /app/backend
COPY backend/go.mod backend/go.sum ./
RUN go mod download

COPY backend/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main ./cmd/server

# Stage 3: Runtime
FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata
WORKDIR /root/

# Copy backend binary
COPY --from=backend-builder /app/backend/main .

# Copy frontend build
COPY --from=frontend-builder /app/frontend/dist ./static

# Copy other necessary files
COPY backend/migrations ./migrations
COPY backend/configs ./configs

# Create non-root user
RUN addgroup -g 1001 -S appuser && \
    adduser -S appuser -u 1001

USER appuser

EXPOSE 8080

CMD ["./main"]
```

### 2. **Docker Compose 配置**

```yaml
# docker-compose.yml
version: "3.8"

services:
  api:
    build: .
    ports:
      - "8080:8080"
    environment:
      - DATABASE_URL=postgres://oraura:oraura@postgres:5432/oraura?sslmode=disable
      - REDIS_URL=redis://redis:6379
      - JWT_SECRET=${JWT_SECRET}
      - OPENAI_API_KEY=${OPENAI_API_KEY}
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    networks:
      - oraura-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  postgres:
    image: postgres:15-alpine
    environment:
      - POSTGRES_DB=oraura
      - POSTGRES_USER=oraura
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./backend/migrations:/docker-entrypoint-initdb.d
    networks:
      - oraura-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U oraura"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes
    volumes:
      - redis_data:/data
    networks:
      - oraura-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 3

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf
      - ./nginx/ssl:/etc/nginx/ssl
    depends_on:
      - api
    networks:
      - oraura-network
    restart: unless-stopped

volumes:
  postgres_data:
  redis_data:

networks:
  oraura-network:
    driver: bridge
```

### 3. **生产环境配置**

```yaml
# docker-compose.prod.yml
version: "3.8"

services:
  api:
    image: ghcr.io/your-org/oraura:latest
    deploy:
      replicas: 3
      resources:
        limits:
          cpus: "1"
          memory: 1G
        reservations:
          cpus: "0.5"
          memory: 512M
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: 3
        window: 120s
    environment:
      - DATABASE_URL=postgres://oraura:${POSTGRES_PASSWORD}@postgres:5432/oraura?sslmode=require
      - REDIS_URL=redis://redis:6379
      - JWT_SECRET=${JWT_SECRET}
      - OPENAI_API_KEY=${OPENAI_API_KEY}
      - ENVIRONMENT=production
    networks:
      - oraura-network
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

  postgres:
    image: postgres:15-alpine
    environment:
      - POSTGRES_DB=oraura
      - POSTGRES_USER=oraura
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - oraura-network
    deploy:
      resources:
        limits:
          cpus: "2"
          memory: 2G
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

networks:
  oraura-network:
    external: true

volumes:
  postgres_data:
    external: true
```

---

## 🚀 部署策略

### 1. **蓝绿部署脚本**

```bash
#!/bin/bash
# scripts/blue-green-deploy.sh

set -e

BLUE_PORT=8080
GREEN_PORT=8081
HEALTH_CHECK_URL="http://localhost"
DOCKER_IMAGE="ghcr.io/your-org/oraura:latest"

# 确定当前活跃环境
if curl -f $HEALTH_CHECK_URL:$BLUE_PORT/health &>/dev/null; then
    ACTIVE_PORT=$BLUE_PORT
    INACTIVE_PORT=$GREEN_PORT
    ACTIVE_ENV="blue"
    INACTIVE_ENV="green"
else
    ACTIVE_PORT=$GREEN_PORT
    INACTIVE_PORT=$BLUE_PORT
    ACTIVE_ENV="green"
    INACTIVE_ENV="blue"
fi

echo "Current active environment: $ACTIVE_ENV (port $ACTIVE_PORT)"
echo "Deploying to inactive environment: $INACTIVE_ENV (port $INACTIVE_PORT)"

# 停止非活跃环境
docker-compose -f docker-compose.$INACTIVE_ENV.yml down

# 拉取最新镜像
docker pull $DOCKER_IMAGE

# 启动非活跃环境
docker-compose -f docker-compose.$INACTIVE_ENV.yml up -d

# 健康检查
echo "Waiting for $INACTIVE_ENV environment to be ready..."
for i in {1..60}; do
    if curl -f $HEALTH_CHECK_URL:$INACTIVE_PORT/health &>/dev/null; then
        echo "$INACTIVE_ENV environment is ready!"
        break
    fi
    if [ $i -eq 60 ]; then
        echo "Health check failed for $INACTIVE_ENV environment"
        docker-compose -f docker-compose.$INACTIVE_ENV.yml logs
        exit 1
    fi
    sleep 5
done

# 更新负载均衡器配置
echo "Switching traffic to $INACTIVE_ENV environment..."
./scripts/switch-traffic.sh $INACTIVE_PORT

# 等待流量切换完成
sleep 30

# 验证新环境
if curl -f $HEALTH_CHECK_URL/health &>/dev/null; then
    echo "Traffic successfully switched to $INACTIVE_ENV environment"

    # 停止之前的活跃环境
    echo "Stopping old $ACTIVE_ENV environment..."
    docker-compose -f docker-compose.$ACTIVE_ENV.yml down

    echo "Deployment completed successfully!"
else
    echo "New environment failed validation, rolling back..."
    ./scripts/switch-traffic.sh $ACTIVE_PORT
    docker-compose -f docker-compose.$INACTIVE_ENV.yml down
    exit 1
fi
```

### 2. **零停机部署脚本**

```bash
#!/bin/bash
# scripts/rolling-deploy.sh

set -e

DOCKER_IMAGE="ghcr.io/your-org/oraura:latest"
SERVICE_NAME="oraura_api"

echo "Starting rolling deployment..."

# 拉取最新镜像
docker pull $DOCKER_IMAGE

# 获取当前运行的容器
CONTAINERS=$(docker ps --filter "name=$SERVICE_NAME" --format "{{.Names}}")

for container in $CONTAINERS; do
    echo "Updating container: $container"

    # 创建新容器
    NEW_CONTAINER="${container}_new"
    docker run -d --name $NEW_CONTAINER \
        --network oraura-network \
        -e DATABASE_URL=$DATABASE_URL \
        -e REDIS_URL=$REDIS_URL \
        $DOCKER_IMAGE

    # 健康检查
    echo "Waiting for new container to be ready..."
    for i in {1..30}; do
        if docker exec $NEW_CONTAINER curl -f http://localhost:8080/health &>/dev/null; then
            break
        fi
        if [ $i -eq 30 ]; then
            echo "Health check failed for new container"
            docker rm -f $NEW_CONTAINER
            exit 1
        fi
        sleep 2
    done

    # 更新负载均衡器
    echo "Adding new container to load balancer..."
    ./scripts/update-lb.sh add $NEW_CONTAINER

    # 等待流量分配
    sleep 10

    # 从负载均衡器移除旧容器
    echo "Removing old container from load balancer..."
    ./scripts/update-lb.sh remove $container

    # 等待连接排空
    sleep 30

    # 停止并删除旧容器
    docker stop $container
    docker rm $container

    # 重命名新容器
    docker rename $NEW_CONTAINER $container

    echo "Container $container updated successfully"
done

echo "Rolling deployment completed!"
```

---

## 📊 监控与告警

### 1. **健康检查配置**

```yaml
# .github/workflows/health-check.yml
name: Health Check

on:
  schedule:
    - cron: "*/5 * * * *" # 每5分钟检查一次
  workflow_dispatch:

jobs:
  health-check:
    runs-on: ubuntu-latest

    steps:
      - name: Check Production Health
        run: |
          if ! curl -f https://api.oraura.com/health; then
            echo "Production health check failed!"
            curl -X POST ${{ secrets.SLACK_WEBHOOK_URL }} \
              -H 'Content-type: application/json' \
              --data '{"text":"🚨 Production API health check failed!"}'
            exit 1
          fi

      - name: Check Development Health
        run: |
          if ! curl -f https://dev-api.oraura.com/health; then
            echo "Development health check failed!"
            curl -X POST ${{ secrets.SLACK_WEBHOOK_URL }} \
              -H 'Content-type: application/json' \
              --data '{"text":"⚠️ Development API health check failed!"}'
          fi
```

### 2. **性能监控**

```yaml
# .github/workflows/performance-monitor.yml
name: Performance Monitoring

on:
  schedule:
    - cron: "0 */6 * * *" # 每6小时运行一次

jobs:
  performance-check:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: "18"

      - name: Install dependencies
        run: npm install -g lighthouse artillery

      - name: Run Lighthouse audit
        run: |
          lighthouse https://app.oraura.com \
            --chrome-flags="--headless" \
            --output json \
            --output-path lighthouse-results.json

      - name: Check performance scores
        run: |
          PERFORMANCE=$(cat lighthouse-results.json | jq '.categories.performance.score * 100')
          if (( $(echo "$PERFORMANCE < 80" | bc -l) )); then
            curl -X POST ${{ secrets.SLACK_WEBHOOK_URL }} \
              -H 'Content-type: application/json' \
              --data "{\"text\":\"📉 Performance score dropped to $PERFORMANCE\"}"
          fi

      - name: Run load test
        run: |
          artillery quick \
            --count 50 \
            --num 10 \
            https://api.oraura.com/health
```

### 3. **自动回滚机制**

```bash
#!/bin/bash
# scripts/auto-rollback.sh

HEALTH_ENDPOINT="https://api.oraura.com/health"
ERROR_THRESHOLD=5
CHECK_INTERVAL=60
ROLLBACK_IMAGE_TAG="stable"

error_count=0

while true; do
    if ! curl -f $HEALTH_ENDPOINT &>/dev/null; then
        error_count=$((error_count + 1))
        echo "Health check failed. Error count: $error_count"

        if [ $error_count -ge $ERROR_THRESHOLD ]; then
            echo "Error threshold reached. Initiating rollback..."

            # 发送告警
            curl -X POST $SLACK_WEBHOOK_URL \
                -H 'Content-type: application/json' \
                --data '{"text":"🔄 Auto-rollback initiated due to health check failures"}'

            # 执行回滚
            docker service update --image ghcr.io/your-org/oraura:$ROLLBACK_IMAGE_TAG oraura_api

            # 等待回滚完成
            sleep 120

            # 验证回滚
            if curl -f $HEALTH_ENDPOINT &>/dev/null; then
                curl -X POST $SLACK_WEBHOOK_URL \
                    -H 'Content-type: application/json' \
                    --data '{"text":"✅ Auto-rollback completed successfully"}'
            else
                curl -X POST $SLACK_WEBHOOK_URL \
                    -H 'Content-type: application/json' \
                    --data '{"text":"❌ Auto-rollback failed. Manual intervention required!"}'
            fi

            break
        fi
    else
        error_count=0
        echo "Health check passed"
    fi

    sleep $CHECK_INTERVAL
done
```

---

## 🔐 环境变量管理

### 1. **GitHub Secrets 配置**

```bash
# 生产环境密钥
PROD_SERVER_HOST=your-prod-server.com
PROD_SERVER_USER=deploy
PROD_SERVER_KEY="-----BEGIN OPENSSH PRIVATE KEY-----..."

# 开发环境密钥
DEV_SERVER_HOST=dev.oraura.com
DEV_SERVER_USER=deploy
DEV_SERVER_KEY="-----BEGIN OPENSSH PRIVATE KEY-----..."

# 数据库配置
POSTGRES_PASSWORD=your-secure-password
JWT_SECRET=your-jwt-secret

# 第三方服务
OPENAI_API_KEY=sk-...
STRIPE_SECRET_KEY=sk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...

# 监控服务
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
SENTRY_DSN=https://...@sentry.io/...

# 容器注册表
GITHUB_TOKEN=ghp_...
DOCKER_REGISTRY_PASSWORD=your-password
```

### 2. **环境配置模板**

```bash
# .env.example
# 复制此文件为 .env 并填入实际值

# 数据库配置
DATABASE_URL=postgres://username:password@localhost:5432/oraura
REDIS_URL=redis://localhost:6379

# JWT 配置
JWT_SECRET=your-jwt-secret-here
JWT_EXPIRES_IN=24h

# OpenAI 配置
OPENAI_API_KEY=sk-your-openai-key
OPENAI_MODEL=gpt-4o
OPENAI_MAX_TOKENS=2000

# 支付配置
STRIPE_SECRET_KEY=sk_test_your-stripe-key
STRIPE_WEBHOOK_SECRET=whsec_your-webhook-secret

# 存储配置
S3_BUCKET=oraura-assets
S3_REGION=us-east-1
S3_ACCESS_KEY=your-s3-access-key
S3_SECRET_KEY=your-s3-secret-key

# 邮件服务
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=noreply@oraura.com
SMTP_PASS=your-smtp-password

# 监控配置
SENTRY_DSN=https://your-sentry-dsn
LOG_LEVEL=info

# 应用配置
PORT=8080
ENVIRONMENT=development
CORS_ORIGINS=http://localhost:3000,https://app.oraura.com
```

---

## 📱 移动端 CI/CD

### 1. **EAS Build 配置**

```json
// mobile/eas.json
{
  "cli": {
    "version": ">= 5.0.0"
  },
  "build": {
    "development": {
      "developmentClient": true,
      "distribution": "internal",
      "ios": {
        "resourceClass": "m1-medium"
      }
    },
    "preview": {
      "distribution": "internal",
      "ios": {
        "simulator": true,
        "resourceClass": "m1-medium"
      },
      "android": {
        "buildType": "apk",
        "gradleCommand": ":app:assembleRelease"
      }
    },
    "production": {
      "ios": {
        "resourceClass": "m1-medium"
      },
      "android": {
        "buildType": "app-bundle"
      }
    }
  },
  "submit": {
    "production": {
      "ios": {
        "appleId": "your-apple-id@example.com",
        "ascAppId": "1234567890",
        "appleTeamId": "ABCDEF1234"
      },
      "android": {
        "serviceAccountKeyPath": "./pc-api-key.json",
        "track": "internal"
      }
    }
  }
}
```

### 2. **OTA 更新工作流**

```yaml
# .github/workflows/mobile-ota.yml
name: Mobile OTA Update

on:
  push:
    branches: [main]
    paths: ["mobile/**"]

jobs:
  ota-update:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: "18"
          cache: "npm"
          cache-dependency-path: "mobile/package-lock.json"

      - name: Setup Expo and EAS
        uses: expo/expo-github-action@v8
        with:
          expo-version: latest
          eas-version: latest
          token: ${{ secrets.EXPO_TOKEN }}

      - name: Install dependencies
        working-directory: ./mobile
        run: npm ci

      - name: Publish OTA update
        working-directory: ./mobile
        run: |
          eas update --branch main --message "Auto update from commit ${{ github.sha }}"

      - name: Notify team
        if: success()
        run: |
          curl -X POST ${{ secrets.SLACK_WEBHOOK_URL }} \
            -H 'Content-type: application/json' \
            --data '{"text":"📱 Mobile OTA update published successfully"}'
```

这个 CI/CD 流程设计文档为 OrAura 项目提供了完整的自动化部署流程，包括代码质量检查、自动化测试、安全扫描、Docker 构建、蓝绿部署、监控告警等完整的 DevOps 实践。接下来我将创建最后两个文档。
