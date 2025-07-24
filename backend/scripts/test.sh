#!/bin/bash

# OrAura Backend Test Runner
# 综合测试脚本，包含单元测试、集成测试和代码覆盖率

set -e

echo "🧪 OrAura Backend Test Suite"
echo "=============================="

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 检查Go环境
echo -e "${BLUE}📋 Checking Go environment...${NC}"
go version

# 检查依赖
echo -e "${BLUE}📦 Checking dependencies...${NC}"
go mod verify
go mod tidy

# 运行代码格式检查
echo -e "${BLUE}🔧 Running code formatting check...${NC}"
if ! gofmt -l . | grep -v -E '\.(pb|mock)\.go$' | wc -l | grep -q "^0$"; then
    echo -e "${RED}❌ Code formatting issues found:${NC}"
    gofmt -l . | grep -v -E '\.(pb|mock)\.go$'
    echo -e "${YELLOW}Run 'go fmt ./...' to fix formatting issues${NC}"
    exit 1
fi
echo -e "${GREEN}✅ Code formatting check passed${NC}"

# 运行代码检查
echo -e "${BLUE}🔍 Running code analysis with go vet...${NC}"
go vet ./...
echo -e "${GREEN}✅ Code analysis passed${NC}"

# 运行单元测试
echo -e "${BLUE}🧪 Running unit tests...${NC}"
go test -v -race -timeout=60s ./internal/services/... || {
    echo -e "${RED}❌ Service tests failed${NC}"
    exit 1
}

go test -v -race -timeout=60s ./internal/handlers/... || {
    echo -e "${RED}❌ Handler tests failed${NC}"
    exit 1
}

go test -v -race -timeout=60s ./internal/middleware/... || {
    echo -e "${RED}❌ Middleware tests failed${NC}"
    exit 1
}

go test -v -race -timeout=120s ./internal/store/... || {
    echo -e "${RED}❌ Repository tests failed${NC}"
    exit 1
}

echo -e "${GREEN}✅ All unit tests passed${NC}"

# 运行测试覆盖率
echo -e "${BLUE}📊 Running test coverage analysis...${NC}"
go test -coverprofile=coverage.out -covermode=atomic ./internal/... || {
    echo -e "${RED}❌ Coverage analysis failed${NC}"
    exit 1
}

# 生成覆盖率报告
go tool cover -html=coverage.out -o coverage.html
COVERAGE=$(go tool cover -func=coverage.out | grep total | awk '{print $3}' | sed 's/%//')

echo -e "${BLUE}📈 Test Coverage: ${COVERAGE}%${NC}"

# 覆盖率阈值检查
THRESHOLD=70
if (( $(echo "$COVERAGE < $THRESHOLD" | bc -l) )); then
    echo -e "${YELLOW}⚠️  Coverage is below ${THRESHOLD}% threshold${NC}"
else
    echo -e "${GREEN}✅ Coverage meets ${THRESHOLD}% threshold${NC}"
fi

# 构建测试
echo -e "${BLUE}🔨 Testing build process...${NC}"
go build -o bin/test-server ./cmd/server/ || {
    echo -e "${RED}❌ Build test failed${NC}"
    exit 1
}
rm -f bin/test-server
echo -e "${GREEN}✅ Build test passed${NC}"

# 清理临时文件
echo -e "${BLUE}🧹 Cleaning up...${NC}"
rm -f coverage.out

echo -e "${GREEN}🎉 All tests completed successfully!${NC}"
echo -e "${BLUE}📊 Coverage report available at: coverage.html${NC}"
echo -e "${BLUE}📚 API documentation available at: http://localhost:8080/swagger/index.html${NC}"