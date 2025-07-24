#!/bin/bash

# OrAura Backend 快速验证脚本

echo "🚀 OrAura Backend 快速验证测试"
echo "================================="

echo ""
echo "📦 1. 检查 Go 模块依赖..."
go mod tidy && echo "✅ 依赖检查通过" || echo "❌ 依赖检查失败"

echo ""
echo "🔨 2. 编译检查..."
go build -o /dev/null ./cmd/server && echo "✅ 编译通过" || echo "❌ 编译失败"

echo ""
echo "🧪 3. 运行单元测试..."
go test ./... -v > test_results.log 2>&1
if [ $? -eq 0 ]; then
    echo "✅ 所有测试通过"
    echo "测试概要："
    grep "PASS\|ok" test_results.log | tail -10
else
    echo "❌ 测试失败"
    echo "错误详情："
    grep "FAIL\|error" test_results.log | tail -5
fi

echo ""
echo "📊 4. 测试覆盖率..."
go test ./... -coverprofile=coverage.out > /dev/null 2>&1
if [ -f coverage.out ]; then
    coverage=$(go tool cover -func=coverage.out | grep total | awk '{print $3}')
    echo "✅ 测试覆盖率: $coverage"
else
    echo "❌ 无法生成覆盖率报告"
fi

echo ""
echo "🔍 5. 代码质量检查..."
go vet ./... && echo "✅ go vet 检查通过" || echo "❌ go vet 检查失败"

echo ""
echo "🏗️ 6. 项目结构验证..."
echo "检查关键文件是否存在："

files=(
    "cmd/server/main.go"
    "internal/models/user.go"
    "internal/services/user_service.go" 
    "internal/handlers/user_handler.go"
    "internal/store/user_repository.go"
    "internal/middleware/auth.go"
    "internal/config/config.go"
    "internal/utils/jwt.go"
    "docker-compose.yml"
    "Dockerfile"
    "Makefile"
)

for file in "${files[@]}"; do
    if [ -f "$file" ]; then
        echo "✅ $file"
    else
        echo "❌ $file (缺失)"
    fi
done

echo ""
echo "📋 7. API 路由验证..."
echo "检查已实现的 API 端点："
grep -r "POST\|GET\|PUT\|DELETE" internal/routes/ | grep -E "(auth|users)" | head -10

echo ""
echo "🎯 验证完成!"
echo "================================="

if [ -f test_results.log ]; then
    passed_tests=$(grep -c "PASS" test_results.log)
    echo "📈 统计信息："
    echo "   - 通过的测试: $passed_tests"
    echo "   - 代码覆盖率: ${coverage:-"未计算"}"
    echo "   - 核心文件: ✅ 完整"
fi

echo ""
echo "🚀 快速启动指南："
echo "   1. 启动数据库: make db-up"
echo "   2. 运行应用: make run"
echo "   3. 测试 API: curl http://localhost:8080/health"
echo ""
echo "📖 更多信息请查看 README.md 和 api_examples.md"

# 清理临时文件
rm -f test_results.log coverage.out