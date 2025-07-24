# Git 忽略文件说明

## 被忽略的文件类型

### 🔒 敏感配置文件
- `configs/app.env` - 包含数据库密码、JWT密钥等敏感信息
- `.env*` - 各种环境配置文件
- `*.pem`, `*.key`, `*.crt` - TLS证书和私钥

### 🤖 AI工具配置
- `.claude/` - Claude AI 配置文件夹
- `../.claude/` - 父级目录的 Claude 配置
- `**/.claude/` - 任意层级的 Claude 配置

### 🔧 构建产物
- `bin/` - Go编译后的二进制文件
- `dist/` - 分发包
- `*.exe`, `*.dll`, `*.so`, `*.dylib` - 各平台的可执行文件

### 🧪 测试文件
- `*.test` - Go测试二进制文件
- `*.test.out` - 测试输出文件
- `*.test.bak` - 测试备份文件
- `*_test.go.bak` - 测试源码备份

### 📝 临时文件
- `logs/` - 日志文件夹
- `tmp/`, `temp/` - 临时文件夹
- `uploads/`, `media/` - 上传文件
- `.DS_Store` - macOS系统文件

### 💻 IDE配置
- `.vscode/` - VS Code配置
- `.idea/` - JetBrains IDE配置
- `*.swp`, `*.swo` - Vim临时文件

## 🔐 安全注意事项

**永远不要提交以下类型的文件：**
- 包含密码、API密钥的配置文件
- TLS私钥和证书
- 用户上传的文件
- 数据库文件
- 日志文件（可能包含敏感信息）

## 📋 检查忽略状态

```bash
# 查看被忽略的文件
git status --ignored

# 检查特定文件是否被忽略
git check-ignore configs/app.env

# 强制添加被忽略的文件（谨慎使用）
git add -f some-ignored-file
```

## 🔄 已从Git中移除的文件

以下文件已从Git跟踪中移除但保留在本地：
- `configs/app.env` - 环境配置文件
- `.claude/settings.local.json` - Claude配置文件

这些文件现在被 `.gitignore` 忽略，不会意外提交到仓库。