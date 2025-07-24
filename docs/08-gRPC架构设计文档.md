# OrAura gRPC 架构设计文档

## 📋 文档概览

本文档详细描述 OrAura 后端服务的 gRPC 架构设计，包括服务定义、数据模型、认证机制、错误处理和性能优化策略。

---

## 🏗️ gRPC 架构概览

### 1. **架构设计原则**

- **微服务架构**: 每个功能模块独立的 gRPC 服务
- **类型安全**: Protocol Buffers 提供强类型定义
- **高性能**: HTTP/2 多路复用，二进制传输
- **向后兼容**: protobuf 版本管理确保 API 兼容性
- **可观测性**: 完整的 tracing、metrics 和 logging

### 2. **服务架构图**

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Mobile App    │    │    Web Client   │    │  Admin Portal   │
│   (iOS/Android) │    │    (React)      │    │   (Dashboard)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                        ┌─────────────────┐
                        │  gRPC Gateway   │
                        │  (HTTP/JSON)    │
                        └─────────────────┘
                                 │
                    ┌─────────────────────────┐
                    │    Load Balancer        │
                    │   (nginx/envoy)         │
                    └─────────────────────────┘
                                 │
        ┌────────────────────────┼────────────────────────┐
        │                       │                       │
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Auth Service   │    │  User Service   │    │ Divination      │
│     :50001      │    │     :50002      │    │   Service       │
└─────────────────┘    └─────────────────┘    │     :50003      │
                                              └─────────────────┘
        │                       │                       │
        └───────────────────────┼───────────────────────┘
                                │
                    ┌─────────────────────────┐
                    │    Shared Resources     │
                    │  PostgreSQL + Redis     │
                    └─────────────────────────┘
```

---

## 📝 Protocol Buffer 服务定义

### 1. **公共类型定义**

```protobuf
// proto/common/v1/common.proto
syntax = "proto3";

package common.v1;

import "google/protobuf/timestamp.proto";

option go_package = "github.com/OrAura/backend/api/common/v1";

// 分页请求
message PaginationRequest {
  int32 page = 1;
  int32 page_size = 2;
  string order_by = 3;
  bool desc = 4;
}

// 分页响应
message PaginationResponse {
  int32 page = 1;
  int32 page_size = 2;
  int32 total_count = 3;
  int32 total_pages = 4;
  bool has_next = 5;
  bool has_prev = 6;
}

// 用户信息
message User {
  string id = 1;
  string email = 2;
  string username = 3;
  string avatar_url = 4;
  google.protobuf.Timestamp created_at = 5;
  google.protobuf.Timestamp updated_at = 6;
  bool is_premium = 7;
  google.protobuf.Timestamp premium_expires_at = 8;
}

// 响应状态
message Status {
  int32 code = 1;
  string message = 2;
  repeated string details = 3;
}
```

### 2. **认证服务定义**

```protobuf
// proto/auth/v1/auth.proto
syntax = "proto3";

package auth.v1;

import "google/protobuf/timestamp.proto";
import "common/v1/common.proto";

option go_package = "github.com/OrAura/backend/api/auth/v1";

service AuthService {
  // 用户注册
  rpc Register(RegisterRequest) returns (RegisterResponse);

  // 用户登录
  rpc Login(LoginRequest) returns (LoginResponse);

  // 刷新令牌
  rpc RefreshToken(RefreshTokenRequest) returns (RefreshTokenResponse);

  // Google OAuth 登录
  rpc GoogleOAuth(GoogleOAuthRequest) returns (GoogleOAuthResponse);

  // Apple OAuth 登录
  rpc AppleOAuth(AppleOAuthRequest) returns (AppleOAuthResponse);

  // 验证令牌
  rpc VerifyToken(VerifyTokenRequest) returns (VerifyTokenResponse);

  // 登出
  rpc Logout(LogoutRequest) returns (LogoutResponse);
}

message RegisterRequest {
  string email = 1;
  string password = 2;
  string username = 3;
  string device_id = 4;
}

message RegisterResponse {
  common.v1.User user = 1;
  string access_token = 2;
  string refresh_token = 3;
  google.protobuf.Timestamp expires_at = 4;
}

message LoginRequest {
  string email = 1;
  string password = 2;
  string device_id = 3;
}

message LoginResponse {
  common.v1.User user = 1;
  string access_token = 2;
  string refresh_token = 3;
  google.protobuf.Timestamp expires_at = 4;
}

message RefreshTokenRequest {
  string refresh_token = 1;
}

message RefreshTokenResponse {
  string access_token = 1;
  string refresh_token = 2;
  google.protobuf.Timestamp expires_at = 3;
}

message GoogleOAuthRequest {
  string id_token = 1;
  string device_id = 2;
}

message GoogleOAuthResponse {
  common.v1.User user = 1;
  string access_token = 2;
  string refresh_token = 3;
  google.protobuf.Timestamp expires_at = 4;
  bool is_new_user = 5;
}

message AppleOAuthRequest {
  string identity_token = 1;
  string authorization_code = 2;
  string device_id = 3;
}

message AppleOAuthResponse {
  common.v1.User user = 1;
  string access_token = 2;
  string refresh_token = 3;
  google.protobuf.Timestamp expires_at = 4;
  bool is_new_user = 5;
}

message VerifyTokenRequest {
  string access_token = 1;
}

message VerifyTokenResponse {
  bool valid = 1;
  common.v1.User user = 2;
  google.protobuf.Timestamp expires_at = 3;
}

message LogoutRequest {
  string access_token = 1;
  string device_id = 2;
}

message LogoutResponse {
  bool success = 1;
}
```

### 3. **占卜服务定义**

```protobuf
// proto/divination/v1/divination.proto
syntax = "proto3";

package divination.v1;

import "google/protobuf/timestamp.proto";
import "common/v1/common.proto";

option go_package = "github.com/OrAura/backend/api/divination/v1";

service DivinationService {
  // 发起占卜咨询
  rpc Ask(AskRequest) returns (AskResponse);

  // 获取占卜历史
  rpc GetHistory(GetHistoryRequest) returns (GetHistoryResponse);

  // 获取占卜详情
  rpc GetDetail(GetDetailRequest) returns (GetDetailResponse);

  // 删除占卜记录
  rpc Delete(DeleteRequest) returns (DeleteResponse);

  // 获取每日运势
  rpc GetDailyFortune(GetDailyFortuneRequest) returns (GetDailyFortuneResponse);

  // 获取占卜类型
  rpc GetDivinationTypes(GetDivinationTypesRequest) returns (GetDivinationTypesResponse);
}

enum DivinationType {
  DIVINATION_TYPE_UNSPECIFIED = 0;
  DIVINATION_TYPE_TAROT = 1;      // 塔罗牌
  DIVINATION_TYPE_ASTROLOGY = 2;  // 星座
  DIVINATION_TYPE_ICHING = 3;     // 易经
  DIVINATION_TYPE_ORACLE = 4;     // 神谕卡
  DIVINATION_TYPE_RUNE = 5;       // 符文
}

message AskRequest {
  string question = 1;
  DivinationType type = 2;
  int32 card_count = 3;  // 抽卡数量（1-3张）
}

message Card {
  string id = 1;
  string name = 2;
  string description = 3;
  string image_url = 4;
  bool is_reversed = 5;  // 是否逆位
  string meaning = 6;
  string reversed_meaning = 7;
}

message AskResponse {
  string session_id = 1;
  string question = 2;
  DivinationType type = 3;
  repeated Card cards = 4;
  string interpretation = 5;  // AI 解读
  string advice = 6;          // 建议
  string image_url = 7;       // 生成的插画
  google.protobuf.Timestamp created_at = 8;
}

message GetHistoryRequest {
  common.v1.PaginationRequest pagination = 1;
  DivinationType type_filter = 2;
  google.protobuf.Timestamp start_date = 3;
  google.protobuf.Timestamp end_date = 4;
}

message DivinationRecord {
  string id = 1;
  string question = 2;
  DivinationType type = 3;
  repeated Card cards = 4;
  string interpretation = 5;
  string advice = 6;
  string image_url = 7;
  google.protobuf.Timestamp created_at = 8;
}

message GetHistoryResponse {
  repeated DivinationRecord records = 1;
  common.v1.PaginationResponse pagination = 2;
}

message GetDetailRequest {
  string id = 1;
}

message GetDetailResponse {
  DivinationRecord record = 1;
}

message DeleteRequest {
  string id = 1;
}

message DeleteResponse {
  bool success = 1;
}

message GetDailyFortuneRequest {
  google.protobuf.Timestamp date = 1;
}

message DailyFortune {
  google.protobuf.Timestamp date = 1;
  string overall_fortune = 2;
  string love_fortune = 3;
  string career_fortune = 4;
  string wealth_fortune = 5;
  string health_fortune = 6;
  string lucky_color = 7;
  int32 lucky_number = 8;
  string advice = 9;
  string image_url = 10;
}

message GetDailyFortuneResponse {
  DailyFortune fortune = 1;
}

message GetDivinationTypesRequest {}

message DivinationTypeInfo {
  DivinationType type = 1;
  string name = 2;
  string description = 3;
  string icon_url = 4;
  bool is_premium = 5;  // 是否需要会员
}

message GetDivinationTypesResponse {
  repeated DivinationTypeInfo types = 1;
}
```

### 4. **情绪跟踪服务定义**

```protobuf
// proto/emotion/v1/emotion.proto
syntax = "proto3";

package emotion.v1;

import "google/protobuf/timestamp.proto";
import "common/v1/common.proto";

option go_package = "github.com/OrAura/backend/api/emotion/v1";

service EmotionService {
  // 记录情绪
  rpc RecordEmotion(RecordEmotionRequest) returns (RecordEmotionResponse);

  // 获取情绪历史
  rpc GetEmotionHistory(GetEmotionHistoryRequest) returns (GetEmotionHistoryResponse);

  // 获取情绪统计
  rpc GetEmotionStats(GetEmotionStatsRequest) returns (GetEmotionStatsResponse);

  // 获取AI情绪分析
  rpc GetEmotionAnalysis(GetEmotionAnalysisRequest) returns (GetEmotionAnalysisResponse);
}

enum EmotionType {
  EMOTION_TYPE_UNSPECIFIED = 0;
  EMOTION_TYPE_VERY_SAD = 1;     // 非常难过
  EMOTION_TYPE_SAD = 2;          // 难过
  EMOTION_TYPE_NEUTRAL = 3;      // 中性
  EMOTION_TYPE_HAPPY = 4;        // 开心
  EMOTION_TYPE_VERY_HAPPY = 5;   // 非常开心
  EMOTION_TYPE_ANXIOUS = 6;      // 焦虑
  EMOTION_TYPE_ANGRY = 7;        // 愤怒
  EMOTION_TYPE_EXCITED = 8;      // 兴奋
  EMOTION_TYPE_CALM = 9;         // 平静
  EMOTION_TYPE_STRESSED = 10;    // 压力大
}

message RecordEmotionRequest {
  EmotionType emotion = 1;
  int32 intensity = 2;  // 强度 1-10
  string note = 3;      // 备注
  repeated string tags = 4;  // 标签
  google.protobuf.Timestamp recorded_at = 5;
}

message RecordEmotionResponse {
  string id = 1;
  EmotionRecord record = 2;
  string ai_feedback = 3;  // AI 反馈建议
}

message EmotionRecord {
  string id = 1;
  EmotionType emotion = 2;
  int32 intensity = 3;
  string note = 4;
  repeated string tags = 5;
  google.protobuf.Timestamp recorded_at = 6;
  google.protobuf.Timestamp created_at = 7;
}

message GetEmotionHistoryRequest {
  common.v1.PaginationRequest pagination = 1;
  google.protobuf.Timestamp start_date = 2;
  google.protobuf.Timestamp end_date = 3;
  repeated EmotionType emotion_filter = 4;
}

message GetEmotionHistoryResponse {
  repeated EmotionRecord records = 1;
  common.v1.PaginationResponse pagination = 2;
}

message GetEmotionStatsRequest {
  google.protobuf.Timestamp start_date = 1;
  google.protobuf.Timestamp end_date = 2;
  string period = 3;  // "day", "week", "month"
}

message EmotionStat {
  EmotionType emotion = 1;
  int32 count = 2;
  double average_intensity = 3;
  double percentage = 4;
}

message EmotionTrend {
  google.protobuf.Timestamp date = 1;
  double average_mood = 2;  // 平均心情分数
  int32 record_count = 3;
}

message GetEmotionStatsResponse {
  repeated EmotionStat emotion_stats = 1;
  repeated EmotionTrend trend_data = 2;
  double overall_mood_score = 3;  // 总体心情分数
  repeated string frequent_tags = 4;  // 常用标签
}

message GetEmotionAnalysisRequest {
  google.protobuf.Timestamp start_date = 1;
  google.protobuf.Timestamp end_date = 2;
}

message GetEmotionAnalysisResponse {
  string analysis = 1;        // AI 分析报告
  string recommendations = 2; // 改善建议
  repeated string insights = 3; // 洞察
  string mood_pattern = 4;    // 心情模式分析
}
```

---

## 🔐 认证与授权机制

### 1. **JWT 认证拦截器**

```go
// internal/interceptors/auth.go
func JWTAuthInterceptor(jwtService *jwt.Service) grpc.UnaryServerInterceptor {
    return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
        // 跳过认证的方法
        if isPublicMethod(info.FullMethod) {
            return handler(ctx, req)
        }

        md, ok := metadata.FromIncomingContext(ctx)
        if !ok {
            return nil, status.Error(codes.Unauthenticated, "missing metadata")
        }

        authHeader := md.Get("authorization")
        if len(authHeader) == 0 {
            return nil, status.Error(codes.Unauthenticated, "missing authorization header")
        }

        token := strings.TrimPrefix(authHeader[0], "Bearer ")
        claims, err := jwtService.VerifyToken(token)
        if err != nil {
            return nil, status.Error(codes.Unauthenticated, "invalid token")
        }

        // 将用户信息添加到上下文
        ctx = context.WithValue(ctx, "user_id", claims.UserID)
        ctx = context.WithValue(ctx, "user", claims.User)

        return handler(ctx, req)
    }
}

func isPublicMethod(method string) bool {
    publicMethods := []string{
        "/auth.v1.AuthService/Register",
        "/auth.v1.AuthService/Login",
        "/auth.v1.AuthService/GoogleOAuth",
        "/auth.v1.AuthService/AppleOAuth",
        "/health.v1.HealthService/Check",
    }

    for _, pm := range publicMethods {
        if method == pm {
            return true
        }
    }
    return false
}
```

### 2. **权限检查拦截器**

```go
// internal/interceptors/authorization.go
func AuthorizationInterceptor() grpc.UnaryServerInterceptor {
    return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
        userID := ctx.Value("user_id").(string)

        // 检查高级功能权限
        if isPremiumMethod(info.FullMethod) {
            user := ctx.Value("user").(*models.User)
            if !user.IsPremium || user.PremiumExpiresAt.Before(time.Now()) {
                return nil, status.Error(codes.PermissionDenied, "premium subscription required")
            }
        }

        // 检查使用限制
        if isLimitedMethod(info.FullMethod) {
            if err := checkUsageLimit(ctx, userID, info.FullMethod); err != nil {
                return nil, err
            }
        }

        return handler(ctx, req)
    }
}
```

---

## 📊 错误处理与状态码

### 1. **错误定义**

```protobuf
// proto/common/v1/errors.proto
syntax = "proto3";

package common.v1;

option go_package = "github.com/OrAura/backend/api/common/v1";

enum ErrorCode {
  ERROR_CODE_UNSPECIFIED = 0;

  // 认证错误 (1000-1099)
  ERROR_CODE_INVALID_CREDENTIALS = 1001;
  ERROR_CODE_TOKEN_EXPIRED = 1002;
  ERROR_CODE_TOKEN_INVALID = 1003;
  ERROR_CODE_USER_NOT_FOUND = 1004;
  ERROR_CODE_EMAIL_ALREADY_EXISTS = 1005;

  // 授权错误 (1100-1199)
  ERROR_CODE_PERMISSION_DENIED = 1101;
  ERROR_CODE_SUBSCRIPTION_REQUIRED = 1102;
  ERROR_CODE_USAGE_LIMIT_EXCEEDED = 1103;

  // 业务逻辑错误 (2000-2999)
  ERROR_CODE_DIVINATION_LIMIT_EXCEEDED = 2001;
  ERROR_CODE_INVALID_DIVINATION_TYPE = 2002;
  ERROR_CODE_AI_SERVICE_UNAVAILABLE = 2003;
  ERROR_CODE_PAYMENT_FAILED = 2004;

  // 系统错误 (9000-9999)
  ERROR_CODE_INTERNAL_ERROR = 9001;
  ERROR_CODE_DATABASE_ERROR = 9002;
  ERROR_CODE_EXTERNAL_SERVICE_ERROR = 9003;
}

message ErrorDetail {
  ErrorCode code = 1;
  string message = 2;
  string field = 3;
  map<string, string> metadata = 4;
}
```

### 2. **错误处理中间件**

```go
// internal/interceptors/error.go
func ErrorHandlingInterceptor() grpc.UnaryServerInterceptor {
    return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
        resp, err := handler(ctx, req)
        if err != nil {
            // 记录错误日志
            logError(ctx, err, info.FullMethod)

            // 转换错误为 gRPC 状态
            st := convertErrorToStatus(err)
            return nil, st.Err()
        }
        return resp, nil
    }
}

func convertErrorToStatus(err error) *status.Status {
    switch e := err.(type) {
    case *errors.AuthError:
        return status.New(codes.Unauthenticated, e.Message)
    case *errors.PermissionError:
        return status.New(codes.PermissionDenied, e.Message)
    case *errors.ValidationError:
        return status.New(codes.InvalidArgument, e.Message)
    case *errors.NotFoundError:
        return status.New(codes.NotFound, e.Message)
    case *errors.BusinessLogicError:
        return status.New(codes.FailedPrecondition, e.Message)
    default:
        return status.New(codes.Internal, "internal server error")
    }
}
```

---

## 🚀 性能优化策略

### 1. **连接池配置**

```go
// pkg/grpc/client/pool.go
type ConnectionPool struct {
    connections chan *grpc.ClientConn
    address     string
    opts        []grpc.DialOption
}

func NewConnectionPool(address string, size int, opts ...grpc.DialOption) *ConnectionPool {
    pool := &ConnectionPool{
        connections: make(chan *grpc.ClientConn, size),
        address:     address,
        opts:        opts,
    }

    // 预创建连接
    for i := 0; i < size; i++ {
        conn, err := grpc.Dial(address, opts...)
        if err != nil {
            panic(err)
        }
        pool.connections <- conn
    }

    return pool
}

func (p *ConnectionPool) Get() *grpc.ClientConn {
    return <-p.connections
}

func (p *ConnectionPool) Put(conn *grpc.ClientConn) {
    select {
    case p.connections <- conn:
    default:
        // 连接池已满，关闭连接
        conn.Close()
    }
}
```

### 2. **缓存策略**

```go
// internal/services/cache_service.go
type CacheService struct {
    redis *redis.Client
}

func (s *CacheService) GetOrSet(ctx context.Context, key string, ttl time.Duration, fn func() (interface{}, error)) (interface{}, error) {
    // 尝试从缓存获取
    cached := s.redis.Get(ctx, key)
    if cached.Err() == nil {
        var result interface{}
        if err := json.Unmarshal([]byte(cached.Val()), &result); err == nil {
            return result, nil
        }
    }

    // 缓存未命中，执行函数
    result, err := fn()
    if err != nil {
        return nil, err
    }

    // 存入缓存
    data, _ := json.Marshal(result)
    s.redis.Set(ctx, key, data, ttl)

    return result, nil
}
```

### 3. **监控指标**

```go
// internal/interceptors/metrics.go
var (
    grpcRequestsTotal = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "grpc_requests_total",
            Help: "Total number of gRPC requests",
        },
        []string{"method", "status"},
    )

    grpcRequestDuration = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "grpc_request_duration_seconds",
            Help: "gRPC request duration in seconds",
            Buckets: prometheus.DefBuckets,
        },
        []string{"method"},
    )
)

func MetricsInterceptor() grpc.UnaryServerInterceptor {
    return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
        start := time.Now()

        resp, err := handler(ctx, req)

        duration := time.Since(start).Seconds()
        status := "success"
        if err != nil {
            status = "error"
        }

        grpcRequestsTotal.WithLabelValues(info.FullMethod, status).Inc()
        grpcRequestDuration.WithLabelValues(info.FullMethod).Observe(duration)

        return resp, err
    }
}
```

---

## 🔧 部署配置

### 1. **Docker 配置**

```dockerfile
# Dockerfile
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o grpc-server cmd/server/main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates tzdata
WORKDIR /root/

COPY --from=builder /app/grpc-server .
COPY --from=builder /app/configs ./configs

EXPOSE 50051 8080

CMD ["./grpc-server"]
```

### 2. **Kubernetes 配置**

```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: oraura-grpc-server
spec:
  replicas: 3
  selector:
    matchLabels:
      app: oraura-grpc-server
  template:
    metadata:
      labels:
        app: oraura-grpc-server
    spec:
      containers:
        - name: grpc-server
          image: oraura/grpc-server:latest
          ports:
            - containerPort: 50051
              name: grpc
            - containerPort: 8080
              name: http
          env:
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: oraura-secrets
                  key: database-url
            - name: REDIS_URL
              valueFrom:
                secretKeyRef:
                  name: oraura-secrets
                  key: redis-url
          livenessProbe:
            grpc:
              port: 50051
          readinessProbe:
            grpc:
              port: 50051
          resources:
            requests:
              memory: "256Mi"
              cpu: "250m"
            limits:
              memory: "512Mi"
              cpu: "500m"

---
apiVersion: v1
kind: Service
metadata:
  name: oraura-grpc-service
spec:
  selector:
    app: oraura-grpc-server
  ports:
    - name: grpc
      port: 50051
      targetPort: 50051
    - name: http
      port: 8080
      targetPort: 8080
  type: LoadBalancer
```

这个 gRPC 架构设计为 OrAura 项目提供了：

1. **高性能**: HTTP/2 多路复用和二进制传输
2. **类型安全**: Protocol Buffers 强类型定义
3. **可扩展性**: 微服务架构，易于水平扩展
4. **兼容性**: gRPC-Gateway 提供 REST API 兼容
5. **可观测性**: 完整的监控和追踪
6. **安全性**: JWT 认证和权限控制

您希望我详细展开哪个部分，或者开始实现具体的服务代码吗？
