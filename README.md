# Go Web Application Boilerplate

A production-ready Go web application boilerplate with enterprise-grade features including security, monitoring, database optimization, and scalable architecture.

## 🚀 Features

### Core Framework
- **Gin HTTP Framework**: High-performance HTTP web framework
- **Clean Architecture**: Organized into clear layers (API, Service, Repository)
- **JWT Authentication**: Secure token-based authentication
- **Security Headers**: Comprehensive security headers (CSP, HSTS, etc.)

### Database & Caching
- **PostgreSQL**: Primary database with connection pooling
- **Read/Write Splitting**: Automatic routing to read replicas
- **Redis Caching**: Session management and data caching
- **Redis Cluster**: Horizontal scaling and high availability
- **Query Monitoring**: Slow query detection and logging

### Monitoring & Logging
- **Structured Logging**: JSON-based logging with file rotation
- **Health Checks**: Database and Redis connectivity monitoring
- **Rate Limiting**: Configurable rate limiting with Redis storage
- **Performance Monitoring**: Request timing and metrics

## 📁 Project Structure

```
go.mod
go.sum
README.md
cmd/
├── api/
│   └── main.go
└── worker/
    └── main.go
configs/
├── config.example.yaml
└── config.yaml
internal/
├── app/
│   ├── api/
│   │   └── server.go
│   └── config/
│       └── config.go
├── pkg/
│   ├── auth/
│   │   ├── auth_types.go
│   │   ├── delivery/
│   │   │   └── http/
│   │   │       ├── auth_handler.go
│   │   │       └── auth_router.go
│   │   ├── repository/
│   │   │   └── auth_repository.go
│   │   └── service/
│   │       └── auth_service.go
│   ├── health/
│   │   ├── database_checker.go
│   │   ├── health_types.go
│   │   ├── redis_checker.go
│   │   ├── delivery/
│   │   │   └── http/
│   │   │       └── health_handler.go
│   │   └── service/
│   │       └── health_service.go
│   └── user/
│       ├── user_types.go
│       ├── delivery/
│       │   └── http/
│       │       ├── user_handler.go
│       │       └── user_router.go
│       ├── repository/
│       │   └── user_repository.go
│       └── service/
│           └── user_service.go
├── scheduler/
│   ├── cron.go
│   └── services/
│       ├── cleanup_service.go
│       ├── database_health_check_job.go
│       ├── health_history.go
│       └── report_service.go
└── shared/
    ├── cache/
    │   └── redis.go
    ├── cookies/
    │   └── cookies.go
    ├── database/
    │   ├── database.go
    │   └── read_write.go
    ├── logger/
    │   └── logger.go
    ├── metrics/
    │   └── metrics.go
    ├── middleware/
    │   ├── auth_middleware.go
    │   ├── logging_middleware.go
    │   ├── rate_limit_middleware.go
    │   ├── recovery_middleware.go
    │   └── security_middleware.go
    └── utils/
        └── http_utils.go
├── utils/
│   ├── device_detection.go
│   ├── password/
│   │   └── hash.go
│   └── request/
│       └── json.go
logs/
├── db-health.json
├── debug.log
├── error.log
├── info.log
└── warn.log
migration/
├── 001_create_test_table.go
└── migration.go
scripts/
└── migrate.go
tmp/
├── build-errors.log
└── main
tools/
└── health_history_viewer.go
```

## 🛠️ Quick Start

### Prerequisites
- Go 1.21+
- PostgreSQL 13+
- Redis 6+

### Installation

1. **Clone and setup**:
   ```bash
   git clone <repository-url>
   cd go-boilerplate
   go mod download
   ```

2. **Database setup**:
   ```bash
   go run scripts/migrate.go up
   ```

3. **Configuration**:
   ```bash
   cp configs/config.yaml configs/config.local.yaml
   # Edit config.local.yaml with your credentials
   ```

4. **Run**:
   ```bash
   go run cmd/api/main.go
   ```

## ⚙️ Configuration

### Key Settings

```yaml
app:
  port: 8080
  environment: "development"

database:
  host: "localhost"
  name: "go_boilerplate"
  read_write_splitting: true
  slow_query_threshold: "100ms"

redis:
  host: "localhost"
  port: 6379

auth:
  jwt_secret: "your-secret-key"
  jwt_expiration: "24h"

rate_limiting:
  max_attempts: 100
  window: "1m"
  burst_size: 10
```

### Environment Variables
- `DB_HOST`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`
- `REDIS_HOST`, `REDIS_PORT`
- `JWT_SECRET`
- `APP_ENV`, `APP_PORT`

## 🔒 Security Features

### Security Headers
- Content Security Policy (CSP)
- X-Frame-Options, X-Content-Type-Options
- Strict-Transport-Security (HSTS)
- XSS Protection, Referrer Policy

### Rate Limiting
```go
// Basic rate limiting
rateLimiter.GinRateLimitWithOptions(middleware.RateLimitOptions{
    Window:    60,  // seconds
    Limit:     100, // requests
    BurstSize: 10,  // burst allowance
    KeyPrefix: "api",
})
```

## 🗄️ Database Features

### Read/Write Splitting
- Automatic routing: reads to replicas, writes to primary
- Load balancing across multiple read replicas
- Health monitoring and failover

### Query Monitoring
- Slow query detection and logging
- Execution time tracking
- Configurable thresholds

## � Redis Features

### Single Node & Cluster Support
- Automatic detection of Redis mode
- Seamless scaling from single node to cluster
- Connection pooling and health checks

### Usage
```go
// Works with both single node and cluster
redisClient.Set(ctx, "key", "value", time.Hour)
result := redisClient.Get(ctx, "key")
```

## 📊 Monitoring & Health Checks

### Health Endpoints
- `GET /health` - Overall health status
- `GET /health/database` - Database connectivity
- `GET /health/redis` - Redis connectivity

### Logging
- Structured JSON logs
- Configurable log levels
- File rotation and compression

## 🧪 Testing

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run integration tests
go test -tags=integration ./...
```

## 🚀 Deployment

### Docker
```dockerfile
FROM golang:1.21-alpine
WORKDIR /app
COPY . .
RUN go build -o main cmd/api/main.go
CMD ["./main"]
```

### Production Checklist
- [ ] Set `APP_ENV=production`
- [ ] Configure production database
- [ ] Set strong `JWT_SECRET`
- [ ] Enable security headers
- [ ] Configure monitoring
- [ ] Set up Redis cluster (optional)



## 🧩 Migrations

This project includes a simple migration system under `migration` and a CLI runner at `scripts/migrate.go`.

- Migration files live in `migration` and register themselves using `Register(id, name, migration)` in `init()`.
- Each migration implements two methods:
  - `Up(tx *sql.Tx) error` — apply the migration inside a transaction.
  - `Down(tx *sql.Tx) error` — rollback the migration inside a transaction.

### Running migrations

- Apply all pending migrations (Up):
```bash
go run scripts/migrate.go --dir up
```

  - Roll back a specific migration id (for example `001`):
```bash
go run scripts/migrate.go --dir down --target 001
```

Notes:
- Each migration runs in a transaction; on error the transaction is rolled back and the migration process stops.
- The applied migrations are recorded in the `schema_migrations` table (`id`, `name`, `applied_at`).
- If you prefer to run migrations against a different DSN without changing `configs`, you can add a `--dsn` flag or `DATABASE_URL` env var fallback to the CLI.