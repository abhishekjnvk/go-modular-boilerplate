package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"

	"go-boilerplate/internal/app/api"
	"go-boilerplate/internal/app/config"
	authHttp "go-boilerplate/internal/pkg/auth/delivery/http"
	authRepository "go-boilerplate/internal/pkg/auth/repository"
	authService "go-boilerplate/internal/pkg/auth/service"
	"go-boilerplate/internal/pkg/health"
	healthHttp "go-boilerplate/internal/pkg/health/delivery/http"
	healthService "go-boilerplate/internal/pkg/health/service"
	userHttp "go-boilerplate/internal/pkg/user/delivery/http"
	userRepository "go-boilerplate/internal/pkg/user/repository"
	userService "go-boilerplate/internal/pkg/user/service"
	"go-boilerplate/internal/shared/cache"
	"go-boilerplate/internal/shared/database"
	"go-boilerplate/internal/shared/logger"
	"go-boilerplate/internal/shared/metrics"
	"go-boilerplate/internal/shared/middleware"
)

func main() {
	// Load configuration
	cfg, err := config.LoadConfig("./configs")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize logger
	appLogger := logger.New(cfg.Environment)
	defer appLogger.Sync()

	// Initialize metrics (if enabled)
	var metricsCollector *metrics.Metrics
	if cfg.MetricsEnabled {
		metricsCollector = metrics.New(appLogger)
	}

	// Initialize database connection
	rwDBConfig := database.NewReadWriteConfig(cfg)
	rwDB, err := database.NewReadWriteDatabase(rwDBConfig, appLogger, metricsCollector)
	if err != nil {
		appLogger.Fatal("Failed to connect to database", zap.Error(err))
	}
	defer rwDB.Close()

	// Start database health monitoring
	// ctx := context.Background()

	// Initialize Redis connection
	redisConfig := cache.DefaultConfig(cfg)
	redisClient, err := cache.New(redisConfig, appLogger)
	if err != nil {
		appLogger.Fatal("Failed to connect to Redis", zap.Error(err))
	}
	defer redisClient.Close()

	// Initialize middleware
	authMiddleware, err := middleware.NewAuthMiddleware(appLogger)
	if err != nil {
		appLogger.Fatal("Failed to initialize auth middleware", zap.Error(err))
	}
	loggingMiddleware := middleware.NewLoggingMiddleware(appLogger)
	recoveryMiddleware := middleware.NewRecoveryMiddleware(appLogger)
	securityMiddleware := middleware.NewSecurityMiddleware(appLogger, cfg.Environment == "development")
	requestIDMiddleware := middleware.NewRequestIDMiddleware(appLogger)

	// Initialize rate limiting middleware
	rateLimitConfig := middleware.DefaultRateLimitConfig()
	rateLimitMiddleware := middleware.NewRateLimitMiddleware(rateLimitConfig, redisClient, appLogger)

	// Initialize repositories
	authRepo := authRepository.NewPostgresAuthRepository(rwDB, appLogger)
	userRepo := userRepository.NewPostgresUserRepository(rwDB, appLogger)

	// Initialize services
	authSvc, err := authService.NewAuthService(authRepo, cfg, appLogger, metricsCollector)
	if err != nil {
		appLogger.Fatal("Failed to initialize auth service", zap.Error(err))
	}
	userSvc := userService.NewUserService(userRepo, appLogger)

	// Initialize health service
	healthSvc := healthService.NewHealthService("1.0.0", appLogger)
	healthSvc.AddChecker(health.NewRedisHealthChecker(redisClient, appLogger))

	// Initialize handlers
	authHandler := authHttp.NewAuthHandler(authSvc, appLogger)
	userHandler := userHttp.NewUserHandler(userSvc, appLogger)
	healthHandler := healthHttp.NewHealthHandler(healthSvc, appLogger)

	// Initialize HTTP server
	serverOptions := &api.ServerOptions{
		Config:              cfg,
		Logger:              appLogger,
		AuthHandler:         authHandler,
		UserHandler:         userHandler,
		HealthHandler:       healthHandler,
		AuthMiddleware:      authMiddleware,
		LoggingMiddleware:   loggingMiddleware,
		RecoveryMiddleware:  recoveryMiddleware,
		SecurityMiddleware:  securityMiddleware,
		RateLimitMiddleware: rateLimitMiddleware,
		RequestIDMiddleware: requestIDMiddleware,
		Metrics:             metricsCollector,
	}

	server := api.NewServer(serverOptions)

	// Set up graceful shutdown
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	// Start server in a goroutine
	go func() {
		if err := server.Start(); err != nil {
			appLogger.Fatal("Failed to start server", zap.Error(err))
		}
	}()

	appLogger.Info("Server is running", zap.Int("port", cfg.ServerPort), zap.String("environment", cfg.Environment))

	// Wait for interrupt signal
	<-done
	appLogger.Info("Server is shutting down...")

	// Create a deadline for graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Attempt graceful shutdown
	if err := server.Stop(ctx); err != nil {
		appLogger.Fatal("Server shutdown failed", zap.Error(err))
	}

	appLogger.Info("Server gracefully stopped")
}
