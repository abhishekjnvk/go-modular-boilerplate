package healthHttp

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	healthService "go-boilerplate/internal/pkg/health/service"
	"go-boilerplate/internal/shared/logger"
	"go-boilerplate/internal/shared/utils"
)

// HealthHandler handles HTTP requests for health checks
type HealthHandler struct {
	service healthService.HealthService
	logger  *logger.Logger
}

// NewHealthHandler creates a new health handler
func NewHealthHandler(service *healthService.HealthService, logger *logger.Logger) *HealthHandler {
	return &HealthHandler{
		service: *service,
		logger:  logger.Named("health-handler"),
	}
}

// Health responds with the health status
func (h *HealthHandler) Health(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Get health status
	healthStatus := h.service.Health(r.Context())

	// Determine HTTP status code
	statusCode := http.StatusOK
	if healthStatus.Status != "healthy" {
		statusCode = http.StatusServiceUnavailable
	}

	// Log the request
	h.logger.Info("Health check requested",
		zap.String("status", healthStatus.Status),
		zap.Int("status_code", statusCode),
		zap.Duration("duration", time.Since(start)),
	)

	utils.RespondWithJSON(w, statusCode, healthStatus)
}

// Ready responds with the readiness status
func (h *HealthHandler) Ready(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Get readiness status
	readinessStatus := h.service.Ready(r.Context())

	// Determine HTTP status code
	statusCode := http.StatusOK
	if readinessStatus.Status != "ready" {
		statusCode = http.StatusServiceUnavailable
	}

	// Log the request
	h.logger.Info("Readiness check requested",
		zap.String("status", readinessStatus.Status),
		zap.Int("status_code", statusCode),
		zap.Duration("duration", time.Since(start)),
	)

	utils.RespondWithJSON(w, statusCode, readinessStatus)
}

// GinHealth provides Gin-compatible health check endpoint
func (h *HealthHandler) GinHealth(c *gin.Context) {
	start := time.Now()

	// Get health status
	healthStatus := h.service.Health(c.Request.Context())

	// Determine HTTP status code
	statusCode := http.StatusOK
	if healthStatus.Status != "healthy" {
		statusCode = http.StatusServiceUnavailable
	}

	// Log the request
	h.logger.Info("Health check requested",
		zap.String("status", healthStatus.Status),
		zap.Int("status_code", statusCode),
		zap.Duration("duration", time.Since(start)),
	)

	c.JSON(statusCode, healthStatus)
}

// GinReady provides Gin-compatible readiness check endpoint
func (h *HealthHandler) GinReady(c *gin.Context) {
	start := time.Now()

	// Get readiness status
	readinessStatus := h.service.Ready(c.Request.Context())

	// Determine HTTP status code
	statusCode := http.StatusOK
	if readinessStatus.Status != "ready" {
		statusCode = http.StatusServiceUnavailable
	}

	// Log the request
	h.logger.Info("Readiness check requested",
		zap.String("status", readinessStatus.Status),
		zap.Int("status_code", statusCode),
		zap.Duration("duration", time.Since(start)),
	)

	c.JSON(statusCode, readinessStatus)
}
