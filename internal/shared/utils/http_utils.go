package utils

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"go.uber.org/zap"

	"go-boilerplate/internal/shared/logger"
)

// Response is a standardized API response structure
type Response struct {
	Status     string      `json:"status"`     // "success" or "error"
	StatusCode int         `json:"statusCode"` // HTTP status code
	Message    string      `json:"message"`    // Human-readable message
	Data       interface{} `json:"data"`       // Primary payload (can be null)
	Meta       interface{} `json:"meta"`       // For pagination, etc. (can be null)
	Timestamp  time.Time   `json:"timestamp"`  // Time of response
	Duration   string      `json:"duration"`   // Request processing time
}

// HTTPError is a struct for handling HTTP errors
type HTTPError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Err     error  `json:"-"`
}

func (e *HTTPError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

// StatusCode returns the HTTP status code
func (e *HTTPError) StatusCode() int {
	return e.Code
}

// NewHTTPError creates a new HTTP error
func NewHTTPError(code int, message string, err error) *HTTPError {
	return &HTTPError{
		Code:    code,
		Message: message,
		Err:     err,
	}
}

// RespondWithSuccess formats and writes a successful response
func RespondWithSuccess(
	w http.ResponseWriter,
	r *http.Request,
	start time.Time,
	message string,
	data interface{},
	meta interface{},
	statusCode int,
) {
	duration := time.Since(start)

	response := &Response{
		Status:     "success",
		StatusCode: statusCode,
		Message:    message,
		Data:       data,
		Meta:       meta,
		Timestamp:  time.Now().UTC(),
		Duration:   duration.String(),
	}

	// Set Content-Type header
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	// Encode response to JSON
	if err := json.NewEncoder(w).Encode(response); err != nil {
		// If encoding fails, log the error and send a plain text response
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

// RespondWithError formats and writes an error response
func RespondWithError(
	w http.ResponseWriter,
	r *http.Request,
	start time.Time,
	message string,
	err error,
	statusCode int,
	log *logger.Logger,
) {
	duration := time.Since(start)

	// Log the error
	log.Error(
		"HTTP error",
		zap.String("method", r.Method),
		zap.String("path", r.URL.Path),
		zap.Int("status_code", statusCode),
		zap.String("message", message),
		zap.Error(err),
		zap.Duration("duration", duration),
	)

	response := &Response{
		Status:     "error",
		StatusCode: statusCode,
		Message:    message,
		Data:       nil,
		Meta:       nil,
		Timestamp:  time.Now().UTC(),
		Duration:   duration.String(),
	}

	// Set Content-Type header
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	// Encode response to JSON
	if err := json.NewEncoder(w).Encode(response); err != nil {
		// If encoding fails, log the error and send a plain text response
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

// DecodeJSON decodes JSON from an HTTP request
func DecodeJSON(r *http.Request, v interface{}) error {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		return NewHTTPError(http.StatusBadRequest, "Invalid JSON payload", err)
	}
	return nil
}

// RespondWithJSON sends a raw JSON response (not wrapped in standard response format)
func RespondWithJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		// If encoding fails, send a plain text error
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}
