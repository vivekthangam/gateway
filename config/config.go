	package config

	import (
		"encoding/json"
		"fmt"
		"os"
		"time" // For `now` function in templates
	)

	// RateLimit defines the rate limiting parameters for a route.
	type RateLimit struct {
		Limit int `json:"limit"` // Maximum requests per second (or interval, depending on implementation)
		Burst int `json:"burst"` // Maximum initial burst of requests
	}

	// CacheConfig defines caching parameters for a route.
	type CacheConfig struct {
		Enabled    bool `json:"enabled"`    // Whether caching is enabled for this route
		TTLSeconds int  `json:"ttlSeconds"` // Time-to-live for cache entries in seconds
	}

	// TransformBody defines body transformation rules.
	type TransformBody struct {
		BodyTemplate string            `json:"bodyTemplate"` // Go template string for body transformation
		AddFields    map[string]string `json:"addFields"`    // Fields to add to JSON body (templateable values)
		RemoveFields []string          `json:"removeFields"` // Fields to remove from JSON body
	}

	// RequestTransform defines rules for transforming incoming requests.
	type RequestTransform struct {
		TransformBody
		IgnoreRequestBody bool `json:"ignoreRequestBody"` // Whether to ignore the incoming request body
	}

	// ResponseTransform defines rules for transforming outgoing responses.
	type ResponseTransform struct {
		TransformBody
		IgnoreResponseBody bool `json:"ignoreResponseBody"` // Whether to ignore the outgoing response body
	}

	// Route defines a single routing rule for the API Gateway with advanced features.
	type Route struct {
		Path                  string             `json:"path"`
		Method                string             `json:"method"`
		TargetURL             string             `json:"targetUrl"`
		AuthRequired          bool               `json:"authRequired"`          // Whether authentication is required
		RequiredRole          string             `json:"requiredRole"`          // Required role for authorization
		RateLimit             *RateLimit         `json:"rateLimit"`             // Rate limiting configuration
		Cache                 *CacheConfig       `json:"cache"`                 // Caching configuration
		AddRequestHeaders     map[string]string  `json:"addRequestHeaders"`     // Headers to add to the backend request
		RemoveRequestHeaders  []string           `json:"removeRequestHeaders"`  // Headers to remove from the backend request
		AddResponseHeaders    map[string]string  `json:"addResponseHeaders"`    // Headers to add to the client response
		RemoveResponseHeaders []string           `json:"removeResponseHeaders"` // Headers to remove from the client response
		TransformRequest      *RequestTransform  `json:"transformRequest"`      // Request body transformation rules
		TransformResponse     *ResponseTransform `json:"transformResponse"`     // Response body transformation rules
	}

	// GatewayConfig holds the entire configuration for the API Gateway.
	type GatewayConfig struct {
		Port              int     `json:"port"`              // The port on which the gateway will listen
		DefaultAuthSecret string  `json:"defaultAuthSecret"` // Default secret for JWT validation
		Routes            []Route `json:"routes"`            // A list of defined routes
	}

	// LoadConfig reads the gateway configuration from a specified JSON file.
	func LoadConfig(filePath string) (*GatewayConfig, error) {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file %s: %w", filePath, err)
		}

		var cfg GatewayConfig
		err = json.Unmarshal(data, &cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal config file %s: %w", filePath, err)
		}

		return &cfg, nil
	}

	// CustomFuncMap for Go templates to include 'json' and 'now' functions
	var CustomFuncMap = map[string]interface{}{
		"json": func(v interface{}) (string, error) {
			b, err := json.Marshal(v)
			if err != nil {
				return "", err
			}
			return string(b), nil
		},
		"now": func() string {
			return time.Now().Format(time.RFC3339)
		},
	}
