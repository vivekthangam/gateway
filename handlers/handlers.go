package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"text/template"
	"time"

	"gateway/config"

	"github.com/buger/jsonparser"  // For easy JSON parsing and manipulation
	"github.com/golang-jwt/jwt/v5" // For JWT handling
	"golang.org/x/time/rate"       // For token bucket rate limiting
)

// MyCustomClaims struct to parse JWT tokens
type MyCustomClaims struct {
	Role string `json:"role"`
	jwt.RegisteredClaims
}

// CachedResponse stores the HTTP response data for caching.
type CachedResponse struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
	Timestamp  time.Time
}

// GatewayHandler handles all incoming requests, routing them to appropriate backend services.
type GatewayHandler struct {
	Routes        []config.Route
	JWTSecret     []byte
	RateLimiters  map[string]*rate.Limiter // Key: routePath + method
	RateLimiterMx sync.Mutex               // Mutex for rateLimiters map
	Cache         *sync.Map                // In-memory cache: map[string]*CachedResponse
}

// NewGatewayHandler creates a new instance of GatewayHandler.
func NewGatewayHandler(cfg *config.GatewayConfig) *GatewayHandler {
	return &GatewayHandler{
		Routes:       cfg.Routes,
		JWTSecret:    []byte(cfg.DefaultAuthSecret),
		RateLimiters: make(map[string]*rate.Limiter),
		Cache:        &sync.Map{}, // Initialize the cache
	}
}

// ServeHTTP implements the http.Handler interface for the GatewayHandler.
func (gh *GatewayHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Find a matching route for the incoming request.
	matchedRoute := gh.findMatchingRoute(r.URL.Path, r.Method)

	if matchedRoute == nil {
		http.Error(w, "404 Not Found: No matching route", http.StatusNotFound)
		return
	}

	// 1. Rate Limiting Check
	if matchedRoute.RateLimit != nil {
		limiter := gh.getOrCreateRateLimiter(matchedRoute.Path+matchedRoute.Method, matchedRoute.RateLimit)
		if !limiter.Allow() {
			http.Error(w, "429 Too Many Requests: Rate limit exceeded", http.StatusTooManyRequests)
			return
		}
	}

	// 2. Authentication & Authorization Check
	if matchedRoute.AuthRequired {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "401 Unauthorized: Missing Authorization header", http.StatusUnauthorized)
			return
		}
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		claims := &MyCustomClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return gh.JWTSecret, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "401 Unauthorized: Invalid or expired token", http.StatusUnauthorized)
			return
		}

		// Authorization check
		if matchedRoute.RequiredRole != "" && claims.Role != matchedRoute.RequiredRole {
			http.Error(w, fmt.Sprintf("403 Forbidden: Insufficient role. Required: %s, Found: %s", matchedRoute.RequiredRole, claims.Role), http.StatusForbidden)
			return
		}

		// Add user info to context for potential use in request transformation or logging
		ctx := context.WithValue(r.Context(), "userRole", claims.Role)
		ctx = context.WithValue(ctx, "userID", claims.Subject) // Assuming Subject is User ID
		r = r.WithContext(ctx)
	}

	// 3. Backward Proxy Cache Lookup
	if matchedRoute.Cache != nil && matchedRoute.Cache.Enabled {
		cacheKey := r.URL.String() + "_" + r.Method // Simple cache key based on URL and Method
		if cached, ok := gh.Cache.Load(cacheKey); ok {
			cachedResp := cached.(*CachedResponse)
			if time.Since(cachedResp.Timestamp) < time.Duration(matchedRoute.Cache.TTLSeconds)*time.Second {
				// Serve from cache
				fmt.Printf("Serving from cache: %s %s\n", r.Method, r.URL.Path)
				for header, values := range cachedResp.Headers {
					for _, value := range values {
						w.Header().Add(header, value)
					}
				}
				w.Header().Set("X-Gateway-Cache", "HIT") // Add a cache hit header
				w.WriteHeader(cachedResp.StatusCode)
				_, err := w.Write(cachedResp.Body)
				if err != nil {
					fmt.Printf("Error writing cached response: %v\n", err)
				}
				return // Request handled by cache
			} else {
				// Cache entry expired, delete it
				fmt.Printf("Cache expired: %s %s\n", r.Method, r.URL.Path)
				gh.Cache.Delete(cacheKey)
			}
		} else {
			fmt.Printf("Cache MISS: %s %s\n", r.Method, r.URL.Path)
		}
	}

	// Parse the target URL from the matched route.
	targetURL, err := url.Parse(matchedRoute.TargetURL)
	if err != nil {
		fmt.Printf("Error parsing target URL %s: %v\n", matchedRoute.TargetURL, err)
		http.Error(w, "500 Internal Server Error: Invalid target URL", http.StatusInternalServerError)
		return
	}

	// Extract only the path component from the parsed target URL.
	backendTargetPath := targetURL.Path
	if !strings.HasPrefix(backendTargetPath, "/") { // Ensure it always starts with a slash
		backendTargetPath = "/" + backendTargetPath
	}

	// Create a new reverse proxy.
	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	// Custom Director: Modifies the request before forwarding to the backend.
	proxy.Director = func(req *http.Request) {
		req.URL.Scheme = targetURL.Scheme
		req.URL.Host = targetURL.Host
		req.Host = targetURL.Host // Set Host header for backend

		// Rewrite path with parameters, now passing only the path part of the target URL.
		req.URL.Path = gh.rewritePathWithParams(matchedRoute.Path, backendTargetPath, r.URL.Path)
		fmt.Printf("Proxying request: %s %s to %s%s\n", r.Method, r.URL.Path, targetURL.Host, req.URL.Path)

		// 4. Request Header Filtering
		for _, headerToRemove := range matchedRoute.RemoveRequestHeaders {
			req.Header.Del(headerToRemove)
		}
		for headerToAdd, value := range matchedRoute.AddRequestHeaders {
			req.Header.Set(headerToAdd, value)
		}
	}

	// Custom ModifyResponse: Modifies the response received from the backend before sending to the client.
	proxy.ModifyResponse = func(resp *http.Response) error {
		// Store original body for caching before potential transformation
		var responseBodyBytes []byte
		if resp.Body != nil {
			responseBodyBytes, err = io.ReadAll(resp.Body)
			if err != nil {
				return fmt.Errorf("error reading backend response body: %w", err)
			}
			resp.Body = io.NopCloser(bytes.NewBuffer(responseBodyBytes)) // Restore body for further processing
		}

		// 5. Response Header Filtering
		for _, headerToRemove := range matchedRoute.RemoveResponseHeaders {
			resp.Header.Del(headerToRemove)
		}
		for headerToAdd, value := range matchedRoute.AddResponseHeaders {
			resp.Header.Set(headerToAdd, value)
		}

		// 6. Response Body Transformation
		if matchedRoute.TransformResponse != nil {
			err = gh.transformResponseBody(resp, matchedRoute.TransformResponse)
			if err != nil {
				fmt.Printf("Error during response body transformation: %v\n", err)
				// Decide how to handle transformation errors:
				// - return err (sends 500 to client)
				// - return nil (sends original/partially transformed response)
				// For now, we'll log and let original response pass
			}
			// If body was transformed, use the transformed body for caching
			transformedBodyBytes, readErr := io.ReadAll(resp.Body)
			if readErr != nil {
				fmt.Printf("Error reading transformed response body for caching: %v\n", readErr)
			} else {
				responseBodyBytes = transformedBodyBytes
				resp.Body = io.NopCloser(bytes.NewBuffer(transformedBodyBytes)) // Restore for client
			}
		}

		// 7. Backward Proxy Cache Storage
		if matchedRoute.Cache != nil && matchedRoute.Cache.Enabled && resp.StatusCode >= 200 && resp.StatusCode < 300 {
			cacheKey := r.URL.String() + "_" + r.Method
			cachedResp := &CachedResponse{
				StatusCode: resp.StatusCode,
				Headers:    resp.Header,       // Store a copy of headers
				Body:       responseBodyBytes, // Store the (potentially transformed) body
				Timestamp:  time.Now(),
			}
			gh.Cache.Store(cacheKey, cachedResp)
			fmt.Printf("Cached response for: %s %s (TTL: %d seconds)\n", r.Method, r.URL.Path, matchedRoute.Cache.TTLSeconds)
			resp.Header.Set("X-Gateway-Cache", "STORED") // Indicate it was stored
		} else {
			resp.Header.Set("X-Gateway-Cache", "PASSTHROUGH") // Indicate no cache used
		}

		return nil // No error returned from ModifyResponse to continue with response
	}

	// Handle errors that occur during proxying (e.g., target service unreachable).
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		fmt.Printf("Proxy error: %v for request %s %s\n", err, r.Method, r.URL.Path)
		http.Error(w, "502 Bad Gateway: Backend service unreachable or error", http.StatusBadGateway)
	}

	proxy.ServeHTTP(w, r)
}

// getOrCreateRateLimiter retrieves an existing rate limiter or creates a new one.
func (gh *GatewayHandler) getOrCreateRateLimiter(key string, rlConfig *config.RateLimit) *rate.Limiter {
	gh.RateLimiterMx.Lock()
	defer gh.RateLimiterMx.Unlock()

	if limiter, ok := gh.RateLimiters[key]; ok {
		return limiter
	}

	// Create a new token bucket limiter with specified limit (r) and burst (b)
	// r is tokens per second, b is the bucket size.
	limiter := rate.NewLimiter(rate.Limit(rlConfig.Limit), rlConfig.Burst)
	gh.RateLimiters[key] = limiter
	return limiter
}

// findMatchingRoute attempts to find a matching route for the given path and method.
// It supports simple path parameters (e.g., /users/{id}).
func (gh *GatewayHandler) findMatchingRoute(requestPath, requestMethod string) *config.Route {
	for _, route := range gh.Routes {
		if route.Method != "" && route.Method != requestMethod {
			continue // Method mismatch, but allow empty method to match all
		}

		// Normalize paths for comparison (remove leading/trailing slashes)
		routePathParts := strings.Split(strings.Trim(route.Path, "/"), "/")
		requestPathParts := strings.Split(strings.Trim(requestPath, "/"), "/")

		if len(routePathParts) != len(requestPathParts) {
			continue // Path length mismatch, can't be a direct match or simple param match
		}

		match := true
		for i, part := range routePathParts {
			if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
				// This part is a path parameter, it matches anything
				continue
			}
			if part != requestPathParts[i] {
				// Non-parameter parts must match exactly
				match = false
				break
			}
		}

		if match {
			return &route
		}
	}
	return nil // No matching route found
}

// rewritePathWithParams constructs the final path for the backend service,
// replacing path parameters from the original request path into the target URL's path template.
func (gh *GatewayHandler) rewritePathWithParams(routePath, backendTargetPathTemplate, requestPath string) string {
	routePathParts := strings.Split(strings.Trim(routePath, "/"), "/")
	requestPathParts := strings.Split(strings.Trim(requestPath, "/"), "/")
	backendTargetPathParts := strings.Split(strings.Trim(backendTargetPathTemplate, "/"), "/")

	// Create a map of parameter names to their values from the request path
	paramMap := make(map[string]string)
	for i, routePart := range routePathParts {
		if strings.HasPrefix(routePart, "{") && strings.HasSuffix(routePart, "}") {
			paramName := strings.Trim(routePart, "{}")
			if i < len(requestPathParts) {
				paramMap[paramName] = requestPathParts[i]
			}
		}
	}

	// Build the rewritten path using the backendTargetPathTemplate and extracted parameters
	rewrittenParts := make([]string, len(backendTargetPathParts))
	for i, targetPart := range backendTargetPathParts {
		if strings.HasPrefix(targetPart, "{") && strings.HasSuffix(targetPart, "}") {
			paramName := strings.Trim(targetPart, "{}")
			if val, ok := paramMap[paramName]; ok {
				rewrittenParts[i] = val
			} else {
				// Fallback: if parameter not found, keep the template part.
				// This should ideally not happen if routePath and backendTargetPathTemplate align.
				rewrittenParts[i] = targetPart
			}
		} else {
			rewrittenParts[i] = targetPart
		}
	}

	return "/" + strings.Join(rewrittenParts, "/")
}

// transformRequestBody handles request body transformations.
func (gh *GatewayHandler) transformRequestBody(req *http.Request, transformCfg *config.RequestTransform) {
	if transformCfg.IgnoreRequestBody {
		req.Body = io.NopCloser(bytes.NewBuffer(nil)) // Set body to empty
		req.ContentLength = 0
		return
	}

	if req.Body == nil {
		return // No body to transform
	}

	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		fmt.Printf("Error reading request body for transformation: %v\n", err)
		return
	}
	defer req.Body.Close()

	if len(bodyBytes) == 0 && (transformCfg.BodyTemplate == "" && len(transformCfg.AddFields) == 0 && len(transformCfg.RemoveFields) == 0) {
		return // No body and no transformation rules specified
	}

	var newBodyBytes []byte
	var currentData map[string]interface{}

	// If the body is JSON, parse it for field manipulation
	if strings.Contains(req.Header.Get("Content-Type"), "application/json") && len(bodyBytes) > 0 {
		err = json.Unmarshal(bodyBytes, &currentData)
		if err != nil {
			fmt.Printf("Warning: Request body is not valid JSON, cannot apply field transformations: %v\n", err)
			// Proceed with template only if present, or original body
			currentData = nil // Ensure currentData is nil if not JSON
		}
	}

	// Apply field additions
	if len(transformCfg.AddFields) > 0 && currentData != nil {
		for key, valTemplate := range transformCfg.AddFields {
			// Simple direct string value for now, complex templating for addFields could be added
			// For a true templated value (e.g., from request context), we'd need to parse the template here.
			// For now, it's just raw string values from config.
			currentData[key] = valTemplate
		}
		newBodyBytes, _ = json.Marshal(currentData) // Marshal back after additions
	} else if len(bodyBytes) > 0 {
		newBodyBytes = bodyBytes // If not JSON or no additions, keep original
	}

	// Apply field removals using jsonparser
	if len(transformCfg.RemoveFields) > 0 && len(newBodyBytes) > 0 {
		newBodyBytes = jsonparser.Delete(newBodyBytes, transformCfg.RemoveFields...)
	}

	// Apply body template if specified
	if transformCfg.BodyTemplate != "" {
		tmpl, err := template.New("reqBodyTransform").Funcs(config.CustomFuncMap).Parse(transformCfg.BodyTemplate)
		if err != nil {
			fmt.Printf("Error parsing request body template: %v\n", err)
			return
		}
		var buf bytes.Buffer
		// Use `currentData` if it was successfully parsed as JSON, otherwise use the original body string.
		// If currentData is nil (e.g., non-JSON body), we pass the raw body bytes.
		templateData := make(map[string]interface{})
		if currentData != nil {
			templateData["."] = currentData // Pass the parsed JSON as "."
		} else if len(bodyBytes) > 0 {
			templateData["."] = string(bodyBytes) // Pass original body as string
		}
		// Add request context data (e.g., user role from auth) to template data
		if role := req.Context().Value("userRole"); role != nil {
			templateData["userRole"] = role
		}
		if userID := req.Context().Value("userID"); userID != nil {
			templateData["userID"] = userID
		}

		err = tmpl.Execute(&buf, templateData)
		if err != nil {
			fmt.Printf("Error executing request body template: %v\n", err)
			return
		}
		newBodyBytes = buf.Bytes()
	}

	// If no template, and no adds/removes, use the original body.
	if newBodyBytes == nil && len(bodyBytes) > 0 {
		newBodyBytes = bodyBytes
	}

	req.Body = io.NopCloser(bytes.NewBuffer(newBodyBytes))
	req.ContentLength = int64(len(newBodyBytes))
	// Update Content-Type if transformation changes it (e.g., from text to JSON)
	if transformCfg.BodyTemplate != "" && strings.Contains(transformCfg.BodyTemplate, "json") {
		req.Header.Set("Content-Type", "application/json")
	}
}

// transformResponseBody handles response body transformations.
func (gh *GatewayHandler) transformResponseBody(resp *http.Response, transformCfg *config.ResponseTransform) error {
	if transformCfg.IgnoreResponseBody {
		resp.Body = io.NopCloser(bytes.NewBuffer(nil)) // Set body to empty
		resp.ContentLength = 0
		return nil
	}

	if resp.Body == nil {
		return nil // No body to transform
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body for transformation: %v\n", err)
		return err
	}
	defer resp.Body.Close()

	if len(bodyBytes) == 0 && (transformCfg.BodyTemplate == "" && len(transformCfg.AddFields) == 0 && len(transformCfg.RemoveFields) == 0) {
		return nil // No body and no transformation rules specified
	}

	var newBodyBytes []byte
	var currentData map[string]interface{}

	// If the body is JSON, parse it for field manipulation
	if strings.Contains(resp.Header.Get("Content-Type"), "application/json") && len(bodyBytes) > 0 {
		err = json.Unmarshal(bodyBytes, &currentData)
		if err != nil {
			fmt.Printf("Warning: Response body is not valid JSON, cannot apply field transformations: %v\n", err)
			currentData = nil // Ensure currentData is nil if not JSON
		}
	}

	// Apply field additions
	if len(transformCfg.AddFields) > 0 && currentData != nil {
		for key, valTemplate := range transformCfg.AddFields {
			// For dynamic values from template, execute the template for the value
			tmpl, err := template.New("addFieldValue").Funcs(config.CustomFuncMap).Parse(valTemplate)
			if err != nil {
				fmt.Printf("Error parsing addField value template for key %s: %v\n", key, err)
				currentData[key] = valTemplate // Fallback to literal if template parse fails
				continue
			}
			var buf bytes.Buffer
			// Pass currentData as the context for the addField value template
			err = tmpl.Execute(&buf, currentData)
			if err != nil {
				fmt.Printf("Error executing addField value template for key %s: %v\n", key, err)
				currentData[key] = valTemplate // Fallback to literal if template exec fails
				continue
			}
			// Attempt to unmarshal as JSON if it looks like one, otherwise keep as string
			var jsonVal interface{}
			if err := json.Unmarshal(buf.Bytes(), &jsonVal); err == nil {
				currentData[key] = jsonVal
			} else {
				currentData[key] = buf.String()
			}
		}
		newBodyBytes, _ = json.Marshal(currentData) // Marshal back after additions
	} else if len(bodyBytes) > 0 {
		newBodyBytes = bodyBytes // If not JSON or no additions, keep original
	}

	// Apply field removals using jsonparser
	if len(transformCfg.RemoveFields) > 0 && len(newBodyBytes) > 0 {
		newBodyBytes = jsonparser.Delete(newBodyBytes, transformCfg.RemoveFields...)
	}

	// Apply body template if specified
	if transformCfg.BodyTemplate != "" {
		tmpl, err := template.New("respBodyTransform").Funcs(config.CustomFuncMap).Parse(transformCfg.BodyTemplate)
		if err != nil {
			fmt.Printf("Error parsing response body template: %v\n", err)
			return err
		}
		var buf bytes.Buffer
		templateData := make(map[string]interface{})
		if currentData != nil {
			templateData["."] = currentData // Pass the parsed JSON as "."
		} else if len(bodyBytes) > 0 {
			templateData["."] = string(bodyBytes) // Pass original body as string
		}
		err = tmpl.Execute(&buf, templateData)
		if err != nil {
			fmt.Printf("Error executing response body template: %v\n", err)
			return err
		}
		newBodyBytes = buf.Bytes()
	}

	if newBodyBytes == nil && len(bodyBytes) > 0 {
		newBodyBytes = bodyBytes
	}

	// Update the response body
	resp.Body = io.NopCloser(bytes.NewBuffer(newBodyBytes))
	resp.ContentLength = int64(len(newBodyBytes))

	// Update Content-Type if transformation changes it (e.g., from text to JSON)
	if transformCfg.BodyTemplate != "" && strings.Contains(transformCfg.BodyTemplate, "json") {
		resp.Header.Set("Content-Type", "application/json")
	}
	return nil
}
