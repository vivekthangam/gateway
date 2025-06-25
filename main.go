package main

import (
	"fmt"
	"io" // Added for mock backend body reading
	"log"
	"net/http"
	"strings" // Added for mock backend path trimming

	"gateway/config"   // Import our local config package
	"gateway/handlers" // Import our local handlers package
)

func main() {
	// Define the path to the routes configuration file.
	routesConfigPath := "routes.json"

	// Load the entire gateway configuration from routes.json.
	cfg, err := config.LoadConfig(routesConfigPath)
	if err != nil {
		log.Fatalf("Failed to load gateway configuration: %v", err)
	}

	// Create a new GatewayHandler with the loaded configuration.
	gatewayHandler := handlers.NewGatewayHandler(cfg)

	// Set up the HTTP server.
	mux := http.NewServeMux()
	// Register the GatewayHandler to handle all incoming requests ("/" matches everything).
	mux.Handle("/", gatewayHandler)

	// Start the HTTP server on the configured port from `cfg.Port`.
	addr := fmt.Sprintf(":%d", cfg.Port)
	fmt.Printf("API Gateway starting on %s\n", addr)
	fmt.Printf("Routes loaded from %s:\n", routesConfigPath)
	for _, route := range cfg.Routes {
		fmt.Printf("  - %s %s -> %s\n", route.Method, route.Path, route.TargetURL)
	}

	// ListenAndServe blocks until the server shuts down.
	log.Fatal(http.ListenAndServe(addr, mux))
}

// Simple mock backend service for testing.
// These mock services will start automatically due to the init() function.
func startMockBackend(port int, serviceName string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("[%s] Received %s /users request\n", serviceName, r.Method)
		if r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `[{"id": 1, "name": "Alice %s"}, {"id": 2, "name": "Bob %s"}]`, serviceName, serviceName)
		} else if r.Method == "POST" {
			bodyBytes, _ := io.ReadAll(r.Body)
			r.Body.Close()
			fmt.Printf("[%s] Request Body: %s\n", serviceName, string(bodyBytes))
			w.WriteHeader(http.StatusCreated)
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"message": "User created in %s service!", "receivedBody": %s}`, serviceName, string(bodyBytes))
		} else {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/users/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			id := strings.TrimPrefix(r.URL.Path, "/users/")
			fmt.Printf("[%s] Received %s /users/%s request\n", serviceName, r.Method, id)
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"id": %s, "name": "User %s from %s", "details": "some details for %s"}`, id, id, serviceName, id)
		} else {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/products", func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("[%s] Received %s /products request\n", serviceName, r.Method)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `[{"id": 101, "name": "Laptop %s"}, {"id": 102, "name": "Mouse %s"}]`, serviceName, serviceName)
	})

	mux.HandleFunc("/products/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			id := strings.TrimPrefix(r.URL.Path, "/products/")
			fmt.Printf("[%s] Received %s /products/%s request\n", serviceName, r.Method, id)
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"id": %s, "name": "Product %s from %s"}`, id, id, serviceName)
		} else {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("[%s] Received %s /dashboard request\n", serviceName, r.Method)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, `Welcome to the %s Admin Dashboard!`, serviceName)
	})

	fmt.Printf("Mock Backend '%s' starting on :%d\n", serviceName, port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), mux))
}

// The init() function starts the mock backend services automatically when the gateway starts.
func init() {
	go startMockBackend(8081, "ServiceA") // Mock for /serviceA (e.g., users service)
	go startMockBackend(8082, "ServiceB") // Mock for /serviceB (e.g., products service)
	go startMockBackend(8083, "ServiceC") // Mock for /admin (e.g., admin service)
}
