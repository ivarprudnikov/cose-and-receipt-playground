package main

import (
	"log"
	"log/slog"
	"net/http"
	"os"
)

func NewHttpHandler() http.Handler {
	mux := http.NewServeMux()
	AddRoutes(mux)
	return mux
}

// main starts the server
func main() {
	// Setup a default logger and the level
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		AddSource: true,
		Level:     slog.LevelDebug,
	}))
	slog.SetDefault(logger)
	handler := NewHttpHandler()
	port := getPort()
	listenAddr := "127.0.0.1:" + port
	log.Printf("About to listen on %s. Go to http://%s/", port, listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, handler))
}

// getHostPort returns the host and port of this function app
func getHostPort() string {
	if val, ok := os.LookupEnv("WEBSITE_HOSTNAME"); ok {
		return val
	}
	return "localhost:" + getPort()
}

// getPort returns the port of this function app
func getPort() string {
	if val, ok := os.LookupEnv("FUNCTIONS_CUSTOMHANDLER_PORT"); ok {
		return val
	}
	return "8080"
}
