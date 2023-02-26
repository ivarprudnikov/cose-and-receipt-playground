package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

func healthHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "ok")
}

func didHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "did")
}

func signHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "signing")
}

func main() {
	listenAddr := ":8080"
	if val, ok := os.LookupEnv("FUNCTIONS_CUSTOMHANDLER_PORT"); ok {
		listenAddr = ":" + val
	}
	http.HandleFunc("/.well-known/did.json", didHandler)
	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/sign", signHandler)
	log.Printf("About to listen on %s. Go to https://127.0.0.1%s/", listenAddr, listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, nil))
}
