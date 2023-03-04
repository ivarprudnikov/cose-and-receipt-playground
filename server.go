package main

import (
	"embed"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"

	"github.com/ivarprudnikov/cose-and-receipt-playground/keys"
	"github.com/ivarprudnikov/cose-and-receipt-playground/signer"
)

//go:embed static/*
var static embed.FS

func didHandler(w http.ResponseWriter, r *http.Request) {
	didDoc, err := keys.CreateDoc(getHostPort())
	if err != nil {
		sendError(w, "failed to create did doc", err)
		return
	}
	w.Header().Add("Content-Type", "application/json")
	fmt.Fprint(w, didDoc)
}

func signHandler(w http.ResponseWriter, r *http.Request) {
	body := []byte{}
	var err error
	if r.Body != nil {
		defer r.Body.Close()
		body, err = io.ReadAll(r.Body)
		if err != nil {
			sendError(w, "reading request body failed", err)
			return
		}
	}

	signature, err := signer.CreateSignature(body, getHostPort())
	if err != nil {
		sendError(w, "failed to create signature", err)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	fmt.Fprintf(w, `{
		"payloadHex": "%s",
		"payloadBase64": "%s",
		"signatureHex": "%s",
		"signatureBase64": "%s"
	}`, hex.EncodeToString(body), base64.RawStdEncoding.EncodeToString(body), hex.EncodeToString(signature), base64.RawStdEncoding.EncodeToString(signature))
}

func main() {
	http.HandleFunc("/.well-known/did.json", didHandler)
	http.HandleFunc("/sign", signHandler)

	contentStatic, err := fs.Sub(static, "static")

	if err != nil {
		log.Fatal(err)
	}
	http.Handle("/", http.FileServer(http.FS(contentStatic)))

	port := getPort()
	listenAddr := ":" + port
	log.Printf("About to listen on %s. Go to https://127.0.0.1%s/", listenAddr, listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, nil))
}

func sendError(w http.ResponseWriter, message string, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	fmt.Fprintf(w, `{ "message": "%s", "error": "%v" }`, message, err)
}

func getHostPort() string {
	if val, ok := os.LookupEnv("WEBSITE_HOSTNAME"); ok {
		return val
	}
	return "localhost:" + getPort()
}

func getPort() string {
	if val, ok := os.LookupEnv("FUNCTIONS_CUSTOMHANDLER_PORT"); ok {
		return val
	}
	return "8080"
}
