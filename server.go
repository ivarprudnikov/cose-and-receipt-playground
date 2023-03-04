package main

import (
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
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

func sigCreateHandler(w http.ResponseWriter, r *http.Request) {

	err := r.ParseForm()
	if err != nil {
		sendError(w, "failed to read request body parameters", err)
		return
	}
	payload := r.PostForm.Get("payload")
	if payload == "" {
		sendError(w, "payload is empty", nil)
		return
	}

	signature, err := signer.CreateSignature([]byte(payload), getHostPort())
	if err != nil {
		sendError(w, "failed to create signature", err)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	fmt.Fprintf(w, `{
		"payloadHex": "%s",
		"signatureHex": "%s"
	}`, hex.EncodeToString([]byte(payload)), hex.EncodeToString(signature))
}

type verifyBody struct {
	SignatureHex string `json:"signatureHex"`
}

func sigVerifyHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		sendError(w, "failed to read request body parameters", err)
		return
	}
	signaturejson := r.PostForm.Get("signaturejson")
	if signaturejson == "" {
		sendError(w, "signaturejson is empty", nil)
		return
	}
	var verifyBody verifyBody
	err = json.Unmarshal([]byte(signaturejson), &verifyBody)
	if err != nil {
		sendError(w, "unmarshal request body failed", err)
		return
	}

	signature, err := hex.DecodeString(verifyBody.SignatureHex)
	if err != nil {
		sendError(w, "failed to read signature hex", err)
		return
	}

	err = signer.VerifySignature(signature)
	if err != nil {
		sendError(w, "failed to verify signature", err)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	fmt.Fprintf(w, `{
		"status": "ok"
	}`)
}

func main() {
	http.HandleFunc("/.well-known/did.json", didHandler)
	http.HandleFunc("/signature/create", sigCreateHandler)
	http.HandleFunc("/signature/verify", sigVerifyHandler)

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

func readRequestBody(r *http.Request) ([]byte, error) {
	if r.Method != http.MethodPost {
		return nil, errors.New("method not allowed")
	}

	if r.Body == nil {
		return nil, errors.New("request body is empty")
	}

	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("reading request body failed: %w", err)
	}

	return body, nil
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
