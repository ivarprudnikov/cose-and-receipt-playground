package main

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/ivarprudnikov/cose-and-receipt-playground/keys"
	"github.com/ivarprudnikov/cose-and-receipt-playground/signer"
)

//go:embed index.html
var indexHtml string

const maxFormSize = int64(32 << 20) // 32 MB

func indexHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate") // HTTP 1.1
	w.Header().Set("Pragma", "no-cache")                                   // HTTP 1.0
	w.Header().Set("Expires", "0")                                         // Proxies
	w.Header().Add("Content-Type", "text/html")
	fmt.Fprint(w, indexHtml)
}

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
	payloadHash := sha256.Sum256([]byte(payload))
	payloadHashHex := hex.EncodeToString(payloadHash[:])

	signature, err := signer.CreateSignature([]byte(payload), getHostPort())
	if err != nil {
		sendError(w, "failed to create signature", err)
		return
	}
	signatureHex := hex.EncodeToString(signature)
	w.Header().Add("Content-Type", "application/cose")
	w.Header().Add("Content-Disposition", fmt.Sprintf(`attachment; filename="signature.%s.cose"`, payloadHashHex))
	w.Header().Add("Content-Transfer-Encoding", "binary")
	w.Header().Add("Content-Length", fmt.Sprintf("%d", len(signature)))
	w.Header().Add("X-Signature-Hex", signatureHex)
	w.Write(signature)
}

func sigVerifyHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseMultipartForm(maxFormSize)
	if err != nil {
		sendError(w, "failed to read request body parameters", err)
		return
	}

	signaturefiles := r.MultipartForm.File["signaturefile"]
	signaturehex := r.PostForm.Get("signaturehex")

	if signaturehex == "" && len(signaturefiles) == 0 {
		sendError(w, "signaturefile or signaturehex is required", nil)
		return
	}

	if signaturehex != "" && len(signaturefiles) > 0 {
		sendError(w, "only one representation is allowed, use file or hex", nil)
		return
	}

	var signature []byte
	var fileAttachment io.ReadCloser
	if len(signaturefiles) > 0 {
		fileAttachment, err = signaturefiles[0].Open()
		if err != nil {
			sendError(w, "failed to open signature file", err)
			return
		}
		defer fileAttachment.Close()
		signature, err = io.ReadAll(fileAttachment)
		if err != nil {
			sendError(w, "failed to read signature attachment", err)
			return
		}
	} else {
		signature, err = hex.DecodeString(signaturehex)
		if err != nil {
			sendError(w, "failed to read signature hex", err)
			return
		}
	}

	err = signer.VerifySignature(signature)
	if err != nil {
		sendError(w, "failed to verify signature", err)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	fmt.Fprintf(w, `{
		"valid": true
	}`)
}

func main() {
	http.HandleFunc("/.well-known/did.json", didHandler)
	http.HandleFunc("/signature/create", sigCreateHandler)
	http.HandleFunc("/signature/verify", sigVerifyHandler)
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/index.html", indexHandler)
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
