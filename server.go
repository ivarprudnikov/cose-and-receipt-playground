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

	"github.com/ivarprudnikov/cose-and-receipt-playground/countersigner"
	"github.com/ivarprudnikov/cose-and-receipt-playground/keys"
	"github.com/ivarprudnikov/cose-and-receipt-playground/signer"
	"github.com/veraison/go-cose"
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
	signature, err := readBytesFromForm(r, "signaturefile", "signaturehex")
	if err != nil {
		sendError(w, "failed to read signature", err)
		return
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

func receiptCreateHandler(w http.ResponseWriter, r *http.Request) {
	signature, err := readBytesFromForm(r, "signaturefile", "signaturehex")
	if err != nil {
		sendError(w, "failed to read signature", err)
		return
	}
	err = signer.VerifySignature(signature)
	if err != nil {
		sendError(w, "failed to verify signature", err)
		return
	}
	signatureHash := sha256.Sum256([]byte(signature))
	signatureHashHex := hex.EncodeToString(signatureHash[:])

	var msg cose.Sign1Message
	if err = msg.UnmarshalCBOR(signature); err != nil {
		sendError(w, "failed to unmarshal signature bytes", err)
		return
	}
	receipt, err := countersigner.Countersign(msg, getHostPort())
	if err != nil {
		sendError(w, "failed to countersign", err)
		return
	}
	receiptHex := hex.EncodeToString(receipt)
	w.Header().Add("Content-Type", "application/cbor")
	w.Header().Add("Content-Disposition", fmt.Sprintf(`attachment; filename="receipt.%s.cbor"`, signatureHashHex))
	w.Header().Add("Content-Transfer-Encoding", "binary")
	w.Header().Add("Content-Length", fmt.Sprintf("%d", len(receipt)))
	w.Header().Add("X-Receipt-Hex", receiptHex)
	w.Write(receipt)
}

func main() {
	http.HandleFunc("/.well-known/did.json", didHandler)
	http.HandleFunc("/signature/create", sigCreateHandler)
	http.HandleFunc("/signature/verify", sigVerifyHandler)
	http.HandleFunc("/receipt/create", receiptCreateHandler)
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/index.html", indexHandler)
	port := getPort()
	listenAddr := ":" + port
	log.Printf("About to listen on %s. Go to https://127.0.0.1%s/", listenAddr, listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, nil))
}

// readBytesFromForm reads bytes from either a file or a hex string form fields
func readBytesFromForm(r *http.Request, filekey string, hexkey string) ([]byte, error) {
	err := r.ParseMultipartForm(maxFormSize)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body parameters: %w", err)
	}

	formFiles := r.MultipartForm.File[filekey]
	formHex := r.PostForm.Get(hexkey)

	if formHex == "" && len(formFiles) == 0 {
		return nil, fmt.Errorf("%s or %s is required", filekey, hexkey)
	}

	if formHex != "" && len(formFiles) > 0 {
		return nil, errors.New("only one representation is allowed, use file or hex")
	}

	var signature []byte
	var fileAttachment io.ReadCloser
	if len(formFiles) > 0 {
		fileAttachment, err = formFiles[0].Open()
		if err != nil {
			return nil, fmt.Errorf("failed to open file: %w", err)
		}
		defer fileAttachment.Close()
		signature, err = io.ReadAll(fileAttachment)
		if err != nil {
			return nil, fmt.Errorf("failed to read attachment: %w", err)
		}
	} else {
		signature, err = hex.DecodeString(formHex)
		if err != nil {
			return nil, fmt.Errorf("failed to read hex: %w", err)
		}
	}
	return signature, nil
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
