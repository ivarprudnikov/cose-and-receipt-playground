package main

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/ivarprudnikov/cose-and-receipt-playground/internal/countersigner"
	"github.com/ivarprudnikov/cose-and-receipt-playground/internal/keys"
	"github.com/ivarprudnikov/cose-and-receipt-playground/internal/signer"
	"github.com/veraison/go-cose"
)

//go:embed web/index.html
var indexHtml string

const MAX_FORM_SIZE = int64(32 << 20) // 32 MB

// indexHandler returns the main index page
func indexHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate") // HTTP 1.1
	w.Header().Set("Pragma", "no-cache")                                   // HTTP 1.0
	w.Header().Set("Expires", "0")                                         // Proxies
	w.Header().Add("Content-Type", "text/html")
	fmt.Fprint(w, indexHtml)
}

// didHandler returns a DID document for the current server
func didHandler(w http.ResponseWriter, r *http.Request) {
	didDoc, err := keys.CreateDoc(getHostPort(), keys.GetKeyDefault().Public())
	if err != nil {
		sendError(w, "failed to create did doc", err)
		return
	}
	w.Header().Add("Content-Type", "application/json")
	fmt.Fprint(w, didDoc)
}

// sigCreateHandler creates a signature for a payload provided in the request
func sigCreateHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseMultipartForm(MAX_FORM_SIZE)
	if err != nil {
		sendError(w, "failed to read request body parameters", err)
		return
	}
	contentType := r.PostForm.Get("contenttype")
	if strings.Trim(contentType, " ") == "" {
		contentType = "text/plain"
	}
	payload := r.PostForm.Get("payload")
	if payload == "" {
		sendError(w, "payload is empty", nil)
		return
	}
	payloadHash := sha256.Sum256([]byte(payload))
	payloadHashHex := hex.EncodeToString(payloadHash[:])

	signature, err := signer.CreateSignature([]byte(payload), contentType, getHostPort())
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

// sigVerifyHandler verifies a signature provided in the request
func sigVerifyHandler(w http.ResponseWriter, r *http.Request) {
	signature, err := readBytesFromForm(r, "signaturefile", "signaturehex", false)
	if err != nil {
		sendError(w, "failed to read signature", err)
		return
	}
	err = signer.VerifySignature(signature, nil)
	if err != nil {
		sendError(w, "failed to verify signature", err)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	fmt.Fprintf(w, `{
		"valid": true
	}`)
}

// receiptCreateHandler creates a receipt for a signature provided in the request
func receiptCreateHandler(w http.ResponseWriter, r *http.Request) {
	STANDALONE := "standalone"

	signature, err := readBytesFromForm(r, "signaturefile", "signaturehex", false)
	if err != nil {
		sendError(w, "failed to read signature", err)
		return
	}
	receiptType := r.PostForm.Get("receipttype")
	if receiptType == "" {
		receiptType = STANDALONE
	}

	err = signer.VerifySignature(signature, nil)
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
	receipt, err := countersigner.Countersign(msg, getHostPort(), receiptType != STANDALONE)
	if err != nil {
		sendError(w, "failed to countersign", err)
		return
	}
	var filename string
	if receiptType == STANDALONE {
		filename = fmt.Sprintf(`receipt.%s.cbor`, signatureHashHex)
	} else {
		filename = fmt.Sprintf(`signature.%s.embedded.cose`, signatureHashHex)
	}
	receiptHex := hex.EncodeToString(receipt)
	w.Header().Add("Content-Type", "application/cbor")
	w.Header().Add("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Header().Add("Content-Transfer-Encoding", "binary")
	w.Header().Add("Content-Length", fmt.Sprintf("%d", len(receipt)))
	w.Header().Add("X-Receipt-Hex", receiptHex)
	w.Write(receipt)
}

// receiptVerifyHandler verifies a receipt and a signature provided in the request
func receiptVerifyHandler(w http.ResponseWriter, r *http.Request) {
	signatureB, err := readBytesFromForm(r, "signaturefile", "signaturehex", false)
	if err != nil {
		sendError(w, "failed to read signature", err)
		return
	}

	var signature cose.Sign1Message
	if err = signature.UnmarshalCBOR(signatureB); err != nil {
		sendError(w, "failed to unmarshal signature bytes", err)
		return
	}

	receiptB, err := readBytesFromForm(r, "receiptfile", "receipthex", true)
	if err != nil {
		sendError(w, "failed to read receipt", err)
		return
	}

	if len(receiptB) == 0 {
		embeddedReceiptRaw := signature.Headers.Unprotected[countersigner.COSE_Countersignature_header]
		var ok bool
		receiptB, ok = embeddedReceiptRaw.([]byte)
		if !ok || len(receiptB) == 0 {
			sendError(w, "failed to get receipt bytes from both the request and the signature header", nil)
			return
		}
	}

	var receipt cose.Sign1Message
	if err = receipt.UnmarshalCBOR(receiptB); err != nil {
		sendError(w, "failed to unmarshal receipt bytes", err)
		return
	}

	err = countersigner.Verify(receipt, signature)
	if err != nil {
		sendError(w, "failed to verify receipt", err)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	fmt.Fprintf(w, `{
		"valid": true
	}`)
}

// main starts the server
func main() {
	http.HandleFunc("/.well-known/did.json", didHandler)
	http.HandleFunc("/signature/create", sigCreateHandler)
	http.HandleFunc("/signature/verify", sigVerifyHandler)
	http.HandleFunc("/receipt/create", receiptCreateHandler)
	http.HandleFunc("/receipt/verify", receiptVerifyHandler)
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/index.html", indexHandler)
	port := getPort()
	listenAddr := ":" + port
	log.Printf("About to listen on %s. Go to https://127.0.0.1%s/", listenAddr, listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, nil))
}

// readBytesFromForm reads bytes from either a file or a hex string from the form fields
func readBytesFromForm(r *http.Request, filekey string, hexkey string, isOptional bool) ([]byte, error) {
	err := r.ParseMultipartForm(MAX_FORM_SIZE)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body parameters: %w", err)
	}

	formFiles := r.MultipartForm.File[filekey]
	formHex := r.PostForm.Get(hexkey)

	if formHex == "" && len(formFiles) == 0 {
		if isOptional {
			return []byte{}, nil
		}
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

type ApiError struct {
	Message string `json:"message"`
	Error   string `json:"error"`
}

// sendError sends a json error response
func sendError(w http.ResponseWriter, message string, err error) {
	if err == nil {
		err = errors.New(message)
	}
	log.Printf("%s: %+v", message, err)
	w.Header().Set("Content-Type", "application/json")
	apiError := ApiError{
		Message: message,
		Error:   err.Error(),
	}
	apiErrorJson, marshalErr := json.Marshal(apiError)
	if marshalErr != nil {
		log.Fatalf("failed to marshal error: %+v", marshalErr)
	}
	w.WriteHeader(http.StatusBadRequest)
	fmt.Fprint(w, string(apiErrorJson))
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
