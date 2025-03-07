package main

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"log/slog"
	"strings"
	"sync"
	"time"

	"net/http"

	"github.com/ivarprudnikov/cose-and-receipt-playground/internal/countersigner"
	"github.com/ivarprudnikov/cose-and-receipt-playground/internal/keys"
	"github.com/ivarprudnikov/cose-and-receipt-playground/internal/signer"
	"github.com/veraison/go-cose"
	"golang.org/x/time/rate"
)

const MAX_FORM_SIZE = int64(32 << 20) // 32 MB
const MAX_REQ_SEC = 2
const MAX_REQ_BURST = 4
const TEMPLATES_MATCH = "web/*.tmpl.html"

// templates get embedded in the binary
//
//go:embed web
var templatesFs embed.FS

var tmpl *template.Template

func init() {
	tmpl = template.Must(template.ParseFS(templatesFs, TEMPLATES_MATCH))
	matches, _ := fs.Glob(templatesFs, TEMPLATES_MATCH)
	for _, v := range matches {
		log.Printf("Using template file: %s", v)
	}
}

func AddRoutes(mux *http.ServeMux, keystore *keys.KeyStore) {
	pre := newAppMiddleware()
	mux.Handle("GET /.well-known/did.json", pre(DidHandler(keystore)))
	mux.Handle("POST /signature/create", pre(SigCreateHandler(keystore)))
	mux.Handle("POST /signature/verify", pre(sigVerifyHandler()))
	mux.Handle("POST /receipt/create", pre(receiptCreateHandler(keystore)))
	mux.Handle("POST /receipt/verify", pre(receiptVerifyHandler(keystore)))
	mux.Handle("GET /", pre(IndexHandler()))
	mux.Handle("GET /index.html", pre(IndexHandler()))
	mux.Handle("GET /favicon.ico", pre(FaviconHandler()))
}

// Main app middleware called before each request
func newAppMiddleware() func(h http.Handler) http.Handler {

	// Rate limiter
	type client struct {
		limiter  *rate.Limiter
		lastSeen time.Time
	}
	var (
		mu      sync.Mutex
		clients = make(map[string]*client)
	)
	// cleanup clients map every minute
	go func() {
		for {
			time.Sleep(time.Minute)
			// Lock the mutex to protect this section from race conditions.
			mu.Lock()
			for ip, client := range clients {
				if time.Since(client.lastSeen) > 3*time.Minute {
					delete(clients, ip)
				}
			}
			mu.Unlock()
		}
	}()

	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Log all request headers first
			///////////////////////////////
			var allHeaders []slog.Attr
			for k, v := range r.Header {
				allHeaders = append(allHeaders, slog.String(k, strings.Join(v, ", ")))
			}
			slog.LogAttrs(r.Context(), slog.LevelDebug, "request headers", allHeaders...)

			// Apply rate limiter
			///////////////////////////////

			// Extract the IP address from the X-Forwarded-For header.

			xForwardedForValues := r.Header.Values("X-Forwarded-For")
			if len(xForwardedForValues) <= 0 {
				// Rate limiter not applicable
				h.ServeHTTP(w, r)
				return
			}
			xForwardedFor := strings.Join(xForwardedForValues, ",")
			if xForwardedFor == "" {
				// Rate limiter not applicable
				h.ServeHTTP(w, r)
				return
			}
			// Lock the mutex to protect this section from race conditions.
			mu.Lock()
			if _, found := clients[xForwardedFor]; !found {
				clients[xForwardedFor] = &client{limiter: rate.NewLimiter(MAX_REQ_SEC, MAX_REQ_BURST)}
			}
			clients[xForwardedFor].lastSeen = time.Now()
			if !clients[xForwardedFor].limiter.Allow() {
				mu.Unlock()
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			mu.Unlock()

			// Continue with the request
			h.ServeHTTP(w, r)
		})
	}
}

// IndexHandler returns the main index page
func IndexHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/index.html" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate") // HTTP 1.1
		w.Header().Set("Pragma", "no-cache")                                   // HTTP 1.0
		w.Header().Set("Expires", "0")                                         // Proxies
		w.Header().Add("Content-Type", "text/html")

		tmpl.ExecuteTemplate(w, "index.tmpl.html", map[string]interface{}{
			"defaultHeaders": signer.PrintHeaders(
				signer.DefaultHeaders(
					*signer.NewIssuer(signer.DidWeb, getHostPort(), "keyid", [][]byte{[]byte("")}),
				),
			),
		})
	}
}

func FaviconHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Cache-Control", "public, max-age=86400")
		w.Header().Add("Content-Type", "image/svg+xml")
		fmt.Fprint(w, `<svg id="emoji" viewBox="0 0 72 72" xmlns="http://www.w3.org/2000/svg">
  <g id="color">
    <path fill="#F4AA41" stroke="none" d="M33.5357,31.9911c-1.4016-4.2877-0.2247-9.41,3.4285-13.0632c5.018-5.018,12.8077-5.3639,17.3989-0.7727 s4.2452,12.381-0.7728,17.3989c-4.057,4.057-10.4347,5.5131-14.2685,2.5888"/>
    <polyline fill="#F4AA41" stroke="#F4AA41" stroke-linecap="round" stroke-linejoin="round" stroke-miterlimit="10" stroke-width="2" points="33.652,31.7364 31.2181,34.1872 14.6444,50.5142 14.6444,57.6603 21.0426,57.6603 21.0426,53.0835 26.0544,53.0835 26.0544,47.3024 32.04,47.3024 34.3913,44.9292 34.3913,40.6274 36.3618,40.6274 39.4524,37.5368"/>
    <polygon fill="#E27022" stroke="none" points="15.9847,53.3457 15.9857,51.4386 31.8977,35.8744 32.8505,36.8484"/>
    <circle cx="48.5201" cy="23.9982" r="3.9521" fill="#E27022" stroke="none"/>
  </g>
  <g id="hair"/>
  <g id="skin"/>
  <g id="skin-shadow"/>
  <g id="line">
    <polyline fill="none" stroke="#000000" stroke-linecap="round" stroke-linejoin="round" stroke-miterlimit="10" stroke-width="2" points="30.735,34.6557 14.3026,50.6814 14.3026,57.9214 21.868,57.9214 21.868,53.2845 26.9929,53.2845 26.9929,47.4274 32.0913,47.4274 34.4957,45.023 34.4957,40.6647 36.5107,40.6647"/>
    <circle cx="48.5201" cy="23.9982" r="3.9521" fill="none" stroke="#000000" stroke-linecap="round" stroke-linejoin="round" stroke-miterlimit="10" stroke-width="2"/>
    <path fill="none" stroke="#000000" stroke-linecap="round" stroke-linejoin="round" stroke-miterlimit="10" stroke-width="2" d="M34.2256,31.1781c-1.4298-4.2383-0.3466-9.2209,3.1804-12.6947c4.8446-4.7715,12.4654-4.8894,17.0216-0.2634 s4.3223,12.2441-0.5223,17.0156c-3.9169,3.8577-9.6484,4.6736-14.1079,2.3998"/>
  </g>
</svg>`)
	}
}

// DidHandler returns a DID document for the current server
func DidHandler(keystore *keys.KeyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		didDoc, err := keys.CreateDoc(getHostPort(), keystore.GetPubKey(), keystore.GetB64CertChain())
		if err != nil {
			sendError(w, "failed to create did doc", err)
			return
		}
		w.Header().Add("Content-Type", "application/json")
		fmt.Fprint(w, didDoc)
	}
}

// SigCreateHandler creates a signature for a payload provided in the request
func SigCreateHandler(keystore *keys.KeyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		payloadB, err := readBytesFromForm(r, "payloadfile", "payloadhex", "payload", false)
		if err != nil {
			sendError(w, "failed to read payload", err)
			return
		}

		kv := map[string]string{}
		// @Deprecated use for backwards compatibility when using contenttype field in the form
		contentType := r.PostForm.Get("contenttype")
		if strings.Trim(contentType, " ") != "" {
			kv["3"] = contentType
		}
		headerKeys := r.PostForm["headerkey"]
		headerVals := r.PostForm["headerval"]
		for i, k := range headerKeys {
			if i >= len(headerVals) {
				break
			}
			kv[k] = headerVals[i]
		}

		payloadHash := sha256.Sum256(payloadB)
		payloadHashHex := hex.EncodeToString(payloadHash[:])

		// TODO add support for custom issuer profile switch
		issuer := signer.NewIssuer(signer.DidWeb, getHostPort(), keystore.GetPublicKeyId(), keystore.GetCertChain())
		signature, err := signer.CreateSignature(issuer, payloadB, kv, keystore)
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
}

// sigVerifyHandler verifies a signature provided in the request
func sigVerifyHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		signature, err := readBytesFromForm(r, "signaturefile", "signaturehex", "", false)
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
}

// receiptCreateHandler creates a receipt for a signature provided in the request
func receiptCreateHandler(keystore *keys.KeyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		STANDALONE := "standalone"

		signature, err := readBytesFromForm(r, "signaturefile", "signaturehex", "", false)
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
		receipt, err := countersigner.Countersign(msg, keystore, getHostPort(), receiptType != STANDALONE)
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
}

// receiptVerifyHandler verifies a receipt and a signature provided in the request
func receiptVerifyHandler(keystore *keys.KeyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		signatureB, err := readBytesFromForm(r, "signaturefile", "signaturehex", "", false)
		if err != nil {
			sendError(w, "failed to read signature", err)
			return
		}

		var signature cose.Sign1Message
		if err = signature.UnmarshalCBOR(signatureB); err != nil {
			sendError(w, "failed to unmarshal signature bytes", err)
			return
		}

		receiptB, err := readBytesFromForm(r, "receiptfile", "receipthex", "", true)
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

		err = countersigner.Verify(receipt, signature, keystore)
		if err != nil {
			sendError(w, "failed to verify receipt", err)
			return
		}

		w.Header().Add("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"valid": true
		}`)
	}
}

// readBytesFromForm reads bytes from either a file or a hex or a text from the form fields
func readBytesFromForm(r *http.Request, filekey string, hexkey string, textkey string, isOptional bool) ([]byte, error) {
	err := r.ParseMultipartForm(MAX_FORM_SIZE)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body parameters: %w", err)
	}

	formFiles := r.MultipartForm.File[filekey]
	formHex := r.PostForm.Get(hexkey)
	formText := r.PostForm.Get(textkey)

	fileExists := len(formFiles) > 0
	hexExists := formHex != ""
	textExists := formText != ""

	detectedValues := 0
	for _, v := range []bool{fileExists, hexExists, textExists} {
		if v {
			detectedValues++
		}
	}

	if detectedValues < 1 {
		if isOptional {
			return []byte{}, nil
		}
		return nil, fmt.Errorf("%s or %s is required", filekey, hexkey)
	}

	if detectedValues > 1 {
		return nil, errors.New("only one representation is allowed, choose file or hex or text if possible")
	}

	var content []byte
	var fileAttachment io.ReadCloser
	if fileExists {
		fileAttachment, err = formFiles[0].Open()
		if err != nil {
			return nil, fmt.Errorf("failed to open file: %w", err)
		}
		defer fileAttachment.Close()
		content, err = io.ReadAll(fileAttachment)
		if err != nil {
			return nil, fmt.Errorf("failed to read attachment: %w", err)
		}
	} else if hexExists {
		content, err = hex.DecodeString(formHex)
		if err != nil {
			return nil, fmt.Errorf("failed to read hex: %w", err)
		}
	} else if textExists {
		content = []byte(formText)
	}
	return content, nil
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
