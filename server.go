package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/veraison/go-cose"
)

var privateKey *ecdsa.PrivateKey
var signer cose.Signer
var t time.Time

//go:embed static/*
var static embed.FS

func init() {
	t = time.Now()
	var err error
	privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	signer, err = cose.NewSigner(cose.AlgorithmES256, privateKey)
	if err != nil {
		panic(err)
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "ok")
}

func didHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "did")
}

func signHandler(w http.ResponseWriter, r *http.Request) {
	body := []byte{}
	var err error
	if r.Body != nil {
		defer r.Body.Close()
		body, err = io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{ "message": "reading request body failed", "error": "%v" }`, err)
			return
		}
	}

	// create message header
	// TODO: add kid and did issuer pointing to this service
	headers := cose.Headers{
		Protected: cose.ProtectedHeader{
			cose.HeaderLabelAlgorithm: cose.AlgorithmES256,
		},
	}
	// sign and marshal message
	signature, err := cose.Sign1(rand.Reader, signer, headers, body, nil)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{ "message": "signing failed", "error": "%v" }`, err)
		return
	}
	w.Header().Add("Content-Type", "application/json")
	fmt.Fprintf(w, `{
		"data": "%s",
		"keyCreatedAt":"%v", 
		"COSE_Sign1": "%s"
	}`, hex.EncodeToString(body), t.UTC().String(), hex.EncodeToString(signature))
}

func main() {
	listenAddr := ":8080"
	if val, ok := os.LookupEnv("FUNCTIONS_CUSTOMHANDLER_PORT"); ok {
		listenAddr = ":" + val
	}
	http.HandleFunc("/.well-known/did.json", didHandler)
	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/sign", signHandler)

	contentStatic, err := fs.Sub(static, "static")

	if err != nil {
		log.Fatal(err)
	}
	http.Handle("/", http.FileServer(http.FS(contentStatic)))

	log.Printf("About to listen on %s. Go to https://127.0.0.1%s/", listenAddr, listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, nil))
}
