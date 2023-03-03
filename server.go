package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/veraison/go-cose"
)

var privateKey *ecdsa.PrivateKey
var signer cose.Signer
var t time.Time

//go:embed static/*
var static embed.FS

const KEY_ID = "foobar"

// https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/
const ISSUER_HEADER_KEY = 391

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

func didHandler(w http.ResponseWriter, r *http.Request) {

	hostport := getDidHostPort()

	key, err := jwk.New(privateKey)
	if err != nil {
		sendError(w, "failed to create symmetric key", err)
		return
	}
	if _, ok := key.(jwk.ECDSAPrivateKey); !ok {
		sendError(w, fmt.Sprintf("expected jwk.SymmetricKey, got %T\n", key), err)
		return
	}

	key.Set(jwk.KeyIDKey, KEY_ID)
	buf, err := json.MarshalIndent(key, "", "  ")
	if err != nil {
		sendError(w, "failed to marshal key into JSON", err)
		return
	}

	didDoc := fmt.Sprintf(`{
		"@context": [
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/suites/jws-2020/v1"
		],
		"id": "did:web:%s",
		"assertionMethod": [{
			"id": "did:web:%s#%s",
			"type": "JsonWebKey2020",
			"controller": "did:web:%s",
			"publicKeyJwk": %s
		}]
	}`, hostport, hostport, KEY_ID, hostport, buf)

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

	// create message header
	// TODO: add kid and did issuer pointing to this service
	headers := cose.Headers{
		Protected: cose.ProtectedHeader{
			cose.HeaderLabelAlgorithm: cose.AlgorithmES256,
			cose.HeaderLabelKeyID:     []byte(KEY_ID),
			ISSUER_HEADER_KEY:         []byte("did:web:" + getDidHostPort()),
		},
	}
	// sign and marshal message
	signature, err := cose.Sign1(rand.Reader, signer, headers, body, nil)
	if err != nil {
		sendError(w, "signing failed", err)
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
	http.HandleFunc("/.well-known/did.json", didHandler)
	http.HandleFunc("/sign", signHandler)

	contentStatic, err := fs.Sub(static, "static")

	if err != nil {
		log.Fatal(err)
	}
	http.Handle("/", http.FileServer(http.FS(contentStatic)))

	port := getPort()
	log.Printf("About to listen on %s. Go to https://127.0.0.1%s/", port, port)
	log.Fatal(http.ListenAndServe(port, nil))
}

func sendError(w http.ResponseWriter, message string, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	fmt.Fprintf(w, `{ "message": "%s", "error": "%v" }`, message, err)
}

func getDidHostPort() string {
	port := getPort()
	hostname := "localhost%3A" + port
	if val, ok := os.LookupEnv("WEBSITE_HOSTNAME"); ok {
		hostname = val
	}
	return hostname
}

func getPort() string {
	listenAddr := ":8080"
	if val, ok := os.LookupEnv("FUNCTIONS_CUSTOMHANDLER_PORT"); ok {
		listenAddr = ":" + val
	}
	return listenAddr
}
