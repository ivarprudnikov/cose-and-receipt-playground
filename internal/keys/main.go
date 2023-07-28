package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"log"
	"os"

	"github.com/veraison/go-cose"
)

const SHARED_DIR = "/var/tmp/fn/playground-cose-eastus-dir"

var privateKey *ecdsa.PrivateKey

func init() {
	var err error
	var keyBytes []byte

	// Load private key from file if it exists
	filename := SHARED_DIR + "/generated.ecdsa.key"
	if _, err = os.Stat(filename); err == nil {
		keyBytes, err = os.ReadFile(filename)
		if err == nil {
			privateKey, err = x509.ParseECPrivateKey(keyBytes)
			if err != nil {
				log.Printf("Failed to parse private key: %s", err.Error())
			}
		} else {
			log.Printf("Failed to read private key file: %s", err.Error())
		}
	}

	// create new private key if it doesn't exist
	if privateKey == nil {
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		keyBytes, err = x509.MarshalECPrivateKey(privateKey)
		if err != nil {
			panic(err)
		}
		os.WriteFile(filename, keyBytes, 0600)
	}
}

func GetKeyDefault() *ecdsa.PrivateKey {
	return privateKey
}

func GetCoseSignerDefault() (cose.Signer, error) {
	return GetCoseSignerFor(cose.AlgorithmES256, GetKeyDefault())
}

func GetCoseSignerFor(alg cose.Algorithm, key crypto.Signer) (cose.Signer, error) {
	return cose.NewSigner(alg, key)
}

func GetCoseVerifierDefault() (cose.Verifier, error) {
	return GetCoseVerifierFor(cose.AlgorithmES256, GetKeyDefault().Public())
}

func GetCoseVerifierFor(alg cose.Algorithm, pubKey crypto.PublicKey) (cose.Verifier, error) {
	return cose.NewVerifier(alg, pubKey)
}
