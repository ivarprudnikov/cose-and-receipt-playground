package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
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
		if err != nil {
			privateKey, _ = x509.ParseECPrivateKey(keyBytes)
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

func GetKey() *ecdsa.PrivateKey {
	return privateKey
}

func GetCoseSigner() (cose.Signer, error) {
	return cose.NewSigner(cose.AlgorithmES256, GetKey())
}

func GetCoseVerifier() (cose.Verifier, error) {
	return cose.NewVerifier(cose.AlgorithmES256, GetKey().Public())
}
