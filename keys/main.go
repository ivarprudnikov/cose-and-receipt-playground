package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"github.com/veraison/go-cose"
)

var privateKey *ecdsa.PrivateKey

func init() {
	var err error
	privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
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
