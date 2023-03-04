package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
