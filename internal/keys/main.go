package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/veraison/go-cose"
)

const SHARED_DIR = "/var/tmp/fn/playground-cose-eastus-dir"

var keyFile string = SHARED_DIR + "/generated.ecdsa.key"
var caFile string = SHARED_DIR + "/ca.der"

var privateKey *ecdsa.PrivateKey
var rootCert *x509.Certificate

var caTemplate x509.Certificate = x509.Certificate{
	SerialNumber:          big.NewInt(1),
	Subject:               pkix.Name{CommonName: "CosePlayground"},
	NotBefore:             time.Now(),
	NotAfter:              time.Now().AddDate(10, 0, 0),
	IsCA:                  true,
	KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	BasicConstraintsValid: true,
}

// var leafTemplate x509.Certificate = x509.Certificate{
// 	SerialNumber: big.NewInt(2),
// 	Subject:      pkix.Name{CommonName: "CosePlayground Signer"},
// 	NotBefore:    time.Now(),
// 	NotAfter:     time.Now().AddDate(0, 0, 5),
// 	KeyUsage:     x509.KeyUsageDigitalSignature,
// 	ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageMicrosoftCommercialCodeSigning, x509.ExtKeyUsageMicrosoftKernelCodeSigning},
// }

func init() {
	var err error
	var keyBytes []byte
	var certDer []byte
	var recreateCa bool = true

	// create shared directory if it doesn't exist
	if _, err = os.Stat(SHARED_DIR); os.IsNotExist(err) {
		err = os.MkdirAll(SHARED_DIR, 0700)
		if err != nil {
			panic(err)
		}
	}

	// Load private key from file if it exists
	log.Printf("Reading key from file %s", keyFile)
	if _, err = os.Stat(keyFile); err == nil {
		keyBytes, err = os.ReadFile(keyFile)
		if err == nil {
			privateKey, err = x509.ParseECPrivateKey(keyBytes)
			if err != nil {
				log.Printf("Failed to parse private key: %s", err.Error())
			}
		} else {
			log.Printf("Failed to read private key file: %s", err.Error())
		}
	}

	log.Printf("Reading CA from file %s", caFile)
	if _, err = os.Stat(caFile); err == nil {
		certDer, err = os.ReadFile(caFile)
		if err == nil {
			recreateCa = false
		} else {
			log.Printf("Failed to read CA file: %s", err.Error())
		}
	}

	// create new private key if it doesn't exist
	if privateKey == nil {
		recreateCa = true
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		keyBytes, err = x509.MarshalECPrivateKey(privateKey)
		if err != nil {
			panic(err)
		}
		log.Printf("Writing key file to %s", keyFile)
		err = os.WriteFile(keyFile, keyBytes, 0600)
		if err != nil {
			panic(err)
		}
	}

	if recreateCa || len(certDer) == 0 {
		certDer, err = x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &privateKey.PublicKey, privateKey)
		if err != nil {
			panic(err)
		}
		log.Printf("Writing CA file to %s", caFile)
		err = os.WriteFile(caFile, certDer, 0600)
		if err != nil {
			panic(err)
		}
	}

	rootCert, err = x509.ParseCertificate(certDer)
	if err != nil {
		panic(err)
	}
}

func GetKeyDefault() *ecdsa.PrivateKey {
	return privateKey
}

func GetPublicKeyIdDefault() string {
	derCert, err := x509.MarshalPKIXPublicKey(GetKeyDefault().Public())
	if err != nil {
		panic(err)
	}
	certHash := sha256.Sum256(derCert)
	return hex.EncodeToString(certHash[:])
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
