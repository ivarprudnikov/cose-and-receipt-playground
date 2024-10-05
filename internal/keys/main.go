package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/veraison/go-cose"
)

const SHARED_DIR = "/var/tmp/fn/playground-cose-eastus-dir"

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

func NewKeyStore() (*KeyStore, error) {
	return NewKeyStoreIn(SHARED_DIR)
}

func NewKeyStoreIn(dir string) (*KeyStore, error) {
	var err error
	var keyBytes []byte
	var certDer []byte
	var rootKey *ecdsa.PrivateKey
	var rootCert *x509.Certificate
	var recreateCa bool = true
	var keyFile string = dir + "/generated.ecdsa.key"
	var caFile string = dir + "/ca.der"

	// create directory if it doesn't exist
	if _, err = os.Stat(dir); os.IsNotExist(err) {
		err = os.MkdirAll(dir, 0700)
		if err != nil {
			return nil, err
		}
	}

	// Load private key from file if it exists
	log.Printf("Reading key from file %s", keyFile)
	if _, err = os.Stat(keyFile); err == nil {
		keyBytes, err = os.ReadFile(keyFile)
		if err == nil {
			rootKey, err = x509.ParseECPrivateKey(keyBytes)
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
	if rootKey == nil {
		recreateCa = true
		rootKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		keyBytes, err = x509.MarshalECPrivateKey(rootKey)
		if err != nil {
			return nil, err
		}
		log.Printf("Writing key file to %s", keyFile)
		err = os.WriteFile(keyFile, keyBytes, 0600)
		if err != nil {
			return nil, err
		}
	}

	if recreateCa || len(certDer) == 0 {
		certDer, err = x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &rootKey.PublicKey, rootKey)
		if err != nil {
			return nil, err
		}
		log.Printf("Writing CA file to %s", caFile)
		err = os.WriteFile(caFile, certDer, 0600)
		if err != nil {
			return nil, err
		}
	}

	rootCert, err = x509.ParseCertificate(certDer)
	if err != nil {
		return nil, err
	}

	return &KeyStore{
		rootKey:  rootKey,
		rootCert: rootCert,
	}, nil
}

type KeyStore struct {
	rootKey  *ecdsa.PrivateKey
	rootCert *x509.Certificate
}

// GetB64CertChain returns the cert chain as to be used in a JWK
// The chain is from left to right, with the root cert last
func (s *KeyStore) GetB64CertChain() []string {
	return []string{base64.StdEncoding.EncodeToString(s.rootCert.Raw)}
}

func (s *KeyStore) GetCertChain() [][]byte {
	return [][]byte{s.rootCert.Raw}
}

// used to get public key
func (s *KeyStore) GetPubKey() crypto.PublicKey {
	return s.rootKey.Public()
}

func (s *KeyStore) GetPublicKeyId() string {
	return PubKeyCertHash(s.GetPubKey())
}

func (s *KeyStore) GetCoseSigner() (cose.Signer, error) {
	return cose.NewSigner(cose.AlgorithmES256, s.rootKey)
}

func (s *KeyStore) GetCoseVerifier() (cose.Verifier, error) {
	return cose.NewVerifier(cose.AlgorithmES256, s.GetPubKey())
}

func PubKeyCertHash(k crypto.PublicKey) string {
	derCert, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		panic(err)
	}
	certHash := sha256.Sum256(derCert)
	return hex.EncodeToString(certHash[:])
}
