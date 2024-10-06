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
	"path"
	"time"

	"github.com/veraison/go-cose"
)

const SHARED_DIR = "/var/tmp/fn/playground-cose-eastus-dir"
const ROOT_KEY_FILE = "generated.ecdsa.key"
const ROOT_CERT_FILE = "ca.der"

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
	var certDer []byte
	var rootKey *ecdsa.PrivateKey
	var rootCert *x509.Certificate
	var recreateCa bool = true

	var keyFile string = path.Join(dir, ROOT_KEY_FILE)
	var caFile string = path.Join(dir, ROOT_CERT_FILE)

	err = createDirIfNotExists(dir)
	if err != nil {
		return nil, err
	}

	// Load private key from file if it exists
	log.Printf("Reading key from file %s", keyFile)
	rootKey, err = readECKey(keyFile)
	if err != nil {
		recreateCa = true
		log.Printf("Failed to read private key file: %s", err.Error())
		rootKey, err = newECKey(keyFile)
		if err != nil {
			log.Printf("Failed to create private key file: %s", err.Error())
			return nil, err
		}
	}

	if !recreateCa {
		log.Printf("Reading CA from file %s", caFile)
		rootCert, err = readCert(caFile)
		if err != nil {
			recreateCa = true
			log.Printf("Failed to read CA file: %s", err.Error())
		}
	}

	if recreateCa {
		certDer, err = x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &rootKey.PublicKey, rootKey)
		if err != nil {
			log.Printf("Failed to create CA cert %s", err.Error())
			return nil, err
		}
		log.Printf("Writing CA file to %s", caFile)
		err = os.WriteFile(caFile, certDer, 0600)
		if err != nil {
			log.Printf("Failed to write CA file %s", err.Error())
			return nil, err
		}
		rootCert, err = x509.ParseCertificate(certDer)
		if err != nil {
			log.Printf("Failed to parse CA cert file %s", err.Error())
			return nil, err
		}
	}

	return &KeyStore{
		rootKey:  rootKey,
		rootCert: rootCert,
	}, nil
}

func createDirIfNotExists(dir string) error {
	_, err := os.Stat(dir)
	if os.IsNotExist(err) {
		err = os.MkdirAll(dir, 0700)
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	return nil
}

func readECKey(keyFile string) (*ecdsa.PrivateKey, error) {
	_, err := os.Stat(keyFile)
	if err != nil {
		return nil, err
	}
	keyBytes, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	return x509.ParseECPrivateKey(keyBytes)
}

func newECKey(keyFile string) (*ecdsa.PrivateKey, error) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	keyBytes, err := x509.MarshalECPrivateKey(rootKey)
	if err != nil {
		return nil, err
	}
	err = os.WriteFile(keyFile, keyBytes, 0600)
	if err != nil {
		return nil, err
	}
	return rootKey, nil
}

func readCert(certFile string) (*x509.Certificate, error) {
	_, err := os.Stat(certFile)
	if err != nil {
		return nil, err
	}
	certDer, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certDer)
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
