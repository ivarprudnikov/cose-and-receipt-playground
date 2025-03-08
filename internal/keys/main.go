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
	"errors"
	"log"
	"math/big"
	"os"
	"path"
	"time"

	"github.com/veraison/go-cose"
)

const SHARED_DIR = "/var/tmp/fn/playground-cose-eastus-dir"
const ROOT_KEY_FILE = "generated.ecdsa.key"
const ROOT_CERT_FILE = "generated.ca.der"
const SIGNING_KEY_FILE = "generated.signing.ecdsa.key"
const SIGNING_CERT_FILE = "generated.signing.der"

var caTemplate x509.Certificate = x509.Certificate{
	SerialNumber:          big.NewInt(1),
	Subject:               pkix.Name{CommonName: "CosePlayground", Country: []string{"IE"}, Organization: []string{"DoNotTrustMe"}},
	NotBefore:             time.Now(),
	NotAfter:              time.Now().AddDate(10, 0, 0),
	IsCA:                  true,
	KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	BasicConstraintsValid: true,
}

var certTemplate x509.Certificate = x509.Certificate{
	Subject:     pkix.Name{CommonName: "CosePlayground Signer", Country: []string{"IE"}, Organization: []string{"DoNotTrustMe"}},
	NotBefore:   time.Now(),
	NotAfter:    time.Now().AddDate(0, 0, 5),
	KeyUsage:    x509.KeyUsageDigitalSignature,
	ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageMicrosoftCommercialCodeSigning, x509.ExtKeyUsageMicrosoftKernelCodeSigning},
}

var serialNumberLimit *big.Int = new(big.Int).Lsh(big.NewInt(1), 128)

func NewKeyStore() (*KeyStore, error) {
	return NewKeyStoreIn(SHARED_DIR)
}

func NewKeyStoreIn(dir string) (*KeyStore, error) {
	var err error
	var rootKey *ecdsa.PrivateKey
	var rootCert *x509.Certificate
	var signingKey *ecdsa.PrivateKey
	var signingCert *x509.Certificate
	var recreateCert bool = true
	var keyFile string = path.Join(dir, ROOT_KEY_FILE)
	var caFile string = path.Join(dir, ROOT_CERT_FILE)
	var signingKeyFile string = path.Join(dir, SIGNING_KEY_FILE)
	var signingCertFile string = path.Join(dir, SIGNING_CERT_FILE)

	err = createDirIfNotExists(dir)
	if err != nil {
		log.Printf("Failed to create dir: %s", err.Error())
		return nil, err
	}

	rootKey, recreateCert, err = findOrCreateKey(keyFile)
	if err != nil {
		log.Printf("Failed to get root key: %s", err.Error())
		return nil, err
	}

	rootCert, err = findOrCreateCert(caFile, rootKey, recreateCert, nil, nil)
	if err != nil {
		log.Printf("Failed to get CA cert %s", err.Error())
		return nil, err
	}

	recreateCert = false
	signingKey, recreateCert, err = findOrCreateKey(signingKeyFile)
	if err != nil {
		log.Printf("Failed to get signing key: %s", err.Error())
		return nil, err
	}

	signingCert, err = findOrCreateCert(signingCertFile, signingKey, recreateCert, rootCert, rootKey)
	if err != nil {
		log.Printf("Failed to get signing cert %s", err.Error())
		return nil, err
	}

	return &KeyStore{
		rootKey:     rootKey,
		rootCert:    rootCert,
		signingKey:  signingKey,
		signingCert: signingCert,
	}, nil
}

type KeyStore struct {
	rootKey     *ecdsa.PrivateKey
	rootCert    *x509.Certificate
	signingKey  *ecdsa.PrivateKey
	signingCert *x509.Certificate
}

// GetB64CertChain returns the cert chain as to be used in a JWK
// The chain is from left to right, with the root cert last
func (s *KeyStore) GetB64CertChain() []string {
	return []string{base64.StdEncoding.EncodeToString(s.signingCert.Raw), base64.StdEncoding.EncodeToString(s.rootCert.Raw)}
}

func (s *KeyStore) GetCertChain() [][]byte {
	return [][]byte{s.signingCert.Raw, s.rootCert.Raw}
}

// used to get public key
func (s *KeyStore) GetPubKey() crypto.PublicKey {
	return s.signingKey.Public()
}

func (s *KeyStore) GetPublicKeyId() string {
	return PubKeyDerHash(s.GetPubKey())
}

func (s *KeyStore) GetCoseSigner() (cose.Signer, error) {
	return cose.NewSigner(cose.AlgorithmES256, s.signingKey)
}

func (s *KeyStore) GetCoseVerifier() (cose.Verifier, error) {
	return cose.NewVerifier(cose.AlgorithmES256, s.GetPubKey())
}

func PubKeyDerHash(k crypto.PublicKey) string {
	subjectPublicKeyInfoDer, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		panic(err)
	}
	certHash := sha256.Sum256(subjectPublicKeyInfoDer)
	return hex.EncodeToString(certHash[:])
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

func findOrCreateKey(keyFile string) (*ecdsa.PrivateKey, bool, error) {
	key, err := readECKey(keyFile)
	if err == nil {
		return key, false, nil
	}
	key, err = newECKey(keyFile)
	return key, true, err
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

func findOrCreateCert(certFilePath string, key *ecdsa.PrivateKey, recreate bool, parentCert *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, error) {
	sixHoursAhead := time.Now().Add(6 * time.Hour)
	if !recreate {
		cert, err := readCert(certFilePath)
		if err == nil && !sixHoursAhead.After(cert.NotAfter) {
			return cert, nil
		}
	}
	return newCert(certFilePath, key, parentCert, parentKey)
}

func readCert(certFilePath string) (*x509.Certificate, error) {
	_, err := os.Stat(certFilePath)
	if err != nil {
		return nil, err
	}
	certDer, err := os.ReadFile(certFilePath)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certDer)
}

func newCert(certFilePath string, key *ecdsa.PrivateKey, parentCert *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, error) {
	var template *x509.Certificate
	if parentCert == nil {
		template = &caTemplate
		parentCert = &caTemplate
		parentKey = key
	} else {
		template = &certTemplate
		serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
		if err != nil {
			log.Fatalf("Failed to generate serial number: %v", err)
		}
		template.SerialNumber = serialNumber
		if parentKey == nil {
			return nil, errors.New("parent key is required when creating signing certs")
		}
	}
	certDer, err := x509.CreateCertificate(rand.Reader, template, parentCert, &key.PublicKey, parentKey)
	if err != nil {
		return nil, err
	}
	err = os.WriteFile(certFilePath, certDer, 0600)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certDer)
}
