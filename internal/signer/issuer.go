package signer

import (
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"strings"
)

const EKU_OID = "2.5.29.37"
const EKU_ANY_OID = "2.5.29.37.0"

type IssuerProfile int

const (
	Unknown IssuerProfile = iota
	DidWeb
	DidX509
)

func (ip IssuerProfile) String() string {
	if ip == DidWeb {
		return "did:web"
	}
	if ip == DidX509 {
		return "did:x509"
	}
	return "unknown"
}

type Issuer struct {
	profile  IssuerProfile
	hostPort string
	pubKeyId string
	x5chain  [][]byte
}

func NewIssuer(profile IssuerProfile, hostPort string, pubKeyId string, x5chain [][]byte) *Issuer {
	return &Issuer{profile: profile, hostPort: hostPort, pubKeyId: pubKeyId, x5chain: x5chain}
}

func (i *Issuer) GetIss() string {
	if i.profile == DidWeb {
		hostport := strings.ReplaceAll(i.hostPort, ":", "%3A")
		return DidWeb.String() + ":" + hostport
	} else if i.profile == DidX509 {
		// https://github.com/microsoft/did-x509
		caCertDer := i.x5chain[len(i.x5chain)-1]
		thumb := sha256.Sum256(caCertDer)
		thumbBase64Url := base64.RawURLEncoding.EncodeToString(thumb[:])
		return DidX509.String() + ":0:sha256:" + thumbBase64Url + "::subject:CN:CosePlayground"
	} else {
		return "unknown_issuer"
	}
}

func (i *Issuer) GetKid() []byte {
	return []byte("#" + i.pubKeyId)
}

func (i *Issuer) GetX5c() [][]byte {
	return i.x5chain
}

func ResolveDidX509(did string, x5c [][]byte) (crypto.PublicKey, error) {

	prefix := "did:x509:0:"
	if !strings.HasPrefix(did, prefix) {
		return nil, errors.New("invalid did prefix")
	}
	policies := strings.Split(did[len(prefix):], "::")
	if len(policies) == 0 {
		return nil, errors.New("no policies specified")
	}

	certDigest := strings.Split(policies[0], ":")
	if len(certDigest) != 2 {
		return nil, errors.New("invalid CA fingerprint format")
	}
	certHashAlg := certDigest[0]
	certHash := certDigest[1]
	var hashFunc hash.Hash
	switch certHashAlg {
	case "sha256":
		hashFunc = sha256.New()
	case "sha384":
		hashFunc = sha512.New384()
	case "sha512":
		hashFunc = sha512.New()
	default:
		return nil, fmt.Errorf("unsupported fingerprint algorithm: %s", certHashAlg)
	}

	if len(x5c) < 2 {
		return nil, errors.New("must be more than one certificate in the chain")
	}

	var expectedHashes []string
	for _, certDer := range x5c[1:] {
		expectedHashes = append(expectedHashes, hex.EncodeToString(hashFunc.Sum(certDer)))
	}

	matchingCertIdx := -1
	for idx, expected := range expectedHashes {
		if certHash == expected {
			matchingCertIdx = idx + 1
			break
		}
	}
	if matchingCertIdx < 0 {
		return nil, fmt.Errorf("invalid CA fingerprint, expected one of: %v", expectedHashes)
	}

	// TODO parse the CA cert and validate the policies
	_, err := x509.ParseCertificate(x5c[matchingCertIdx])
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	for _, policy := range policies[1:] {
		policyParts := strings.SplitN(policy, ":", 2)
		if len(policyParts) != 2 {
			return nil, fmt.Errorf("invalid cert policy: %v", policy)
		}
		name := policyParts[0]
		// value := policyParts[1]

		switch name {
		// case "subject":
		// 	subjectParts := strings.Split(value, ":")
		// 	if len(subjectParts) == 0 || len(subjectParts)%2 != 0 {
		// 		return nil, errors.New("key-value pairs required in subject")
		// 	}

		// 	fields := make(map[string]string)
		// 	for i := 0; i < len(subjectParts); i += 2 {
		// 		key := subjectParts[i]
		// 		val, err := pctdecode(subjectParts[i+1])
		// 		if err != nil {
		// 			return nil, err
		// 		}
		// 		if _, exists := fields[key]; exists {
		// 			return nil, errors.New("duplicate subject fields")
		// 		}
		// 		fields[key] = val
		// 	}

		// 	for key, val := range fields {
		// 		if expectedVal, ok := decoded[0].Subject[key]; !ok || val != expectedVal {
		// 			return nil, fmt.Errorf("invalid subject value: %s = %s, expected: %s", key, val, expectedVal)
		// 		}
		// 	}

		// case "san":
		// 	sanParts := strings.Split(value, ":")
		// 	if len(sanParts) != 2 {
		// 		return nil, errors.New("exactly one SAN type and value required")
		// 	}
		// 	sanType := sanParts[0]
		// 	sanValue, err := pctdecode(sanParts[1])
		// 	if err != nil {
		// 		return err
		// 	}

		// 	sans, ok := decoded[0].Extensions["san"].([][]string)
		// 	if !ok {
		// 		return errors.New("invalid SAN format in certificate extensions")
		// 	}
		// 	found := false
		// 	for _, san := range sans {
		// 		if san[0] == sanType && san[1] == sanValue {
		// 			found = true
		// 			break
		// 		}
		// 	}
		// 	if !found {
		// 		return fmt.Errorf("invalid SAN: [%s, %s], expected one of: %v", sanType, sanValue, sans)
		// 	}

		// case "eku":
		// 	// 2, 5, 29, 37
		// 	// 2, 5, 29, 37, 0
		// 	hasEKU := false
		// 	for _, ext := range caCert.Extensions {
		// 		if ext.Id.String() == EKU_OID {
		// 			ext.Value
		// 			hasEKU = true
		// 			break
		// 		}
		// 	}

		// 	caCertEku := caCert.ExtKeyUsage
		// 	ekuValues, ok := caCert.Extensions["eku"].([]string)
		// 	if !ok {
		// 		return errors.New("no EKU extension in certificate")
		// 	}
		// 	found := false
		// 	for _, eku := range ekuValues {
		// 		if eku == value {
		// 			found = true
		// 			break
		// 		}
		// 	}
		// 	if !found {
		// 		return fmt.Errorf("invalid EKU: %s, expected one of: %v", value, ekuValues)
		// 	}

		// case "fulcio-issuer":
		// 	fulcioIssuer := "https://" + pctdecode(value)
		// 	expectedFulcioIssuer, ok := decoded[0].Extensions["fulcio_issuer"].(string)
		// 	if !ok || fulcioIssuer != expectedFulcioIssuer {
		// 		return fmt.Errorf("invalid Fulcio issuer: %s, expected: %s", pctencode(fulcioIssuer), pctencode(expectedFulcioIssuer))
		// 	}

		default:
			return nil, fmt.Errorf("unknown did:x509 policy: %s", name)
		}
	}
	leafCert, err := x509.ParseCertificate(x5c[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse leaf certificate: %w", err)
	}
	return leafCert.PublicKey, nil
}
