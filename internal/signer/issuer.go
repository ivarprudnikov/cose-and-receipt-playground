package signer

import (
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"net/url"
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
		iss, err := DidX509FromChain(i.x5chain)
		if err != nil {
			return "unknown_issuer"
		}
		return iss
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

// https://github.com/microsoft/did-x509
func DidX509FromChain(x5c [][]byte) (string, error) {
	if len(x5c) < 2 {
		return "", errors.New("must be more than one certificate in the chain")
	}
	caCertDer := x5c[len(x5c)-1]
	thumb := sha256.Sum256(caCertDer)
	thumbBase64Url := base64.RawURLEncoding.EncodeToString(thumb[:])

	signingCertDer := x5c[0]
	signingCert, err := x509.ParseCertificate(signingCertDer)
	if err != nil {
		return "", fmt.Errorf("failed to parse signing certificate: %w", err)
	}
	commonName := signingCert.Subject.CommonName
	return DidX509.String() + ":0:sha256:" + thumbBase64Url + "::subject:CN:" + commonName, nil
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
	certHashB64Url := certDigest[1]
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

	var expectedThumbs []string
	for _, certDer := range x5c[1:] {
		hashFunc.Reset()
		hashFunc.Write(certDer)
		thumb := hashFunc.Sum(nil)
		thumbBase64Url := base64.RawURLEncoding.EncodeToString(thumb[:])
		expectedThumbs = append(expectedThumbs, thumbBase64Url)
	}

	matchingCertIdx := -1
	for idx, expected := range expectedThumbs {
		if certHashB64Url == expected {
			matchingCertIdx = idx + 1
			break
		}
	}
	if matchingCertIdx < 0 {
		return nil, fmt.Errorf("invalid CA fingerprint %s, expected one of: %v", certHashB64Url, expectedThumbs)
	}

	signingcert, err := x509.ParseCertificate(x5c[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse signing certificate: %w", err)
	}

	for _, policy := range policies[1:] {
		policyParts := strings.SplitN(policy, ":", 2)
		if len(policyParts) != 2 {
			return nil, fmt.Errorf("invalid cert policy: %v", policy)
		}
		name := policyParts[0]
		value := policyParts[1]

		switch name {
		case "subject":
			subjectParts := strings.Split(value, ":")
			if len(subjectParts) == 0 || len(subjectParts)%2 != 0 {
				return nil, errors.New("key-value pairs required in subject")
			}

			fields := make(map[string]string)
			for i := 0; i < len(subjectParts); i += 2 {
				key := subjectParts[i]
				val, err := url.QueryUnescape(subjectParts[i+1])
				if err != nil {
					return nil, err
				}
				if _, exists := fields[key]; exists {
					return nil, errors.New("duplicate subject fields")
				}
				fields[key] = val
			}

			for key, val := range fields {
				if key == "CN" && signingcert.Subject.CommonName != val {
					return nil, fmt.Errorf("invalid subject value: CN = %s, expected: %s", signingcert.Subject.CommonName, val)
				} else if key == "O" && signingcert.Subject.Organization[0] != val {
					return nil, fmt.Errorf("invalid subject value: O = %s, expected: %s", signingcert.Subject.Organization[0], val)
				} else if key == "OU" && signingcert.Subject.OrganizationalUnit[0] != val {
					return nil, fmt.Errorf("invalid subject value: OU = %s, expected: %s", signingcert.Subject.OrganizationalUnit[0], val)
				} else if key == "L" && signingcert.Subject.Locality[0] != val {
					return nil, fmt.Errorf("invalid subject value: L = %s, expected: %s", signingcert.Subject.Locality[0], val)
				} else if key == "ST" && signingcert.Subject.Province[0] != val {
					return nil, fmt.Errorf("invalid subject value: ST = %s, expected: %s", signingcert.Subject.Province[0], val)
				} else if key == "C" && signingcert.Subject.Country[0] != val {
					return nil, fmt.Errorf("invalid subject value: C = %s, expected: %s", signingcert.Subject.Country[0], val)
				} else if key == "SN" && signingcert.Subject.SerialNumber != val {
					return nil, fmt.Errorf("invalid subject value: SN = %s, expected: %s", signingcert.Subject.Country[0], val)
				}
			}

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
