package signer

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

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
