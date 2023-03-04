package signer

import (
	"crypto/rand"
	"strings"

	"github.com/ivarprudnikov/cose-and-receipt-playground/keys"
	"github.com/veraison/go-cose"
)

// https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/
const ISSUER_HEADER_KEY = 391

func CreateSignature(payload []byte, hostport string) ([]byte, error) {
	hostport = strings.ReplaceAll(hostport, ":", "%3A")
	signer, err := cose.NewSigner(cose.AlgorithmES256, keys.GetKey())
	if err != nil {
		return nil, err
	}
	// create message header
	headers := cose.Headers{
		Protected: cose.ProtectedHeader{
			cose.HeaderLabelAlgorithm: cose.AlgorithmES256,
			cose.HeaderLabelKeyID:     []byte(keys.KEY_ID),
			ISSUER_HEADER_KEY:         []byte("did:web:" + hostport),
		},
	}
	// sign and marshal message
	return cose.Sign1(rand.Reader, signer, headers, payload, nil)
}
