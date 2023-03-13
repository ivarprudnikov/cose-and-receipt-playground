package signer

import (
	"crypto/rand"
	_ "crypto/sha256"
	"fmt"
	"strings"

	"github.com/ivarprudnikov/cose-and-receipt-playground/keys"
	"github.com/veraison/go-cose"
)

// https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/
const ISSUER_HEADER_KEY = int64(391)

func CreateSignature(payload []byte, hostport string) ([]byte, error) {
	hostport = strings.ReplaceAll(hostport, ":", "%3A")
	signer, err := cose.NewSigner(cose.AlgorithmES256, keys.GetKey())
	if err != nil {
		return nil, err
	}
	// create message header
	headers := cose.Headers{
		Protected: cose.ProtectedHeader{
			cose.HeaderLabelAlgorithm:   cose.AlgorithmES256,
			cose.HeaderLabelContentType: "text/plain",
			cose.HeaderLabelKeyID:       []byte("#" + keys.KEY_ID),
			ISSUER_HEADER_KEY:           "did:web:" + hostport,
		},
	}
	// sign and marshal message
	return cose.Sign1(rand.Reader, signer, headers, payload, nil)
}

func VerifySignature(signature []byte) error {
	verifier, err := cose.NewVerifier(cose.AlgorithmES256, keys.GetKey().Public())
	if err != nil {
		return fmt.Errorf("failed to create signature verifier: %w", err)
	}
	var msg cose.Sign1Message
	if err = msg.UnmarshalCBOR(signature); err != nil {
		return fmt.Errorf("failed to unmarshal signature bytes: %w", err)
	}
	return msg.Verify(nil, verifier)
}
