package signer

import (
	"crypto/rand"
	_ "crypto/sha256"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/ivarprudnikov/cose-and-receipt-playground/internal/keys"
	"github.com/veraison/go-cose"
)

// https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/
const ISSUER_HEADER_KEY = int64(391)
const ISSUER_HEADER_FEED = int64(392)
const ISSUER_HEADER_REG_INFO = int64(393)

func CreateSignature(payload []byte, hostport string) ([]byte, error) {
	hostport = strings.ReplaceAll(hostport, ":", "%3A")
	signer, err := keys.GetCoseSignerDefault()
	if err != nil {
		return nil, err
	}
	// create message header
	headers := cose.Headers{
		Protected: cose.ProtectedHeader{
			cose.HeaderLabelAlgorithm:   cose.AlgorithmES256,
			cose.HeaderLabelContentType: "text/plain",
			cose.HeaderLabelKeyID:       []byte("#" + keys.GetPublicKeyIdDefault()),
			ISSUER_HEADER_KEY:           "did:web:" + hostport,
			ISSUER_HEADER_FEED:          "demo",
			ISSUER_HEADER_REG_INFO: map[interface{}]interface{}{
				"register_by": uint64(time.Now().Add(24 * time.Hour).Unix()),
				"sequence_no": uint64(1),
				"issuance_ts": uint64(time.Now().Unix()),
			},
		},
	}
	// sign and marshal message
	return cose.Sign1(rand.Reader, signer, headers, payload, nil)
}

func VerifySignature(signature []byte, didHttpClient *http.Client) error {
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(signature); err != nil {
		return fmt.Errorf("failed to unmarshal signature bytes: %w", err)
	}

	issuerRaw := msg.Headers.Protected[ISSUER_HEADER_KEY]
	issuer, ok := issuerRaw.(string)
	if !ok {
		return fmt.Errorf("issuer is not a string: %v", issuerRaw)
	}
	kidRaw := msg.Headers.Protected[cose.HeaderLabelKeyID]
	kid, ok := kidRaw.([]byte)
	if !ok {
		return fmt.Errorf("kid is not a byte array: %v", kidRaw)
	}
	algRaw := msg.Headers.Protected[cose.HeaderLabelAlgorithm]
	alg, ok := algRaw.(cose.Algorithm)
	if !ok {
		return fmt.Errorf("unexpected alg value: %v", algRaw)
	}

	log.Printf("resolving issuer did: %s, kid %s, alg %v \n", issuer, kid, alg)
	didResolver := keys.Did{Issuer: issuer, KeyId: string(kid), Client: didHttpClient}
	pubKey, err := didResolver.ResolvePublicKey()
	if err != nil {
		return fmt.Errorf("failed to resolve public key: %w", err)
	}

	verifier, err := keys.GetCoseVerifierFor(alg, pubKey)
	if err != nil {
		return fmt.Errorf("failed to create signature verifier: %w", err)
	}

	return msg.Verify(nil, verifier)
}
