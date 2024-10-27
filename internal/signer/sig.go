package signer

import (
	"crypto/rand"
	_ "crypto/sha256"
	"fmt"
	"log"
	"net/http"

	"github.com/ivarprudnikov/cose-and-receipt-playground/internal/keys"
	"github.com/veraison/go-cose"
)

func CreateSignature(issuer *Issuer, payload []byte, customHeaders map[string]string, keystore *keys.KeyStore) ([]byte, error) {
	signer, err := keystore.GetCoseSigner()
	if err != nil {
		return nil, err
	}
	// create message header
	if issuer == nil {
		return nil, fmt.Errorf("issuer is required")
	}
	protected := DefaultHeaders(*issuer)
	AddHeaders(protected, customHeaders)
	headers := cose.Headers{
		Protected: protected,
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

	verifier, err := cose.NewVerifier(alg, pubKey)
	if err != nil {
		return fmt.Errorf("failed to create signature verifier: %w", err)
	}

	return msg.Verify(nil, verifier)
}
