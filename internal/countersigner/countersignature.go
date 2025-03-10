package countersigner

import (
	"crypto/rand"
	"strings"

	"github.com/ivarprudnikov/cose-and-receipt-playground/internal/keys"
	"github.com/ivarprudnikov/cose-and-receipt-playground/internal/signer"
	"github.com/veraison/go-cose"
)

func GetCountersignHeaders(hostport string, pubKeyId string, x5chain [][]byte) cose.Headers {
	return cose.Headers{
		Protected: cose.ProtectedHeader{
			cose.HeaderLabelAlgorithm: cose.AlgorithmES256,
			cose.HeaderLabelKeyID:     []byte("#" + pubKeyId),
			cose.HeaderLabelX5Chain:   x5chain,
			signer.CWT_CLAIMS_HEADER: map[any]any{
				signer.CWT_CLAIMS_ISSUER_KEY: "did:web:" + strings.ReplaceAll(hostport, ":", "%3A"),
			},
		},
	}
}

// Using full COSE_Countersignature aka cose.Sign1Message
func Countersign(target cose.Sign1Message, keystore *keys.KeyStore, hostport string, embedInSignature bool) ([]byte, error) {
	signer, err := keystore.GetCoseSigner()
	if err != nil {
		return nil, err
	}

	msgCountersig := cose.NewCountersignature()
	msgCountersig.Headers = GetCountersignHeaders(hostport, keystore.GetPublicKeyId(), keystore.GetCertChain())
	err = msgCountersig.Sign(rand.Reader, signer, target, nil)
	if err != nil {
		return nil, err
	}

	if !embedInSignature {
		cs_b, err := msgCountersig.MarshalCBOR()
		if err != nil {
			return nil, err
		}
		return cs_b, nil
	}

	// Reset the Raw value for the decoding to work
	target.Headers.RawUnprotected = nil
	target.Headers.Unprotected[cose.HeaderLabelCounterSignatureV2] = msgCountersig
	return target.MarshalCBOR()
}

func Verify(countersignature cose.Countersignature, target cose.Sign1Message, keystore *keys.KeyStore) error {
	verifier, err := keystore.GetCoseVerifier()
	if err != nil {
		return err
	}

	return countersignature.Verify(verifier, target, nil)
}
