package countersigner

import (
	"crypto/rand"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/ivarprudnikov/cose-and-receipt-playground/internal/keys"
	"github.com/ivarprudnikov/cose-and-receipt-playground/internal/signer"
	"github.com/veraison/go-cose"
)

const COSE_Countersignature_header = int64(11)
const COSE_Countersignature0_header = int64(12)

var (
	encMode cbor.EncMode
)

func init() {
	var err error

	// init encode mode
	encOpts := cbor.EncOptions{
		Sort:        cbor.SortCoreDeterministic, // sort map keys
		IndefLength: cbor.IndefLengthForbidden,  // no streaming
	}
	encMode, err = encOpts.EncMode()
	if err != nil {
		panic(err)
	}
}

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
	cs := cose.Sign1Message{
		Headers: GetCountersignHeaders(hostport, keystore.GetPublicKeyId(), keystore.GetCertChain()),
		Payload: []byte{},
	}
	tbsCbor, err := ToBeSigned(target, cs.Headers)
	if err != nil {
		return nil, err
	}
	tbsSig, err := signer.Sign(rand.Reader, tbsCbor)
	if err != nil {
		return nil, err
	}
	cs.Signature = tbsSig

	cs_b, err := cs.MarshalCBOR()
	if err != nil {
		return nil, err
	}

	if !embedInSignature {
		return cs_b, nil
	}

	// get rid of raw headers
	clone := &cose.Sign1Message{
		Headers: cose.Headers{
			Protected:   target.Headers.Protected,
			Unprotected: target.Headers.Unprotected,
		},
		Payload:   target.Payload,
		Signature: target.Signature,
	}
	clone.Headers.Unprotected[COSE_Countersignature_header] = cs_b
	return clone.MarshalCBOR()
}

func Verify(countersignature cose.Sign1Message, target cose.Sign1Message, keystore *keys.KeyStore) error {
	verifier, err := keystore.GetCoseVerifier()
	if err != nil {
		return err
	}
	tbsCbor, err := ToBeSigned(target, countersignature.Headers)
	if err != nil {
		return err
	}
	return verifier.Verify(tbsCbor, countersignature.Signature)
}

// ToBeSigned constructs Countersign_structure, computes and returns ToBeSigned.
//
// Reference: https://datatracker.ietf.org/doc/html/rfc9338#section-3.3
func ToBeSigned(target cose.Sign1Message, csHeaders cose.Headers) ([]byte, error) {
	// Countersign_structure = [
	//    context : "CounterSignature" / "CounterSignature0" /
	//              "CounterSignatureV2" / "CounterSignature0V2" /,
	//    body_protected : empty_or_serialized_map,
	//    ? sign_protected : empty_or_serialized_map,
	//    external_aad : bstr,
	//    payload : bstr,
	//    ? other_fields : [+ bstr ]
	//  ]

	var (
		csProtected, sigProtected cbor.RawMessage
		err                       error
	)
	csProtected, err = csHeaders.MarshalProtected()
	if err != nil {
		return nil, err
	}
	sigProtected, err = target.Headers.MarshalProtected()
	if err != nil {
		return nil, err
	}

	countersignStructure := []interface{}{
		"CounterSignatureV2",            // context
		csProtected,                     // body_protected
		sigProtected,                    // sign_protected
		[]byte{},                        // external_aad
		target.Payload,                  // payload
		[]interface{}{target.Signature}, // other_fields - This field is an array of all bstr fields after the second
	}

	// create the value ToBeSigned by encoding the Sig_structure to a byte
	// string.
	return encMode.Marshal(countersignStructure)
}
