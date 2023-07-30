package countersigner

import (
	"crypto/rand"
	"encoding/hex"
	"log"
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

func GetCountersignHeaders(hostport string) cose.Headers {
	return cose.Headers{
		Protected: cose.ProtectedHeader{
			cose.HeaderLabelAlgorithm: cose.AlgorithmES256,
			cose.HeaderLabelKeyID:     []byte("#" + keys.GetPublicKeyIdDefault()),
			signer.ISSUER_HEADER_KEY:  "did:web:" + strings.ReplaceAll(hostport, ":", "%3A"),
		},
	}
}

// Using full COSE_Countersignature aka cose.Sign1Message
func Countersign(target cose.Sign1Message, hostport string, embedInSignature bool) ([]byte, error) {
	signer, err := keys.GetCoseSignerDefault()
	if err != nil {
		return nil, err
	}
	cs := cose.Sign1Message{
		Headers: GetCountersignHeaders(hostport),
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

	log.Println(hex.EncodeToString(cs_b))

	var unprotected cose.UnprotectedHeader = target.Headers.Unprotected
	if unprotected == nil {
		unprotected = cose.UnprotectedHeader{}
	}

	unprotected[COSE_Countersignature_header] = cs_b
	target.Headers.Unprotected = unprotected
	return target.MarshalCBOR()
}

func Verify(countersignature cose.Sign1Message, target cose.Sign1Message) error {
	verifier, err := keys.GetCoseVerifierDefault()
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
