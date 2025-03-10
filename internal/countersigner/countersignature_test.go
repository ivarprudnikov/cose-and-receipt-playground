package countersigner_test

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/ivarprudnikov/cose-and-receipt-playground/internal/countersigner"
	"github.com/ivarprudnikov/cose-and-receipt-playground/internal/keys"
	"github.com/ivarprudnikov/cose-and-receipt-playground/internal/signer"
	"github.com/stretchr/testify/require"
	"github.com/veraison/go-cose"
)

func Test_GetCountersignHeaders(t *testing.T) {
	for _, tc := range []struct {
		name           string
		hostport       string
		expectedIssuer string
	}{
		{
			name:           "localhost",
			hostport:       "localhost",
			expectedIssuer: "did:web:localhost",
		},
		{
			name:           "localhost with port",
			hostport:       "localhost:8080",
			expectedIssuer: "did:web:localhost%3A8080",
		},
		{
			name:           "localhost with encoded port",
			hostport:       "localhost%3A8080",
			expectedIssuer: "did:web:localhost%3A8080",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hdr := countersigner.GetCountersignHeaders(tc.hostport, "foobar", [][]byte{[]byte("cert1"), []byte("cert2")})
			cwt, ok := hdr.Protected[signer.CWT_CLAIMS_HEADER].(map[interface{}]interface{})
			require.True(t, ok)
			require.Equal(t, tc.expectedIssuer, cwt[signer.CWT_CLAIMS_ISSUER_KEY])
		})
	}
}

func Test_Countersign(t *testing.T) {
	tmpDir := t.TempDir()
	tmpKeystore, err := keys.NewKeyStoreIn(tmpDir)
	require.NoError(t, err)

	msg1 := cose.NewSign1Message()
	msg1.Headers.Protected[cose.HeaderLabelAlgorithm] = cose.AlgorithmES256
	msg1.Payload = []byte("hello world")
	msg1.Signature = []byte("signature")

	receipt_b, err := countersigner.Countersign(*msg1, tmpKeystore, "localhost", false)
	require.NoError(t, err)
	require.NotEmpty(t, receipt_b)

	var receipt cose.Countersignature
	err = receipt.UnmarshalCBOR(receipt_b)
	require.NoError(t, err)
	require.NotNil(t, receipt)
	require.NotEmpty(t, receipt.Headers.Protected)
	require.Equal(t, cose.AlgorithmES256, receipt.Headers.Protected[cose.HeaderLabelAlgorithm])
	require.Equal(t, []byte("#"+tmpKeystore.GetPublicKeyId()), receipt.Headers.Protected[cose.HeaderLabelKeyID])

	cwt, ok := receipt.Headers.Protected[signer.CWT_CLAIMS_HEADER].(map[interface{}]interface{})
	require.True(t, ok)
	require.Equal(t, cwt[signer.CWT_CLAIMS_ISSUER_KEY], interface{}("did:web:localhost"))

	require.NotEmpty(t, receipt.Signature)
}

func Test_Countersign_embedded(t *testing.T) {

	tmpDir := t.TempDir()
	tmpKeystore, err := keys.NewKeyStoreIn(tmpDir)
	require.NoError(t, err)

	msg1 := cose.NewSign1Message()
	msg1.Headers.Protected[cose.HeaderLabelAlgorithm] = cose.AlgorithmES256
	msg1.Payload = []byte("hello world")
	msg1.Signature = []byte("signature")

	msg2_hex := "d28458c7a60126036a746578742f706c61696e045841233936396437353463363164626465323665356236353237663136383938663630646266636137613937303736356432343437336337323563613366343933643119018778346469643a7765623a706c617967726f756e642d636f73652d6561737475732d6170692e617a75726577656273697465732e6e65741901886464656d6f190189a36b69737375616e63655f74731a64c68f666b72656769737465725f62791a64c7e0e66b73657175656e63655f6e6f01a04566726f646f58402dc4667f6ab8fdc71835552ca7ae90ff8067f4f971516ecf81bf81afabea2d7844e2aab8eea7ea4776c5676830a157229e25b4370de6f9462705f8e67e6266cc"
	msg2_b, err := hex.DecodeString(msg2_hex)
	require.NoError(t, err)
	var msg2 cose.Sign1Message
	msg2.UnmarshalCBOR(msg2_b)

	for idx, original := range []cose.Sign1Message{*msg1, msg2} {
		t.Run(fmt.Sprintf("embedded message %d", idx), func(t *testing.T) {
			embedded_b, err := countersigner.Countersign(original, tmpKeystore, "localhost", true)
			require.NoError(t, err)
			require.NotEmpty(t, embedded_b)

			var embedded cose.Sign1Message
			err = embedded.UnmarshalCBOR(embedded_b)
			require.NoError(t, err)
			require.NotNil(t, embedded)
			require.NotEmpty(t, embedded.Headers.Unprotected)
			receipt_any := embedded.Headers.Unprotected[cose.HeaderLabelCounterSignatureV2]
			require.NotNil(t, receipt_any)
			receipt, ok := receipt_any.(*cose.Countersignature)
			require.True(t, ok, "receipt is Countersignature")
			require.NotNil(t, receipt)
			require.NotEmpty(t, receipt.Headers.Protected)
			require.Equal(t, cose.AlgorithmES256, receipt.Headers.Protected[cose.HeaderLabelAlgorithm])
			require.Equal(t, []byte("#"+tmpKeystore.GetPublicKeyId()), receipt.Headers.Protected[cose.HeaderLabelKeyID])

			cwt, ok := receipt.Headers.Protected[signer.CWT_CLAIMS_HEADER].(map[interface{}]interface{})
			require.True(t, ok)
			require.Equal(t, cwt[signer.CWT_CLAIMS_ISSUER_KEY], interface{}("did:web:localhost"))
			require.NotEmpty(t, receipt.Signature)
		})
	}

}

func Test_countersign_then_verify(t *testing.T) {
	tmpDir := t.TempDir()
	tmpKeystore, err := keys.NewKeyStoreIn(tmpDir)
	require.NoError(t, err)

	msg1 := cose.NewSign1Message()
	msg1.Headers.Protected[cose.HeaderLabelAlgorithm] = cose.AlgorithmES256
	msg1.Payload = []byte("hello world")
	msg1.Signature = []byte("signature")

	result, err := countersigner.Countersign(*msg1, tmpKeystore, "localhost", false)
	require.NoError(t, err)
	require.NotEmpty(t, result)

	var countersignature cose.Countersignature
	err = countersignature.UnmarshalCBOR(result)
	require.NoError(t, err)
	err = countersigner.Verify(countersignature, *msg1, tmpKeystore)
	require.NoError(t, err)
}
