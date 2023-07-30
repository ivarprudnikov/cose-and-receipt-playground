package countersigner_test

import (
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
			hdr := countersigner.GetCountersignHeaders(tc.hostport)
			require.Equal(t, tc.expectedIssuer, hdr.Protected[signer.ISSUER_HEADER_KEY])
		})
	}
}

func Test_Countersign(t *testing.T) {
	receipt_b, err := countersigner.Countersign(cose.Sign1Message{}, "localhost", false)
	require.NoError(t, err)
	require.NotEmpty(t, receipt_b)

	var receipt cose.Sign1Message
	err = receipt.UnmarshalCBOR(receipt_b)
	require.NoError(t, err)
	require.NotNil(t, receipt)
	require.NotEmpty(t, receipt.Headers.Protected)
	require.Equal(t, cose.AlgorithmES256, receipt.Headers.Protected[cose.HeaderLabelAlgorithm])
	require.Equal(t, []byte("#"+keys.GetPublicKeyIdDefault()), receipt.Headers.Protected[cose.HeaderLabelKeyID])
	require.Equal(t, "did:web:localhost", receipt.Headers.Protected[signer.ISSUER_HEADER_KEY])
	require.Empty(t, receipt.Payload)
	require.NotEmpty(t, receipt.Signature)
}

func Test_Countersign_embedded(t *testing.T) {
	original := cose.NewSign1Message()
	original.Headers.Protected[cose.HeaderLabelAlgorithm] = cose.AlgorithmES256
	original.Signature = []byte("signature")

	embedded_b, err := countersigner.Countersign(*original, "localhost", true)
	require.NoError(t, err)
	require.NotEmpty(t, embedded_b)

	var embedded cose.Sign1Message
	err = embedded.UnmarshalCBOR(embedded_b)
	require.NoError(t, err)
	require.NotNil(t, embedded)
	require.NotEmpty(t, embedded.Headers.Unprotected)
	receipt_raw := embedded.Headers.Unprotected[countersigner.COSE_Countersignature_header]
	require.NotNil(t, receipt_raw)
	receipt_b, ok := receipt_raw.([]byte)
	require.True(t, ok, "receipt bytes")

	var receipt cose.Sign1Message
	err = receipt.UnmarshalCBOR(receipt_b)
	require.NoError(t, err)
	require.NotNil(t, receipt)
	require.NotEmpty(t, receipt.Headers.Protected)
	require.Equal(t, cose.AlgorithmES256, receipt.Headers.Protected[cose.HeaderLabelAlgorithm])
	require.Equal(t, []byte("#"+keys.GetPublicKeyIdDefault()), receipt.Headers.Protected[cose.HeaderLabelKeyID])
	require.Equal(t, "did:web:localhost", receipt.Headers.Protected[signer.ISSUER_HEADER_KEY])
	require.Empty(t, receipt.Payload)
	require.NotEmpty(t, receipt.Signature)
}

func Test_countersign_then_verify(t *testing.T) {
	target := cose.NewSign1Message()
	result, err := countersigner.Countersign(*target, "localhost", false)
	require.NoError(t, err)
	require.NotEmpty(t, result)

	var countersignature cose.Sign1Message
	err = countersignature.UnmarshalCBOR(result)
	require.NoError(t, err)
	err = countersigner.Verify(countersignature, *target)
	require.NoError(t, err)
}
