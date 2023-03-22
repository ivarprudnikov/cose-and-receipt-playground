package countersigner_test

import (
	"testing"

	"github.com/ivarprudnikov/cose-and-receipt-playground/countersigner"
	"github.com/ivarprudnikov/cose-and-receipt-playground/keys"
	"github.com/ivarprudnikov/cose-and-receipt-playground/signer"
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
	data, err := countersigner.Countersign(cose.Sign1Message{}, "localhost")
	require.NoError(t, err)
	require.NotEmpty(t, data)

	msg := cose.NewSign1Message()
	err = msg.UnmarshalCBOR(data)
	require.NoError(t, err)
	require.NotNil(t, msg)
	require.NotEmpty(t, msg.Headers.Protected)
	require.Equal(t, cose.AlgorithmES256, msg.Headers.Protected[cose.HeaderLabelAlgorithm])
	require.Equal(t, []byte("#"+keys.KEY_ID), msg.Headers.Protected[cose.HeaderLabelKeyID])
	require.Equal(t, "did:web:localhost", msg.Headers.Protected[signer.ISSUER_HEADER_KEY])
	require.Empty(t, msg.Payload)
	require.NotEmpty(t, msg.Signature)
}

func Test_countersign_then_verify(t *testing.T) {
	target := cose.NewSign1Message()
	result, err := countersigner.Countersign(*target, "localhost")
	require.NoError(t, err)
	require.NotEmpty(t, result)

	countersignature := cose.NewSign1Message()
	err = countersignature.UnmarshalCBOR(result)
	require.NoError(t, err)
	err = countersigner.Verify(*countersignature, *target)
	require.NoError(t, err)
}
