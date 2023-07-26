package signer_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ivarprudnikov/cose-and-receipt-playground/internal/keys"
	"github.com/ivarprudnikov/cose-and-receipt-playground/internal/signer"
	"github.com/stretchr/testify/require"
	"github.com/veraison/go-cose"
)

func Test_Create_Sig(t *testing.T) {
	sig, err := signer.CreateSignature([]byte("hello world"), "foo.bar.com")
	require.NoError(t, err)
	require.NotNil(t, sig)
}

func Test_Create_Verify_with_default_key(t *testing.T) {
	sig, err := signer.CreateSignature([]byte("hello world"), "foo.bar.com")
	require.NoError(t, err)

	var msg cose.Sign1Message
	err = msg.UnmarshalCBOR(sig)
	require.NoError(t, err)

	verifier, err := keys.GetCoseVerifierDefault()
	require.NoError(t, err)

	err = msg.Verify(nil, verifier)
	require.NoError(t, err)
}

func Test_Create_Verify_with_did(t *testing.T) {
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		didDoc, err := keys.CreateDoc(strings.ReplaceAll(r.Host, ":", "%3A"), keys.GetKeyDefault().Public())
		require.NoError(t, err)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(didDoc))
	}))

	serverUrl := strings.TrimPrefix(tlsServer.URL, "https://")

	sig, err := signer.CreateSignature([]byte("hello world"), serverUrl)
	require.NoError(t, err)

	err = signer.VerifySignature(sig, tlsServer.Client())
	require.NoError(t, err)
}
