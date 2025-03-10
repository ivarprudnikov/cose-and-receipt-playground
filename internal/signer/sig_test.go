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
	tmpDir := t.TempDir()
	tmpKeystore, err := keys.NewKeyStoreIn(tmpDir)
	require.NoError(t, err)

	issuer := signer.NewIssuer(signer.DidWeb, "foo.bar.com", tmpKeystore.GetPublicKeyId(), tmpKeystore.GetCertChain())
	sig, err := signer.CreateSignature(issuer, []byte("hello world"), map[string]string{"3": "foo/bar"}, tmpKeystore)
	require.NoError(t, err)
	require.NotNil(t, sig)

	var msg cose.Sign1Message
	err = msg.UnmarshalCBOR(sig)
	require.NoError(t, err)

	require.Equal(t, msg.Headers.Protected[cose.HeaderLabelAlgorithm], interface{}(cose.AlgorithmES256))
	require.Equal(t, msg.Headers.Protected[cose.HeaderLabelContentType], interface{}("foo/bar"))
	kid, ok := msg.Headers.Protected[cose.HeaderLabelKeyID].([]byte)
	require.True(t, ok)
	require.Equal(t, kid[0], byte('#'))

	cwt, ok := msg.Headers.Protected[signer.CWT_CLAIMS_HEADER].(map[interface{}]interface{})
	require.True(t, ok)
	require.Equal(t, cwt[signer.CWT_CLAIMS_ISSUER_KEY], interface{}("did:web:foo.bar.com"))
	require.Equal(t, cwt[signer.CWT_CLAIMS_SUBJECT_KEY], interface{}("demo"))
}

func Test_Create_Verify_with_default_key(t *testing.T) {
	tmpDir := t.TempDir()
	tmpKeystore, err := keys.NewKeyStoreIn(tmpDir)
	require.NoError(t, err)

	issuer := signer.NewIssuer(signer.DidWeb, "foo.bar.com", tmpKeystore.GetPublicKeyId(), tmpKeystore.GetCertChain())
	sig, err := signer.CreateSignature(issuer, []byte("hello world"), map[string]string{"3": "foo/bar"}, tmpKeystore)
	require.NoError(t, err)

	var msg cose.Sign1Message
	err = msg.UnmarshalCBOR(sig)
	require.NoError(t, err)

	verifier, err := tmpKeystore.GetCoseVerifier()
	require.NoError(t, err)

	err = msg.Verify(nil, verifier)
	require.NoError(t, err)
}

func Test_Create_Verify_with_didweb_server(t *testing.T) {
	tmpDir := t.TempDir()
	tmpKeystore, err := keys.NewKeyStoreIn(tmpDir)
	require.NoError(t, err)

	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		didDoc, err := keys.CreateDoc(strings.ReplaceAll(r.Host, ":", "%3A"), tmpKeystore.GetPubKey(), tmpKeystore.GetB64CertChain())
		require.NoError(t, err)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(didDoc))
	}))

	serverUrl := strings.TrimPrefix(tlsServer.URL, "https://")

	issuer := signer.NewIssuer(signer.DidWeb, serverUrl, tmpKeystore.GetPublicKeyId(), tmpKeystore.GetCertChain())
	sig, err := signer.CreateSignature(issuer, []byte("hello world"), map[string]string{"3": "foo/bar"}, tmpKeystore)
	require.NoError(t, err)

	err = signer.VerifySignature(sig, tlsServer.Client())
	require.NoError(t, err)
}

func Test_Create_Verify_with_didx509(t *testing.T) {
	tmpDir := t.TempDir()
	tmpKeystore, err := keys.NewKeyStoreIn(tmpDir)
	require.NoError(t, err)

	issuer := signer.NewIssuer(signer.DidX509, "foo.bar.com", tmpKeystore.GetPublicKeyId(), tmpKeystore.GetCertChain())
	sig, err := signer.CreateSignature(issuer, []byte("hello world"), map[string]string{"3": "foo/bar"}, tmpKeystore)
	require.NoError(t, err)

	err = signer.VerifySignature(sig, nil)
	require.NoError(t, err)
}
