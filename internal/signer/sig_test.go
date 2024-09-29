package signer_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ivarprudnikov/cose-and-receipt-playground/internal/keys"
	"github.com/ivarprudnikov/cose-and-receipt-playground/internal/signer"
	"github.com/stretchr/testify/require"
	"github.com/veraison/go-cose"
)

func Test_AddHeaders(t *testing.T) {
	initial := cose.ProtectedHeader{}
	signer.AddHeaders(initial, map[string]string{
		// "3":     "content/type",
		"33[0]": "first",
		// "15.1":  "issuer",
		// "15.2":  "subject",
		// "15.3":  "audience",
	})
	// require.Nil(t, initial)
	// require.Equal(t, interface{}("content/type"), initial[cose.HeaderLabelContentType])
	// require.Equal(t, initial[int64(15)], interface{}(map[interface{}]interface{}{int64(1): "issuer", int64(2): "subject", int64(3): "audience"}))
	require.Equal(t, interface{}([]interface{}{"first"}), initial[cose.HeaderLabelX5Chain])
}

func Test_DefaultHeaders(t *testing.T) {
	headers := signer.DefaultHeaders("foo.bar.com:8080")
	require.NotNil(t, headers)
	require.Equal(t, headers[cose.HeaderLabelAlgorithm], interface{}(cose.AlgorithmES256))
	require.Equal(t, headers[cose.HeaderLabelContentType], interface{}("text/plain"))
	kid, ok := headers[cose.HeaderLabelKeyID].([]byte)
	require.True(t, ok)
	require.Equal(t, kid[0], byte('#'))
	require.Equal(t, headers[signer.ISSUER_HEADER_KEY], interface{}("did:web:foo.bar.com%3A8080"))
	require.Equal(t, headers[signer.ISSUER_HEADER_FEED], interface{}("demo"))

	regInfo, ok := headers[signer.ISSUER_HEADER_REG_INFO].(map[interface{}]interface{})
	require.True(t, ok)
	require.Greater(t, regInfo["register_by"].(uint64), uint64(time.Now().Unix()+3600))
	require.Equal(t, regInfo["sequence_no"], uint64(1))
	require.LessOrEqual(t, regInfo["issuance_ts"].(uint64), uint64(time.Now().Unix()))
}

func Test_PrintHeaders(t *testing.T) {
	headers := signer.DefaultHeaders("foo.bar.com:8080")
	printed := signer.PrintHeaders(headers)
	require.Contains(t, printed, "1: ES256,")
	require.Contains(t, printed, "3: text/plain,")
	require.Contains(t, printed, "4: #")
	require.Contains(t, printed, "391: did:web:foo.bar.com%3A8080,")
	require.Contains(t, printed, "392: demo,")
	require.Contains(t, printed, "issuance_ts: ")
	require.Contains(t, printed, "register_by: ")
	require.Contains(t, printed, "sequence_no: 1")
}

func Test_Create_Sig(t *testing.T) {
	sig, err := signer.CreateSignature([]byte("hello world"), map[string]string{"3": "foo/bar"}, "foo.bar.com")
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
	require.Equal(t, msg.Headers.Protected[signer.ISSUER_HEADER_KEY], interface{}("did:web:foo.bar.com"))
	require.Equal(t, msg.Headers.Protected[signer.ISSUER_HEADER_FEED], interface{}("demo"))
	regInfo, ok := msg.Headers.Protected[signer.ISSUER_HEADER_REG_INFO].(map[interface{}]interface{})
	require.True(t, ok)
	require.Greater(t, regInfo["register_by"].(int64), time.Now().Unix()+3600)
	require.Equal(t, regInfo["sequence_no"].(int64), int64(1))
	require.Less(t, regInfo["issuance_ts"].(int64), time.Now().Unix()+5)
}

func Test_Create_Verify_with_default_key(t *testing.T) {
	sig, err := signer.CreateSignature([]byte("hello world"), map[string]string{"3": "foo/bar"}, "foo.bar.com")
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

	sig, err := signer.CreateSignature([]byte("hello world"), map[string]string{"3": "foo/bar"}, serverUrl)
	require.NoError(t, err)

	err = signer.VerifySignature(sig, tlsServer.Client())
	require.NoError(t, err)
}
