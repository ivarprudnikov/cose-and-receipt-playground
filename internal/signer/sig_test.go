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

func Test_AddHeaders_Grouped(t *testing.T) {
	initial := cose.ProtectedHeader{}
	signer.AddHeaders(initial, map[string]string{
		"3":     "content/type",
		"33[0]": "first",
		"33[1]": "second",
		"33[5]": "last",
		"15.1":  "issuer",
		"15.2":  "subject",
		"15.3":  "audience",
	})
	require.NotNil(t, initial)
	require.Equal(t, interface{}("content/type"), initial[cose.HeaderLabelContentType])
	require.Equal(t, interface{}(map[interface{}]interface{}{int64(1): "issuer", int64(2): "subject", int64(3): "audience"}), initial[int64(15)])
	require.Equal(t, interface{}(&[]interface{}{"first", "second", nil, nil, nil, "last"}), initial[cose.HeaderLabelX5Chain])
}

func Test_AddHeaders(t *testing.T) {
	type test struct {
		initial     cose.ProtectedHeader
		kIn         string
		vIn         string
		kOut        any
		vOut        any
		errContains string
	}

	tests := []test{
		{
			initial:     cose.ProtectedHeader{},
			kIn:         "[1]",
			vIn:         "foo",
			errContains: "header key cannot start with a square bracket",
		},
		{
			initial: cose.ProtectedHeader{},
			kIn:     "3",
			vIn:     "content/type",
			kOut:    cose.HeaderLabelContentType,
			vOut:    "content/type",
		},
		{
			initial: cose.ProtectedHeader{},
			kIn:     "foo",
			vIn:     "bar",
			kOut:    "foo",
			vOut:    "bar",
		},
		{
			initial:     cose.ProtectedHeader{},
			kIn:         "foo[bar]",
			vIn:         "baz",
			errContains: "conflict: bar is not a valid index",
		},
		{
			initial: cose.ProtectedHeader{},
			kIn:     "33[0]",
			vIn:     "first",
			kOut:    cose.HeaderLabelX5Chain,
			vOut:    &[]any{"first"},
		},
		{
			initial: cose.ProtectedHeader{},
			kIn:     "33[2]",
			vIn:     "last",
			kOut:    cose.HeaderLabelX5Chain,
			vOut:    &[]any{nil, nil, "last"},
		},
		{
			initial: cose.ProtectedHeader{cose.HeaderLabelX5Chain: &[]any{"first"}},
			kIn:     "33[0]",
			vIn:     "overwrite",
			kOut:    cose.HeaderLabelX5Chain,
			vOut:    &[]any{"overwrite"},
		},
		{
			initial: cose.ProtectedHeader{cose.HeaderLabelX5Chain: &[]any{"first"}},
			kIn:     "33[2]",
			vIn:     "third",
			kOut:    cose.HeaderLabelX5Chain,
			vOut:    &[]any{"first", nil, "third"},
		},
		{
			initial: cose.ProtectedHeader{},
			kIn:     "15.1",
			vIn:     "issuer",
			kOut:    int64(15),
			vOut:    map[any]any{int64(1): "issuer"},
		},
		{
			initial: cose.ProtectedHeader{int64(15): map[any]any{int64(1): "issuer"}},
			kIn:     "15.1",
			vIn:     "overwrite",
			kOut:    int64(15),
			vOut:    map[any]any{int64(1): "overwrite"},
		},
		{
			initial: cose.ProtectedHeader{int64(15): map[any]any{int64(1): "issuer"}},
			kIn:     "15.2",
			vIn:     "addition",
			kOut:    int64(15),
			vOut:    map[any]any{int64(1): "issuer", int64(2): "addition"},
		},
		{
			initial: cose.ProtectedHeader{},
			kIn:     "a.b.c.d",
			vIn:     "nested",
			kOut:    "a",
			vOut:    map[any]any{"b": map[any]any{"c": map[any]any{"d": "nested"}}},
		},
		// {
		// 	initial: cose.ProtectedHeader{},
		// 	kIn:     "a[0]b",
		// 	vIn:     "nestedmixed",
		// 	kOut:    "a",
		// 	vOut:    &[]any{map[any]any{"b": "nestedmixed"}},
		// },
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.kIn, func(t *testing.T) {
			err := signer.AddHeaders(tt.initial, map[string]string{tt.kIn: tt.vIn})
			if tt.errContains != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errContains)
				return
			}
			require.Equal(t, tt.vOut, tt.initial[tt.kOut])
		})
	}
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
