package signer_test

import (
	"crypto/x509"
	"encoding/pem"
	"testing"

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
		{
			initial:     cose.ProtectedHeader{},
			kIn:         "a[0]b",
			vIn:         "nestedmixed",
			errContains: "failed to set object value nestedmixed under key 0]b",
		},
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
			require.NoError(t, err)
			require.Equal(t, tt.vOut, tt.initial[tt.kOut])
		})
	}
}

func Test_DefaultHeaders_DidWeb(t *testing.T) {
	issuer := signer.NewIssuer(signer.DidWeb, "foo.bar.com:8080", "foobar", [][]byte{[]byte("chain")})
	headers := signer.DefaultHeaders(*issuer)
	require.NotNil(t, headers)
	require.Equal(t, headers[cose.HeaderLabelAlgorithm], interface{}(cose.AlgorithmES256))
	require.Equal(t, headers[cose.HeaderLabelContentType], interface{}("text/plain"))
	kid, ok := headers[cose.HeaderLabelKeyID].([]byte)
	require.True(t, ok)
	require.Equal(t, kid, []byte("#foobar"))

	cwt, ok := headers[signer.CWT_CLAIMS_HEADER].(map[interface{}]interface{})
	require.True(t, ok)
	require.Equal(t, cwt[signer.CWT_CLAIMS_ISSUER_KEY], interface{}("did:web:foo.bar.com%3A8080"))
	require.Equal(t, cwt[signer.CWT_CLAIMS_SUBJECT_KEY], interface{}("demo"))
}

func Test_DefaultHeaders_DidX509(t *testing.T) { // test x509 certificate
	certPem := `-----BEGIN CERTIFICATE-----
MIIDLzCCAhegAwIBAgIUT0RL5CuegXHg+ZAmIryZtxYcXjEwDQYJKoZIhvcNAQEL
BQAwJzEMMAoGA1UECwwDd2ViMRcwFQYDVQQDDA53d3cuc2VydmVyLmNvbTAeFw0y
NTAzMDgwMDE5NTZaFw0zNTAzMDYwMDE5NTZaMCcxDDAKBgNVBAsMA3dlYjEXMBUG
A1UEAwwOd3d3LnNlcnZlci5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQDckpYwwJR9NyKmViAqbeuRHATyW6+h/rl3sUVGe08Y0vo4Q1DcWjCNXt/q
Jc03jgvMFeuowpjqyOp6TUh7pKidh3Wx6AlmWepnzXedJ73Nvd37Klae8YbRy81j
KPvXKigKn83uJghWc3C4ho8O+jHLqo58tPYa5ciS9Esg9F5infiUCMKKLngs8Ukr
AhY45zk3GM2p4hA48+18FwT9WNyp5lpvfmwokrwDUByH2VO1WA3Hs3l9/s9vjCYX
okDVBSIFz0LVnSylMNipfWFsFiCe1Qn7BkGmsKUxI1ngsVbrS3WMnq7IQH02q6iH
vCTaSz06euPBL0qeEGYBsn48F1QDAgMBAAGjUzBRMB0GA1UdDgQWBBRw2P/JCMNZ
uLI42UNAx+QYwBqvlTAfBgNVHSMEGDAWgBRw2P/JCMNZuLI42UNAx+QYwBqvlTAP
BgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCZZoEMy+6Dj/VdMhkN
Qr8B+Tw632T42SjgZye7kcw2dEZIieCgfKXyjqTxXru0IBSJLgPDRl8s4tHodghM
vl1baDJtMcpB6S3OAD7d+42ykNfBHK/vfc3qXbe67wKYxz+LHpiQrfJxUBf1zVk2
tHSbc2AH7XdEYbMHF1rpP/JuV4cU98Ubtt9UluyPiKiMOAavu3Wh5988c5Tj75xh
e61MIvwfVwEwglqJU9E9XgVBmYxyzZxW5KRql/VNLde8LSVNz2oI0pSIKKobfwU4
L3GUAplB3usAtxTExavEkNXQhMiOAMUCzkfRWXHEz6W1a0NnkDCxF9JArTUlVeyY
BpNe
-----END CERTIFICATE-----
`
	block, _ := pem.Decode([]byte(certPem))
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	require.NotNil(t, cert)

	certChain := [][]byte{cert.Raw, cert.Raw}

	issuer := signer.NewIssuer(signer.DidX509, "foo.bar.com:8080", "foobar", certChain)
	headers := signer.DefaultHeaders(*issuer)
	require.NotNil(t, headers)
	require.Equal(t, headers[cose.HeaderLabelAlgorithm], interface{}(cose.AlgorithmES256))
	require.Equal(t, headers[cose.HeaderLabelContentType], interface{}("text/plain"))
	require.Equal(t, headers[cose.HeaderLabelX5Chain], interface{}([][]byte{cert.Raw, cert.Raw}))

	cwt, ok := headers[signer.CWT_CLAIMS_HEADER].(map[interface{}]interface{})
	require.True(t, ok)
	require.Equal(t, cwt[signer.CWT_CLAIMS_ISSUER_KEY], interface{}("did:x509:0:sha256:-PzQNPfBWEBI2kbwlzfpeOssuKzedW1eR-y1a_Q-cv4::subject:CN:www.server.com"))
	require.Equal(t, cwt[signer.CWT_CLAIMS_SUBJECT_KEY], interface{}("demo"))
}

func Test_PrintHeaders(t *testing.T) {
	issuer := signer.NewIssuer(signer.DidWeb, "foo.bar.com:8080", "foobar", [][]byte{[]byte("chain")})
	headers := signer.DefaultHeaders(*issuer)
	printed := signer.PrintHeaders(headers)
	require.Contains(t, printed, "1: ES256,")
	require.Contains(t, printed, "3: text/plain,")
	require.Contains(t, printed, "4: #foobar")
	require.Contains(t, printed, "15: [ 1: did:web:foo.bar.com%3A8080, 2: demo ]")
}
