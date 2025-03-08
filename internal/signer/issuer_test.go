package signer_test

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"

	"github.com/ivarprudnikov/cose-and-receipt-playground/internal/signer"
	"github.com/stretchr/testify/require"
)

func Test_NewIssuer_DidWeb(t *testing.T) {
	issuer := signer.NewIssuer(signer.DidWeb, "foo.bar.com:8080", "foobar", [][]byte{[]byte("chain")})
	require.NotNil(t, issuer)
	require.Equal(t, "did:web:foo.bar.com%3A8080", issuer.GetIss())
	require.Equal(t, []byte("#foobar"), issuer.GetKid())
	require.Equal(t, [][]byte{[]byte("chain")}, issuer.GetX5c())
}

func Test_NewIssuer_DidX509(t *testing.T) {
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
	require.NotNil(t, issuer)
	require.Equal(t, "did:x509:0:sha256:-PzQNPfBWEBI2kbwlzfpeOssuKzedW1eR-y1a_Q-cv4::subject:CN:www.server.com", issuer.GetIss())
	require.Equal(t, []byte("#foobar"), issuer.GetKid())
	require.Equal(t, [][]byte{cert.Raw, cert.Raw}, issuer.GetX5c())
}

func Test_ResolveDidX509(t *testing.T) {
	type test struct {
		did         string
		x5chain     [][]byte
		errContains string
	}

	signCert, err := base64.StdEncoding.DecodeString("MIIB3zCCAYWgAwIBAgIQT+RflxsIC8UkGnTzRdI6DjAKBggqhkjOPQQDAjA9MQswCQYDVQQGEwJJRTEVMBMGA1UEChMMRG9Ob3RUcnVzdE1lMRcwFQYDVQQDEw5Db3NlUGxheWdyb3VuZDAeFw0yNTAzMDYyMzEwMDFaFw0yNTAzMTEyMzEwMDFaMEQxCzAJBgNVBAYTAklFMRUwEwYDVQQKEwxEb05vdFRydXN0TWUxHjAcBgNVBAMTFUNvc2VQbGF5Z3JvdW5kIFNpZ25lcjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABKJqndX2wcT7st0P144T4/KiEfJL3jVVFwXias8bq4ei1+Qh34qPtZOrijwbv+ekXurKFXsJ9hUpy65WzgYGEyOjYDBeMA4GA1UdDwEB/wQEAwIHgDArBgNVHSUEJDAiBggrBgEFBQcDAwYKKwYBBAGCNwIBFgYKKwYBBAGCNz0BATAfBgNVHSMEGDAWgBSaxvMTI0/eIvofo8TFkgTJkFQMdjAKBggqhkjOPQQDAgNIADBFAiEA1w9md+aZUU7bITfacaxDIZgqz6Ho0nLlAATPqcuXcVwCIBzIKqc/YDKndgBvPwMRzLaTPsI5ANy92ZYRcDrT/AnE")
	require.NoError(t, err)
	caCert, err := base64.StdEncoding.DecodeString("MIIBqzCCAVGgAwIBAgIBATAKBggqhkjOPQQDAjA9MQswCQYDVQQGEwJJRTEVMBMGA1UEChMMRG9Ob3RUcnVzdE1lMRcwFQYDVQQDEw5Db3NlUGxheWdyb3VuZDAeFw0yNTAzMDYyMzEwMDFaFw0zNTAzMDYyMzEwMDFaMD0xCzAJBgNVBAYTAklFMRUwEwYDVQQKEwxEb05vdFRydXN0TWUxFzAVBgNVBAMTDkNvc2VQbGF5Z3JvdW5kMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErsl7QOd/sf3KTioUgc//QqJ5fnnbUzwYidEFnzYXWBA3BP9C0S5J+IGxYIoorepTMOVQ/LcL/kbDmDrD9gkkh6NCMEAwDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFJrG8xMjT94i+h+jxMWSBMmQVAx2MAoGCCqGSM49BAMCA0gAMEUCIQC/UuMIrDXoFvYQhD2ev7dSnyQfe+/7j4ldazb6bbNGogIgelR+L8RlybeVVi40/rN8LHJ7fyefI3Ycte0mmC/1zw8=")
	require.NoError(t, err)

	tests := []test{
		{
			did:         "foo",
			errContains: "invalid did prefix",
		},
		{
			did:         "did:x509:99:sha256",
			errContains: "invalid did prefix",
		},
		{
			did:         "did:x509:0:",
			errContains: "invalid CA fingerprint format",
		},
		{
			did:         "did:x509:0:sha1024:foobar",
			errContains: "unsupported fingerprint algorithm",
		},
		{
			did:         "did:x509:0:sha256:foobar",
			x5chain:     [][]byte{[]byte("nomatch")},
			errContains: "must be more than one certificate",
		},
		{
			did:         "did:x509:0:sha256:foobar",
			x5chain:     [][]byte{signCert, caCert},
			errContains: "invalid CA fingerprint foobar",
		},
		{
			did:         "did:x509:0:sha256:I_4hfs2FjU_cQza1HBcpkTZzD30pdmOgxDRSzxCYT0A::foobar",
			x5chain:     [][]byte{signCert, caCert},
			errContains: "invalid cert policy: foobar",
		},
		{
			did:         "did:x509:0:sha256:I_4hfs2FjU_cQza1HBcpkTZzD30pdmOgxDRSzxCYT0A::subject:CN:www.server.com",
			x5chain:     [][]byte{signCert, caCert},
			errContains: "invalid subject value",
		},
		{
			did:     "did:x509:0:sha256:I_4hfs2FjU_cQza1HBcpkTZzD30pdmOgxDRSzxCYT0A::subject:CN:CosePlayground%20Signer",
			x5chain: [][]byte{signCert, caCert},
		},
	}

	for _, tt := range tests {
		t.Run("test did: "+tt.did, func(t *testing.T) {
			_, err := signer.ResolveDidX509(tt.did, tt.x5chain)
			if tt.errContains != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errContains)
				return
			}
			require.NoError(t, err)
		})
	}
}
