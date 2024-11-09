package signer_test

import (
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
	issuer := signer.NewIssuer(signer.DidX509, "foo.bar.com:8080", "foobar", [][]byte{[]byte("chain")})
	require.NotNil(t, issuer)
	require.Equal(t, "did:x509:0:sha256:lBSIax6_Al2wZ6TL0ToJA_vZczpTcruhtYvXLBaZt5g::subject:CN:CosePlayground", issuer.GetIss())
	require.Equal(t, []byte("#foobar"), issuer.GetKid())
	require.Equal(t, [][]byte{[]byte("chain")}, issuer.GetX5c())
}

func Test_ResolveDidX509(t *testing.T) {
	type test struct {
		did         string
		x5chain     [][]byte
		errContains string
	}

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
			did:         "did:x509:0:sha256:61e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			x5chain:     [][]byte{[]byte("nomatch")},
			errContains: "must be more than one certificate",
		},
		{
			did:         "did:x509:0:sha256:61e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			x5chain:     [][]byte{[]byte("nomatch"), []byte("nomatch")},
			errContains: "invalid CA fingerprint",
		},
		{
			did:         "did:x509:0:sha256:61e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855::foobar",
			x5chain:     [][]byte{[]byte("nomatch"), []byte("a")},
			errContains: "failed to parse CA certificate",
		},
		{
			did:         "did:x509:0:sha256:61e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855::foobar:foobar",
			x5chain:     [][]byte{[]byte("nomatch"), []byte("a")},
			errContains: "failed to parse CA certificate",
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
