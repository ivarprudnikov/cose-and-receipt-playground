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
