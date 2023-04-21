package keys_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ivarprudnikov/cose-and-receipt-playground/keys"
	"github.com/stretchr/testify/require"
)

func Test_Did_GetUrl(t *testing.T) {
	for _, tc := range []struct {
		name          string
		issuer        string
		expectedUrl   string
		errorContains string
	}{
		{"did with default path", "did:web:foo.bar.com", "https://foo.bar.com/.well-known/did.json", ""},
		{"did with custom path", "did:web:foo.bar.com:xxx:yyy", "https://foo.bar.com/xxx/yyy/did.json", ""},
		{"invalid issuer", "xyz", "", "invalid issuer: xyz"},
		{"invalid issuer", "did:web", "", "invalid issuer: did:web"},
		{"invalid did method", "did:xxx:foo.com", "", "invalid issuer: did:xxx:foo.com"},
		{"invalid url", "did:web:%", "", "invalid URL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			did := keys.Did{Issuer: tc.issuer}
			url, err := did.GetUrl()
			if tc.errorContains != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errorContains)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.expectedUrl, url.String())
		})
	}
}

func Test_Did_FetchDocument(t *testing.T) {
	for _, tc := range []struct {
		name          string
		didDoc        string
		errorContains string
	}{
		{"retrieves doc", "{}", ""},
		{"retrieves doc", "", "EOF"},
		{"retrieves doc", "[]", "cannot unmarshal array"},
		{"retrieves doc", "1", "cannot unmarshal number"},
		{"retrieves doc", `""`, "cannot unmarshal string"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(tc.didDoc))
			}))

			serverUrl := strings.TrimPrefix(tlsServer.URL, "https://")
			serverUrl = strings.ReplaceAll(serverUrl, ":", "%3A")

			did := keys.Did{Issuer: "did:web:" + serverUrl, Client: tlsServer.Client()}
			_, err := did.FetchDocument()
			if tc.errorContains != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errorContains)
				return
			}
			require.NoError(t, err)
		})
	}
}

func Test_Did_ResolvePublicKey(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		didDoc, err := keys.CreateDoc(strings.ReplaceAll(r.Host, ":", "%3A"), privateKey.Public())
		require.NoError(t, err)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(didDoc))
	}))

	serverUrl := strings.TrimPrefix(tlsServer.URL, "https://")
	serverUrl = strings.ReplaceAll(serverUrl, ":", "%3A")

	did := keys.Did{Issuer: "did:web:" + serverUrl, KeyId: keys.KEY_ID, Client: tlsServer.Client()}
	parsedPubKey, err := did.ResolvePublicKey()
	require.NoError(t, err)

	require.Equal(t, privateKey.Public(), parsedPubKey)
}
