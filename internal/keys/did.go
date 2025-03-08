package keys

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/lestrrat-go/jwx/jwk"
)

func CreateDoc(hostport string, publicKey crypto.PublicKey, b64certChain []string) (string, error) {

	hostport = strings.ReplaceAll(hostport, ":", "%3A")
	pubKeyId := PubKeyDerHash(publicKey)

	key, err := jwk.New(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to create symmetric key: %w", err)
	}
	if _, ok := key.(jwk.ECDSAPublicKey); !ok {
		return "", fmt.Errorf(fmt.Sprintf("expected jwk.SymmetricKey, got %T\n", key), err)
	}

	key.Set(jwk.KeyIDKey, pubKeyId)
	key.Set(jwk.X509CertChainKey, b64certChain)
	buf, err := json.MarshalIndent(key, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal key into JSON: %w", err)

	}

	didDoc := fmt.Sprintf(`{
		"@context": [
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/suites/jws-2020/v1"
		],
		"id": "did:web:%s",
		"assertionMethod": [{
			"id": "did:web:%s#%s",
			"type": "JsonWebKey2020",
			"controller": "did:web:%s",
			"publicKeyJwk": %s
		}]
	}`, hostport, hostport, pubKeyId, hostport, buf)

	return didDoc, nil
}

type Did struct {
	Issuer string
	KeyId  string
	Client *http.Client
}

func (d Did) ResolvePublicKey() (crypto.PublicKey, error) {

	didDoc, err := d.FetchDocument()
	if err != nil {
		return "", fmt.Errorf("failed to get did doc: %w", err)
	}

	if didId, ok := didDoc["id"]; !ok || didId != d.Issuer {
		return "", fmt.Errorf("invalid did id: %s", didId)
	}

	assertionMethod, ok := didDoc["assertionMethod"]
	if !ok {
		return "", errors.New("no assertionMethod in did doc")
	}

	assertionMethodList, ok := assertionMethod.([]interface{})
	if !ok {
		return "", errors.New("assertionMethod is not a list")
	}

	for _, assertionMethod := range assertionMethodList {
		ass, ok := assertionMethod.(map[string]interface{})
		if !ok {
			continue
		}
		id, ok := ass["id"]
		if !ok {
			continue
		}
		idStr, ok := id.(string)
		if !ok {
			continue
		}
		var kid = d.KeyId
		if !strings.HasPrefix(kid, "#") {
			kid = "#" + kid
		}
		if strings.HasSuffix(idStr, kid) {
			publicKeyJwk, ok := ass["publicKeyJwk"]
			if !ok {
				continue
			}

			publicKeyJwkStr, err := json.Marshal(publicKeyJwk)
			if err != nil {
				return "", fmt.Errorf("failed marshal publicKeyJwk: %w", err)
			}

			var raw crypto.PublicKey
			err = jwk.ParseRawKey(publicKeyJwkStr, &raw)
			if err != nil {
				return "", fmt.Errorf("failed to parse jwk: %w", err)
			}

			return raw, nil
		}
	}

	return "", errors.New("no matching assertionMethod")
}

func (d Did) FetchDocument() (map[string]interface{}, error) {
	u, err := d.GetUrl()
	if err != nil {
		return nil, err
	}

	resp, err := d.GetClient().Get(u.String())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to resolve did: %s", resp.Status)
	}

	var didDoc map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&didDoc)
	if err != nil {
		return nil, err
	}

	return didDoc, nil
}

func (d Did) GetClient() *http.Client {
	if d.Client == nil {
		return http.DefaultClient
	}
	return d.Client
}

func (d Did) GetUrl() (*url.URL, error) {
	parts := strings.Split(d.Issuer, ":")
	if len(parts) < 3 || parts[0] != "did" || parts[1] != "web" {
		return nil, fmt.Errorf("invalid issuer: %s", d.Issuer)
	}

	uriParts := parts[2:]
	// replace encoded colons if any
	uriParts[0] = strings.ReplaceAll(uriParts[0], "%3A", ":")
	if len(uriParts) == 1 {
		uriParts = append(uriParts, ".well-known", "did.json")
	} else {
		uriParts = append(uriParts, "did.json")
	}

	uri := fmt.Sprintf("https://%s", strings.Join(uriParts, "/"))
	return url.Parse(uri)
}
