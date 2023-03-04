package keys

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/jwk"
)

const KEY_ID = "foobar"

func CreateDoc(hostport string) ([]byte, error) {

	privateKey := GetKey()

	hostport = strings.ReplaceAll(hostport, ":", "%3A")

	key, err := jwk.New(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create symmetric key: %w", err)
	}
	if _, ok := key.(jwk.ECDSAPrivateKey); !ok {
		return nil, fmt.Errorf(fmt.Sprintf("expected jwk.SymmetricKey, got %T\n", key), err)
	}

	key.Set(jwk.KeyIDKey, KEY_ID)
	buf, err := json.MarshalIndent(key, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal key into JSON: %w", err)

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
	}`, hostport, hostport, KEY_ID, hostport, buf)

	return []byte(didDoc), nil
}
