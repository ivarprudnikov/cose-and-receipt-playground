package signer

import (
	"crypto/rand"
	_ "crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ivarprudnikov/cose-and-receipt-playground/internal/keys"
	"github.com/veraison/go-cose"
)

// https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/
const ISSUER_HEADER_KEY = int64(391)
const ISSUER_HEADER_FEED = int64(392)
const ISSUER_HEADER_REG_INFO = int64(393)

const DEFAULT_CONTENT_TYPE = "text/plain"

func PrintHeaders(headers map[any]any) string {
	returnValue := []string{}
	for key, value := range headers {
		var parsedVal string
		if v, ok := value.([]byte); ok {
			if key == cose.HeaderLabelKeyID {
				parsedVal = string(v)
			} else {
				parsedVal = base64.StdEncoding.EncodeToString(v)
			}
		} else if v, ok := value.(map[any]any); ok {
			parsedVal = fmt.Sprintf("[ %v ]", PrintHeaders(v))
		} else {
			parsedVal = fmt.Sprintf("%v", value)
		}
		returnValue = append(returnValue, fmt.Sprintf("%v: %v", key, parsedVal))
	}
	sort.Strings(returnValue)
	return strings.Join(returnValue, ", ")
}

func DefaultHeaders(hostport string, pubKeyId string) cose.ProtectedHeader {
	hostport = strings.ReplaceAll(hostport, ":", "%3A")
	return cose.ProtectedHeader{
		cose.HeaderLabelAlgorithm:   cose.AlgorithmES256,
		cose.HeaderLabelContentType: DEFAULT_CONTENT_TYPE,
		cose.HeaderLabelKeyID:       []byte("#" + pubKeyId),
		ISSUER_HEADER_KEY:           "did:web:" + hostport,
		ISSUER_HEADER_FEED:          "demo",
		ISSUER_HEADER_REG_INFO: map[any]any{
			"register_by": uint64(time.Now().Add(24 * time.Hour).Unix()),
			"sequence_no": uint64(1),
			"issuance_ts": uint64(time.Now().Unix()),
		},
	}
}

func headerKeyFromString(key string) any {
	var detectedKey any
	if intKey, err := strconv.ParseInt(key, 10, 64); err == nil {
		detectedKey = intKey
	} else {
		detectedKey = key
	}
	return detectedKey
}

func setValInAny(src *any, key any, value any, ignoreIfExists bool) error {
	if obj, ok := (*src).(map[any]any); ok { // check if this is a map
		if _, ok := obj[key]; !ok || !ignoreIfExists {
			obj[key] = value
		}
		return nil
	} else if slice, ok := (*src).(*[]any); ok { // check if this is a slice
		if idx, ok := key.(int); ok {
			if idx >= len(*slice) { // if the index is out of bounds we need to append
				*slice = append(*slice, make([]any, idx-len(*slice)+1)...)
				(*slice)[idx] = value
			} else if !ignoreIfExists {
				(*slice)[idx] = value
			}
			*src = (any)(slice)
			return nil
		} else {
			return fmt.Errorf("invalid key to be used in array %v", key)
		}
	}
	return fmt.Errorf("unexpected pointer type %T with val: %v", *src, *src)
}

func getValInAny(src *any, key any) *any {
	var child *any
	if obj, ok := (*src).(map[any]any); ok { // check if this is a map
		if val, ok := obj[key]; ok {
			child = &val
		}
	} else if slice, ok := (*src).(*[]any); ok { // check if this is a slice
		if idx, ok := key.(int); ok {
			if idx < len(*slice) {
				val := (*slice)[idx]
				child = &val
			}
		}
	}
	return child
}

func AddHeaders(source cose.ProtectedHeader, customHeaders map[string]string) error {
	// convert to any to be able to manipulate it
	sourceMap := (map[any]any)(source)
	sourceAny := (any)(sourceMap)
	for key, nestedValue := range customHeaders {
		// get the pointer to be able to move it around
		current := &sourceAny
		// convert string to rune slice to be able to properly iterate over each character
		keyRunes := []rune(key)
		// use two pointers to scan over the key
		for from := 0; from < len(keyRunes); from++ {
			for to := from; to < len(keyRunes) && to >= from; to++ {
				if to == len(keyRunes)-1 {
					// if we reached the end of the key
					// we can set the end value
					// we are either in a map or a slice
					if string(keyRunes[to]) == "]" {
						// extract the index
						index, err := strconv.Atoi(string(keyRunes[from:to]))
						if err != nil {
							return fmt.Errorf("conflict: %v is not a valid index", string(keyRunes[from:to]))
						}
						err = setValInAny(current, index, nestedValue, false)
						if err != nil {
							return fmt.Errorf("failed to set array value %v", nestedValue)
						}
					} else {
						detectedKey := headerKeyFromString(string(keyRunes[from:]))
						err := setValInAny(current, detectedKey, nestedValue, false)
						if err != nil {
							return fmt.Errorf("failed to set object value %v under key %v", nestedValue, detectedKey)
						}
					}
					from = to + 1
				} else if string(keyRunes[to]) == "." {
					// FIXME: check if in array

					// if we reached a dot then the value is a map
					// we use the key to create a map if one doesn't exist
					// then we move the pointer to the value to the map and move the pointers
					detectedKey := headerKeyFromString(string(keyRunes[from:to]))
					setValInAny(current, detectedKey, map[any]any{}, true)
					current = getValInAny(current, detectedKey)
					from = to + 1 // skip the dot
				} else if string(keyRunes[to]) == "[" {
					if to == 0 {
						return fmt.Errorf("header key cannot start with a square bracket")
					}
					// FIXME: check if in array

					// square bracket means we have a slice
					detectedKey := headerKeyFromString(string(keyRunes[from:to]))
					// set it if it does not exist
					setValInAny(current, detectedKey, &[]any{}, true)
					current = getValInAny(current, detectedKey)
					from = to + 1 // skip the bracket
				}
			}
		}
	}
	return nil
}

func CreateSignature(payload []byte, customHeaders map[string]string, hostport string, keystore *keys.KeyStore) ([]byte, error) {
	signer, err := keystore.GetCoseSigner()
	if err != nil {
		return nil, err
	}
	// create message header
	protected := DefaultHeaders(hostport, keystore.GetPublicKeyId())
	AddHeaders(protected, customHeaders)
	headers := cose.Headers{
		Protected: protected,
	}

	// sign and marshal message
	return cose.Sign1(rand.Reader, signer, headers, payload, nil)
}

func VerifySignature(signature []byte, didHttpClient *http.Client) error {
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(signature); err != nil {
		return fmt.Errorf("failed to unmarshal signature bytes: %w", err)
	}

	issuerRaw := msg.Headers.Protected[ISSUER_HEADER_KEY]
	issuer, ok := issuerRaw.(string)
	if !ok {
		return fmt.Errorf("issuer is not a string: %v", issuerRaw)
	}
	kidRaw := msg.Headers.Protected[cose.HeaderLabelKeyID]
	kid, ok := kidRaw.([]byte)
	if !ok {
		return fmt.Errorf("kid is not a byte array: %v", kidRaw)
	}
	algRaw := msg.Headers.Protected[cose.HeaderLabelAlgorithm]
	alg, ok := algRaw.(cose.Algorithm)
	if !ok {
		return fmt.Errorf("unexpected alg value: %v", algRaw)
	}

	log.Printf("resolving issuer did: %s, kid %s, alg %v \n", issuer, kid, alg)
	didResolver := keys.Did{Issuer: issuer, KeyId: string(kid), Client: didHttpClient}
	pubKey, err := didResolver.ResolvePublicKey()
	if err != nil {
		return fmt.Errorf("failed to resolve public key: %w", err)
	}

	verifier, err := cose.NewVerifier(alg, pubKey)
	if err != nil {
		return fmt.Errorf("failed to create signature verifier: %w", err)
	}

	return msg.Verify(nil, verifier)
}
