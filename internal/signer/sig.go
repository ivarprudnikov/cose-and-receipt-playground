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

func DefaultHeaders(hostport string) cose.ProtectedHeader {
	hostport = strings.ReplaceAll(hostport, ":", "%3A")
	return cose.ProtectedHeader{
		cose.HeaderLabelAlgorithm:   cose.AlgorithmES256,
		cose.HeaderLabelContentType: DEFAULT_CONTENT_TYPE,
		cose.HeaderLabelKeyID:       []byte("#" + keys.GetPublicKeyIdDefault()),
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

func setValInAny(src *any, key any, value any, ignoreIfExists bool) *any {
	fmt.Printf("setValInAny src pointer %p val %v k:%v v:%v\n", src, *src, key, value)
	if obj, ok := (*src).(map[any]any); ok { // check if this is a map
		if _, ok := obj[key]; !ok || !ignoreIfExists {
			obj[key] = value
		}
		return src
	} else if slice, ok := (*src).([]any); ok { // check if this is a slice
		if idx, ok := key.(int); ok {
			if idx >= len(slice) { // if the index is out of bounds we need to append
				slice = append(slice, value) // FIXME
			} else if !ignoreIfExists {
				slice[idx] = value
			}
			sliceToAny := (any)(slice)
			*src = sliceToAny

			fmt.Printf("setValInAny src after %p val %v \n", src, *src)
			return &sliceToAny
		}
	}
	panic("unexpected type")
}

func getValInAny(src *any, key any) *any {
	var child *any
	if obj, ok := (*src).(map[any]any); ok { // check if this is a map
		if val, ok := obj[key]; ok {
			child = &val
		}
	} else if slice, ok := (*src).([]any); ok { // check if this is a slice
		if idx, ok := key.(int); ok {
			if idx < len(slice) {
				val := slice[idx]
				child = &val
			}
		}
	}
	fmt.Printf("getValInAny src %p child %p \n", src, child)
	return child
}

func AddHeaders(source cose.ProtectedHeader, customHeaders map[string]string) cose.ProtectedHeader {
	// convert to any to be able to manipulate it
	sourceMap := (map[any]any)(source)
	fmt.Printf("sourceMap %p \n", &sourceMap)
	sourceAny := (any)(sourceMap)
	fmt.Printf("sourceAny %p \n", &sourceAny)

	for key, nestedValue := range customHeaders {
		// get the pointer to be able to move it around
		current := &sourceAny
		fmt.Printf("current %p \n", current)
		// convert string to rune slice to be able to properly iterate over each character
		keyRunes := []rune(key)
		// use two pointers to iterate over the key
		// the gap between the pointers indicates the key
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
							// TODO: test this
							log.Printf("conflict: %v is not a slice index\n", string(keyRunes[from:to]))
							break
						}
						current = setValInAny(current, index, nestedValue, false)
					} else {
						detectedKey := headerKeyFromString(string(keyRunes[from:]))
						current = setValInAny(current, detectedKey, nestedValue, false)
					}
					from = to + 1
				} else if string(keyRunes[to]) == "." {
					// FIXME: check if in array

					// if we reached a dot then the value is a map
					// we use the key to create a map if one doesn't exist
					// then we move the pointer to the value to the map and move the pointers
					detectedKey := headerKeyFromString(string(keyRunes[from:to]))
					current = setValInAny(current, detectedKey, map[any]any{}, true)
					current = getValInAny(current, detectedKey)
					from = to + 1 // skip the dot
				} else if string(keyRunes[to]) == "[" {
					if to == 0 {
						panic("header key cannot start with a square bracket")
					}
					// FIXME: check if in array

					// square bracket means we have a slice
					detectedKey := headerKeyFromString(string(keyRunes[from:to]))
					// set it if it does not exist
					current = setValInAny(current, detectedKey, make([]any, 0), true)
					current = getValInAny(current, detectedKey)
					from = to + 1 // skip the bracket
				}
			}
		}
	}

	fmt.Printf("sourceAny after %p \n", &sourceAny)
	// convert back to the original type
	if sourceMap, ok := sourceAny.(map[any]any); ok {
		return (cose.ProtectedHeader)(sourceMap)
	}
	return source
}

func CreateSignature(payload []byte, customHeaders map[string]string, hostport string) ([]byte, error) {
	signer, err := keys.GetCoseSignerDefault()
	if err != nil {
		return nil, err
	}
	// create message header
	headers := cose.Headers{
		Protected: AddHeaders(DefaultHeaders(hostport), customHeaders),
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

	verifier, err := keys.GetCoseVerifierFor(alg, pubKey)
	if err != nil {
		return fmt.Errorf("failed to create signature verifier: %w", err)
	}

	return msg.Verify(nil, verifier)
}
