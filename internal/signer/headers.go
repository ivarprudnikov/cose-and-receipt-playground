package signer

import (
	"encoding/base64"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/veraison/go-cose"
)

// https://www.ietf.org/archive/id/draft-ietf-scitt-architecture-11.html
const CWT_CLAIMS_HEADER = int64(15)
const CWT_CLAIMS_ISSUER_KEY = int64(1)
const CWT_CLAIMS_SUBJECT_KEY = int64(2)
const DEFAULT_CONTENT_TYPE = "text/plain"

// DefaultHeaders returns a set of protected headers that are common for all COSE_Sign1 messages
func DefaultHeaders(issuer Issuer) cose.ProtectedHeader {
	protected := cose.ProtectedHeader{
		cose.HeaderLabelAlgorithm:   cose.AlgorithmES256,
		cose.HeaderLabelContentType: DEFAULT_CONTENT_TYPE,
		CWT_CLAIMS_HEADER: map[any]any{
			CWT_CLAIMS_SUBJECT_KEY: "demo",
		},
	}

	if issuer.profile == DidX509 {
		protected[cose.HeaderLabelX5Chain] = issuer.GetX5c()
		protected[CWT_CLAIMS_HEADER].(map[any]any)[CWT_CLAIMS_ISSUER_KEY] = issuer.GetIss()
	} else if issuer.profile == DidWeb {
		protected[cose.HeaderLabelKeyID] = issuer.GetKid()
		protected[CWT_CLAIMS_HEADER].(map[any]any)[CWT_CLAIMS_ISSUER_KEY] = issuer.GetIss()
	}

	return protected
}

// PrintHeaders returns a human readable string representation of the headers
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

// AddHeaders adds custom headers to the protected headers
// customHeaders is a map of key value pairs where the key is a string that represents the path to the value
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
