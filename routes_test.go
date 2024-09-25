package main_test

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	main "github.com/ivarprudnikov/cose-and-receipt-playground"
	"github.com/veraison/go-cose"
)

func TestIndex(t *testing.T) {
	type test struct {
		name   string
		path   string
		status int
	}
	tests := []test{
		{
			name:   "toot reponds with 200",
			path:   "/",
			status: http.StatusOK,
		},
		{
			name:   "index.html reponds with 200",
			path:   "/index.html",
			status: http.StatusOK,
		},
		{
			name:   "unexpected path responds with 404",
			path:   "/xxx",
			status: http.StatusNotFound,
		},
	}

	handler := main.IndexHandler()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			res := w.Result()
			if res.StatusCode != tc.status {
				t.Errorf("expected status code %v got %v", tc.status, res.StatusCode)
			}
		})
	}
}

func TestDidDoc(t *testing.T) {
	handler := main.DidHandler()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("expected status code %v got %v", http.StatusOK, res.StatusCode)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("error reading response body: %v", err)
	}
	var diddoc map[string]interface{}
	err = json.Unmarshal(body, &diddoc)
	if err != nil {
		t.Fatalf("Unexpected error %v", err)
	}
	if _, ok := diddoc["assertionMethod"]; !ok {
		t.Errorf("expected id key in diddoc %v", diddoc)
	}
}

func TestSignatureCreate(t *testing.T) {
	type test struct {
		name           string
		formValues     map[string]string
		formFiles      map[string][]byte
		status         int
		coseHeaderKeys []interface{}
		coseHeaderVals []interface{}
	}
	tests := []test{
		{
			name:   "fails without payload",
			status: http.StatusBadRequest,
		},
		{
			name:           "create from text",
			formValues:     map[string]string{"payload": "hello"},
			status:         http.StatusOK,
			coseHeaderKeys: []interface{}{int64(1), int64(3), int64(4), int64(391), int64(392), int64(393)},
			coseHeaderVals: []interface{}{"", "text/plain", "", "did:web:localhost%3A8080", "demo", ""},
		},
		{
			name:       "create from hex",
			formValues: map[string]string{"payloadhex": "68656c6c6f"},
			status:     http.StatusOK,
		},
		{
			name:       "fails with too many payloads",
			formValues: map[string]string{"payload": "hello", "payloadhex": "68656c6c6f"},
			status:     http.StatusBadRequest,
		},
		{
			name:      "create from file",
			formFiles: map[string][]byte{"payloadfile": []byte("hello")},
			status:    http.StatusOK,
		},
		{
			name:       "fails with too many payloads including file",
			formValues: map[string]string{"payload": "hello"},
			formFiles:  map[string][]byte{"payloadfile": []byte("hello")},
			status:     http.StatusBadRequest,
		},
		{
			name:           "uses custom content type",
			formValues:     map[string]string{"payload": "hello", "contenttype": "foo/bar"},
			status:         http.StatusOK,
			coseHeaderKeys: []interface{}{int64(3)},
			coseHeaderVals: []interface{}{"foo/bar"},
		},
	}

	handler := main.SigCreateHandler()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {

			reqBody := new(bytes.Buffer)
			mp := multipart.NewWriter(reqBody)
			for key, val := range tc.formValues {
				mp.WriteField(key, val)
			}
			for key, val := range tc.formFiles {
				part, err := mp.CreateFormFile(key, key)
				if err != nil {
					t.Errorf("error creating form file: %v", err)
				}
				_, err = part.Write(val)
				if err != nil {
					t.Errorf("error writing form file: %v", err)
				}
			}
			mp.Close()

			req := httptest.NewRequest(http.MethodPost, "/", reqBody)
			req.Header.Set("Content-Type", mp.FormDataContentType())

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			res := w.Result()
			if res.StatusCode != tc.status {
				t.Errorf("expected status code %v got %v", tc.status, res.StatusCode)
			}
			if res.StatusCode != http.StatusOK {
				return
			}
			defer res.Body.Close()
			body, err := io.ReadAll(res.Body)
			if err != nil {
				t.Errorf("error reading response body: %v", err)
			}
			var sig cose.Sign1Message
			err = sig.UnmarshalCBOR(body)
			if err != nil {
				t.Errorf("error unmarshaling response body: %v", err)
			}

			for idx, key := range tc.coseHeaderKeys {
				v, ok := sig.Headers.Protected[key]
				if !ok {
					t.Errorf("expected key %v in protected headers %v", key, sig.Headers.Protected)
				}
				if len(tc.coseHeaderVals) > 0 && tc.coseHeaderVals[idx] != "" {
					if v != tc.coseHeaderVals[idx] {
						t.Errorf("expected value %v for key %v in protected headers %v", tc.coseHeaderVals[idx], key, sig.Headers.Protected)
					}
				}
			}
		})
	}
}
