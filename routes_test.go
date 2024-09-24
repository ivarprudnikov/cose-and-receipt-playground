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
		name       string
		formValues map[string]string
	}
	tests := []test{
		{
			name:       "default content type used",
			formValues: map[string]string{"payload": "hello", "contenttype": ""},
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
			mp.Close()

			req := httptest.NewRequest(http.MethodPost, "/", reqBody)
			req.Header.Set("Content-Type", mp.FormDataContentType())

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
			var sig cose.Sign1Message
			err = sig.UnmarshalCBOR(body)
			if err != nil {
				t.Errorf("error unmarshaling response body: %v", err)
			}
		})
	}
}
