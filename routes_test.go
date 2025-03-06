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
	"github.com/ivarprudnikov/cose-and-receipt-playground/internal/keys"
	"github.com/stretchr/testify/require"
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
			require.Equal(t, tc.status, res.StatusCode)
		})
	}
}

func TestDidDoc(t *testing.T) {
	tmpDir := t.TempDir()
	tmpKeystore, err := keys.NewKeyStoreIn(tmpDir)
	require.NoError(t, err)

	handler := main.DidHandler(tmpKeystore)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	res := w.Result()
	require.Equal(t, http.StatusOK, res.StatusCode)
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	var diddoc map[string]any
	err = json.Unmarshal(body, &diddoc)
	require.NoError(t, err)
	if _, ok := diddoc["assertionMethod"]; !ok {
		t.Errorf("expected id key in diddoc %v", diddoc)
	}
}

func TestSignatureCreate(t *testing.T) {
	type test struct {
		name           string
		formValues     map[string][]string
		formFiles      map[string][]byte
		status         int
		coseHeaderKeys []any
		coseHeaderVals []any
	}
	tests := []test{
		{
			name:   "fails without payload",
			status: http.StatusBadRequest,
		},
		{
			name:           "create from text",
			formValues:     map[string][]string{"payload": {"hello"}},
			status:         http.StatusOK,
			coseHeaderKeys: []any{int64(1), int64(3), int64(4), int64(15), int64(393)},
			coseHeaderVals: []any{"", "text/plain", "", map[interface{}]interface{}(map[interface{}]interface{}{int64(1): "did:web:localhost%3A8080", int64(2): "demo"}), ""},
		},
		{
			name:       "create from hex",
			formValues: map[string][]string{"payloadhex": {"68656c6c6f"}},
			status:     http.StatusOK,
		},
		{
			name:       "fails with too many payloads",
			formValues: map[string][]string{"payload": {"hello"}, "payloadhex": {"68656c6c6f"}},
			status:     http.StatusBadRequest,
		},
		{
			name:      "create from file",
			formFiles: map[string][]byte{"payloadfile": []byte("hello")},
			status:    http.StatusOK,
		},
		{
			name:       "fails with too many payloads including file",
			formValues: map[string][]string{"payload": {"hello"}},
			formFiles:  map[string][]byte{"payloadfile": []byte("hello")},
			status:     http.StatusBadRequest,
		},
		{
			name:           "uses custom content type",
			formValues:     map[string][]string{"payload": {"hello"}, "contenttype": {"foo/bar"}},
			status:         http.StatusOK,
			coseHeaderKeys: []any{int64(3)},
			coseHeaderVals: []any{"foo/bar"},
		},
		{
			name:           "adds custom headers",
			formValues:     map[string][]string{"payload": {"hello"}, "headerkey": {"77777[0]", "77777[1]", "77777[2]"}, "headerval": {"a", "b", "c", "d", "e"}},
			status:         http.StatusOK,
			coseHeaderKeys: []any{int64(77777)},
			coseHeaderVals: []any{[]any{"a", "b", "c"}},
		},
	}

	tmpDir := t.TempDir()
	tmpKeystore, err := keys.NewKeyStoreIn(tmpDir)
	require.NoError(t, err)
	handler := main.SigCreateHandler(tmpKeystore)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {

			reqBody := new(bytes.Buffer)
			mp := multipart.NewWriter(reqBody)
			for key, val := range tc.formValues {
				for _, v := range val {
					mp.WriteField(key, v)
				}
			}
			for key, val := range tc.formFiles {
				part, err := mp.CreateFormFile(key, key)
				require.NoError(t, err)
				_, err = part.Write(val)
				require.NoError(t, err)
			}
			mp.Close()

			req := httptest.NewRequest(http.MethodPost, "/", reqBody)
			req.Header.Set("Content-Type", mp.FormDataContentType())

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			res := w.Result()
			require.Equal(t, tc.status, res.StatusCode)
			if res.StatusCode != http.StatusOK {
				return
			}
			defer res.Body.Close()
			body, err := io.ReadAll(res.Body)
			require.NoError(t, err)
			var sig cose.Sign1Message
			err = sig.UnmarshalCBOR(body)
			require.NoError(t, err)

			for idx, key := range tc.coseHeaderKeys {
				v, ok := sig.Headers.Protected[key]
				if !ok {
					t.Errorf("expected key %v in protected headers %v", key, sig.Headers.Protected)
				}
				if len(tc.coseHeaderVals) > 0 && tc.coseHeaderVals[idx] != "" {
					require.Equal(t, tc.coseHeaderVals[idx], v)
				}
			}
		})
	}
}
