package main_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	main "github.com/ivarprudnikov/cose-and-receipt-playground"
)

func TestIndexPage(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	serverHandler := main.NewHttpHandler()
	serverHandler.ServeHTTP(w, req)
	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("expected status code 200 got %v", res.StatusCode)
	}
}

func TestIndexHtmlPage(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/index.html", nil)
	w := httptest.NewRecorder()
	serverHandler := main.NewHttpHandler()
	serverHandler.ServeHTTP(w, req)
	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("expected status code 200 got %v", res.StatusCode)
	}
}

func TestNotFound(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/foobar", nil)
	w := httptest.NewRecorder()
	serverHandler := main.NewHttpHandler()
	serverHandler.ServeHTTP(w, req)
	res := w.Result()
	if res.StatusCode != http.StatusNotFound {
		t.Errorf("expected status code 404 got %v", res.StatusCode)
	}
}

func TestRateLimiter(t *testing.T) {
	type test struct {
		name       string
		header     string
		reqsSec    []int
		lastStatus int
	}
	tests := []test{
		{
			name:       "no header, no limit",
			header:     "",
			reqsSec:    []int{5, 5},
			lastStatus: http.StatusOK,
		},
		{
			name:       "max four can burst",
			header:     "10.10.10.10",
			reqsSec:    []int{4},
			lastStatus: http.StatusOK,
		},
		{
			name:       "limit reached after burst",
			header:     "10.10.10.20",
			reqsSec:    []int{5},
			lastStatus: http.StatusTooManyRequests,
		},
		{
			name:       "limit reached",
			header:     "10.10.10.30",
			reqsSec:    []int{2, 3},
			lastStatus: http.StatusOK,
		},
	}

	serverHandler := main.NewHttpHandler()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var res *http.Response
			for idx, perSec := range tc.reqsSec {
				for i := 0; i < perSec; i++ {
					req := httptest.NewRequest(http.MethodGet, "/", nil)
					req.Header.Set("X-Forwarded-For", tc.header)
					w := httptest.NewRecorder()
					serverHandler.ServeHTTP(w, req)
					res = w.Result()
				}
				if idx < len(tc.reqsSec)-1 {
					// sleep for a second
					time.Sleep(time.Second)
				}
			}
			if res.StatusCode != tc.lastStatus {
				t.Errorf("expected status code %v got %v", tc.lastStatus, res.StatusCode)
			}
		})
	}
}
