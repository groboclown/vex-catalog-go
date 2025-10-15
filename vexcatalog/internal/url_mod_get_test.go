package internal

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type errTransport struct{}

func (e errTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return nil, errors.New("transport error")
}

func Test_UrlModGet_TransportError(t *testing.T) {
	client := http.Client{Transport: errTransport{}}
	body, _, err := UrlModGet("http://example.com", client)
	if err == nil || err.Error() != `Get "http://example.com": transport error` {
		t.Fatalf("expected transport error, found %v", err)
	}
	if body != nil {
		t.Fatalf("expected nil body on transport error")
	}
}

func Test_UrlModGet_Status404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	client := srv.Client()
	body, _, err := UrlModGet(srv.URL, *client)
	if err == nil || err.Error() != "failed to get "+srv.URL+": 404 Not Found" {
		t.Fatalf("expected error message, found %v", err)
	}
	if body != nil {
		t.Fatal("expected nil body on status error")
	}
}

func Test_UrlModGet_NoLastModified(t *testing.T) {
	content := "sturgeon"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(content))
	}))
	defer srv.Close()

	before := time.Now()
	body, modTime, err := UrlModGet(srv.URL, *srv.Client())
	after := time.Now()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data, _ := io.ReadAll(body)
	body.Close()
	if string(data) != content {
		t.Errorf("expected body %q, found %q", content, string(data))
	}
	if modTime.Before(before) || modTime.After(after) {
		t.Errorf("modTime %v not between %v and %v", modTime, before, after)
	}
}

func Test_UrlModGet_InvalidLastModified(t *testing.T) {
	content := "tuna"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Last-Modified", "invalid")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(content))
	}))
	defer srv.Close()

	before := time.Now()
	body, modTime, err := UrlModGet(srv.URL, *srv.Client())
	after := time.Now()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data, _ := io.ReadAll(body)
	body.Close()
	if string(data) != content {
		t.Errorf("expected body %q, found %q", content, string(data))
	}
	if modTime.Before(before) || modTime.After(after) {
		t.Errorf("modTime %v not between %v and %v", modTime, before, after)
	}
}

func Test_UrlModGet_ValidLastModified(t *testing.T) {
	content := "flounder"
	known := time.Date(2020, 5, 1, 10, 0, 0, 0, time.UTC)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Last-Modified", known.Format(http.TimeFormat))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(content))
	}))
	defer srv.Close()

	body, modTime, err := UrlModGet(srv.URL, *srv.Client())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data, _ := io.ReadAll(body)
	body.Close()
	if string(data) != content {
		t.Errorf("expected body %q, found %q", content, string(data))
	}
	if !modTime.Equal(known) {
		t.Errorf("expected modTime %v, found %v", known, modTime)
	}
}
