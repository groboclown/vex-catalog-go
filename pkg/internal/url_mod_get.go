package internal

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

// UrlModGet is like http.Get, but uses the provided HttpClient interface for making the request.
// It returns the response body as an io.ReadCloser, the time the content was last modified (or time.Now() if unknown).
// It handles status error checks, returning a non-nil error if the request failed or the status was not 200 OK.
// That is, it expects contents (not a 201).
func UrlModGet(url string, client http.Client) (io.ReadCloser, time.Time, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, time.Time{}, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, time.Time{}, fmt.Errorf("failed to get %s: %s", url, resp.Status)
	}
	updatedAt := time.Now()
	if lm := resp.Header.Get("Last-Modified"); lm != "" {
		if t, err := http.ParseTime(lm); err == nil {
			updatedAt = t
		}
	}
	return resp.Body, updatedAt, nil
}
