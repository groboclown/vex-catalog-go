package cache

import (
	"io"
	"time"
)

// PooledFetch allows calling the DocumentPuller using a maximum number of parallel requests.
type PooledFetch interface {
	// Fetch calls the handler with the results of calling the pull function.
	// The maximum number of concurrent calls to Fetch is limited by the pool size.
	// If the pull function returns an error, it is passed to the handler.
	// The error from the handler is returned by Fetch.
	Fetch(
		handler func(io.Reader, time.Time, error) error,
		pull DocumentPuller,
	) error
}

// NotPooledFetcher is a PooledFetch implementation that does not limit the number of concurrent fetches.
type NotPooledFetcher struct{}

var NotPooled PooledFetch = (*NotPooledFetcher)(nil)

func (n *NotPooledFetcher) Fetch(
	handler func(io.Reader, time.Time, error) error,
	pull DocumentPuller,
) error {
	r, t, err := pull()
	defer func() {
		if r != nil {
			r.Close()
		}
	}()
	return handler(r, t, err)
}
