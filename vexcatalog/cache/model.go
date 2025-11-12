package cache

import (
	"errors"
	"io"
	"time"

	"github.com/package-url/packageurl-go"
)

// DocumentPuller is a function that retrieves a VEX document.
// It also returns the time that the document was last modified.
// The construction of the function must know which document it fetches.
// The puller should return the 'NotAvailable' error if the puller does
// not support retrieving the associated Purl; this should signal the cache
// to not store the result, error or otherwise.
type DocumentPuller func() (io.ReadCloser, time.Time, error)

// PackageCache allows for a custom mechanism for storing cached versions of the requested package VEX documents.
//
// This definition only includes the barest minimum interface to support the
// caching needs of the vex catalog.
//
// Implementations must be thread safe.
type PackageCache interface {
	// Cache returns a reader for the given package.
	// The updateInterval should come from the source, which describes how often the document can update.
	// If the cached version is still valid, the pull function might not be called.
	// If an error occurs while fetching or updating the cache, it is returned.
	// Callers should immediately use the returned read object and close it when done; unexpected
	// issues may arise if the caller delays reading.
	Cache(
		pkg packageurl.PackageURL,
		updateInterval time.Duration,

		// pull is a function that, when called, will fetch the latest version of the VEX document.  It returns
		// an io.ReadCloser for the data (which the caller must close), the time that the data was last modified,
		// and any error that occurred while fetching the data.
		pull DocumentPuller,
	) (io.ReadCloser, error)
}

var NotAvailable = errors.New("NotAvailable")
