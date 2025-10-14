package cache

import (
	"io"
	"time"

	"github.com/package-url/packageurl-go"
)

// PackageCacheFactory allows for a custom mechanism for storing cached versions of the requested package VEX documents.
type PackageCacheFactory interface {
	// Cache returns a PackageCache for the given package, creating or updating it as needed.
	// The updateInterval should come from the source, which describes how often the document can update.
	// The pull function is called to fetch the latest version of the VEX document.
	// If the cache is still valid, the pull function may not be called.
	// If an error occurs while fetching or updating the cache, it is returned.
	Cache(
		pkg packageurl.PackageURL,
		updateInterval time.Duration,

		// pull is a function that, when called, will fetch the latest version of the VEX document.  It returns
		// an io.ReadCloser for the data (which the caller must close), the time that the data was last modified,
		// and any error that occurred while fetching the data.
		pull func() (io.ReadCloser, time.Time, error),
	) (PackageCache, error)
}

// PackageCache allows for a custom mechanism for storing cached versions of the requested package VEX documents.
type PackageCache interface {
	Get() (io.ReadCloser, error)
	Flush()
}
