package cache

import (
	"io"
	"time"

	"github.com/package-url/packageurl-go"
)

// NoneCacheFactory is a cache factory that does not cache anything.
type NoneCacheFactory struct{}

// None the no-op cache factory.
var None PackageCache = (*NoneCacheFactory)(nil)

func (n *NoneCacheFactory) Cache(
	pkg packageurl.PackageURL,
	updateInterval time.Duration,
	pull DocumentPuller,
) (io.ReadCloser, error) {
	r, _, e := pull()
	return r, e
}
