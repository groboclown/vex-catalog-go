package cache

import (
	"io"
	"time"

	"github.com/package-url/packageurl-go"
)

// NoneCacheFactory is a cache factory that does not cache anything.
type NoneCacheFactory struct{}

var _ PackageCacheFactory = (*NoneCacheFactory)(nil)

func (n *NoneCacheFactory) Cache(
	pkg packageurl.PackageURL,
	updateInterval time.Duration,
	pull func() (io.ReadCloser, time.Time, error),
) (PackageCache, error) {
	return &noneCache{puller: pull}, nil
}

type noneCache struct {
	puller func() (io.ReadCloser, time.Time, error)
}

var _ PackageCache = (*noneCache)(nil)

func (n *noneCache) Get() (io.ReadCloser, error) {
	r, _, e := n.puller()
	return r, e
}

func (n *noneCache) Flush() {}
