package cache

import (
	"bytes"
	"io"
	"sync"
	"time"

	"github.com/package-url/packageurl-go"
)

type cacheKey string

// MemoryCache is a cache factory that keeps an in-memory cache of downloaded files.
// It keeps hold of all information without any mechanism for eviction beyond the update interval.
// It is thread safe.
type MemoryCache struct {
	packages map[cacheKey]*memoryPackage
	pool     PooledFetch
	lock     sync.RWMutex
}

var _ PackageCache = (*MemoryCache)(nil)

// NewMemoryCache creates a new in-memory cache factory.
// The pool parameter allows for restricting simultaneous requests to a maximum.
func NewMemoryCache(pool PooledFetch) *MemoryCache {
	return &MemoryCache{
		packages: make(map[cacheKey]*memoryPackage),
		pool:     pool,
	}
}

func (m *MemoryCache) Cache(
	pkg packageurl.PackageURL,
	updateInterval time.Duration,
	pull DocumentPuller,
) (io.ReadCloser, error) {
	cached := m.get_or_add(pkg, updateInterval)
	data, err := cached.download(pull, m.pool)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

// FlushPackage removes the given package from the cache.
func (m *MemoryCache) FlushPackage(pkg packageurl.PackageURL) {
	key := as_cache_key(pkg)
	m.lock.Lock()
	defer m.lock.Unlock()
	delete(m.packages, key)
}

// FlushAll removes all packages from the cache.
func (m *MemoryCache) FlushAll() {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.packages = make(map[cacheKey]*memoryPackage)
}

func as_cache_key(pkg packageurl.PackageURL) cacheKey {
	return cacheKey(pkg.String())
}

// get_or_add retrieves the cached package, if it exists, or adds it.
func (m *MemoryCache) get_or_add(
	pkg packageurl.PackageURL,
	updateInterval time.Duration,
) *memoryPackage {
	// Note that Go's mutexes do not support upgradeable locks.
	key := as_cache_key(pkg)
	ret := m.get_cached(key, pkg, updateInterval)
	if ret != nil {
		return ret
	}
	return m.add(key, pkg, updateInterval)
}

// get_cached retrieves the cached package, without checking for expiration.
//
// If expired, then this just returns nil.  It's up to the caller to evict it in a write lock.
func (m *MemoryCache) get_cached(
	key cacheKey,
	pkg packageurl.PackageURL,
	updateInterval time.Duration,
) *memoryPackage {
	// Use a read lock to see if it exists.
	m.lock.RLock()
	defer m.lock.RUnlock()
	cached, ok := m.packages[key]
	if !ok {
		return nil
	}
	// Expiration checks happen as part of the download action.
	return cached
}

// add adds a new cached package entry.
func (m *MemoryCache) add(
	key cacheKey,
	pkg packageurl.PackageURL,
	updateInterval time.Duration,
) *memoryPackage {
	// Use a write lock.
	m.lock.Lock()
	defer m.lock.Unlock()
	if cached, ok := m.packages[key]; ok {
		// Don't overwrite existing.  This means some thread won.
		return cached
	}
	cached := newMemoryPackage(
		pkg,
		updateInterval,
	)
	m.packages[key] = cached
	return cached
}

// add_to_cache adds the given data to the cache for the given package.
// MUST be called with the read lock held.
func (m *MemoryCache) add_to_cache(
	key cacheKey,
	pkg packageurl.PackageURL,
	updateInterval time.Duration,
) *memoryPackage {
	ret := newMemoryPackage(
		pkg,
		updateInterval,
	)
	m.lock.Lock()
	defer m.lock.Unlock()
	m.packages[key] = ret
	return ret
}

type memoryPackage struct {
	pkg            packageurl.PackageURL
	data           []byte
	expires        time.Time
	updateInterval time.Duration
	err            error
	lock           sync.Mutex
}

func newMemoryPackage(
	pkg packageurl.PackageURL,
	updateInterval time.Duration,
) *memoryPackage {
	return &memoryPackage{
		pkg:            pkg,
		updateInterval: updateInterval,
	}
}

func (m *memoryPackage) download(puller DocumentPuller, pool PooledFetch) ([]byte, error) {
	m.lock.Lock()
	defer m.lock.Unlock()
	if (m.err == nil && m.data == nil) || time.Now().After(m.expires) {
		// Need to (re)download.
		// Errors are captured within the inner fetch function.
		_ = pool.Fetch(
			func(r io.Reader, t time.Time, e error) error {
				if e != nil {
					m.err = e
					m.data = nil
					return e
				}
				d, e := io.ReadAll(r)

				if e != nil {
					m.err = e
					m.data = nil
					return e
				}
				m.data = d
				m.err = nil
				m.expires = t
				return nil
			},
			puller,
		)
	}
	// Note: caches the error message.
	return m.data, m.err
}
