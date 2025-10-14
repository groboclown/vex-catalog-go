package vexrepo

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/groboclown/vex-catalog-go/pkg/cache"
	"github.com/groboclown/vex-catalog-go/pkg/vexloader"
)

// VexRepositoryUrlLoader accesses a URL-based VEX repository.
// This keeps a local cache of the VEX documents, and updates them
// after the specified update interval.
//
// The loader uses the provided VexMarshaller to parse the VEX documents
// into the desired type T.
func NewVexRepositoryUrlLoader[T any](
	loader vexloader.VexMarshaller[T],
	version *VexRepositoryVersion,
	location *VexRepositoryLocation,
	cache cache.PackageCacheFactory,
	client http.Client,
) *VexRepoIndexLoader[T] {
	interval, err := version.ParseUpdateInterval()
	if err != nil {
		// Invalid interval.  Use some rational default.
		interval = 24 * time.Hour
	}
	baseUrl := strings.TrimSuffix(location.URL, "/")
	indexCache := NewUrlIndexCache(baseUrl, interval, client)
	return NewVexRepoIndexLoader(loader, indexCache, cache)
}

type UrlIndexCache struct {
	baseUrl              string
	indexUrl             string
	indexRefreshInterval time.Duration
	index                *RepositoryIndex
	indexNextLoadTime    time.Time
	client               http.Client
	mutex                sync.RWMutex
}

var _ IndexCache = (*UrlIndexCache)(nil)

func NewUrlIndexCache(baseUrl string, refreshInterval time.Duration, client http.Client) *UrlIndexCache {
	return &UrlIndexCache{
		baseUrl:              strings.TrimSuffix(baseUrl, "/"),
		indexUrl:             fmt.Sprintf("%s/index.json", baseUrl),
		indexRefreshInterval: refreshInterval,
		client:               client,
	}
}

func (v *UrlIndexCache) ReadIndex() (*RepositoryIndex, error) {
	// Is it already loaded and still valid?
	v.mutex.RLock()
	defer v.mutex.RUnlock()
	if v.index != nil && time.Now().Before(v.indexNextLoadTime) {
		return v.index, nil
	}

	// Need to reload it.  Write lock to prevent others from entering this
	// line of code while it reloads.
	v.mutex.Lock()
	defer v.mutex.Unlock()
	index, updatedAt, err := DownloadJsonRepositoryIndex(v.indexUrl, v.client)
	if err != nil {
		return nil, err
	}
	v.index = index
	v.indexNextLoadTime = updatedAt.Add(v.indexRefreshInterval)
	return v.index, nil
}

func (v *UrlIndexCache) ReadFile(path string) (io.ReadCloser, error) {
	url := fmt.Sprintf("%s/%s", v.baseUrl, strings.TrimPrefix(path, "/"))
	resp, err := v.client.Get(url)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("failed to get %s: %s", url, resp.Status)
	}
	return resp.Body, nil
}

func (v *UrlIndexCache) Flush() {
	v.mutex.Lock()
	defer v.mutex.Unlock()
	v.index = nil
	v.indexNextLoadTime = time.Time{}
}
