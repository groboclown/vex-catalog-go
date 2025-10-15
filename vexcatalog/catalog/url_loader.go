package catalog

import (
	"context"
	"io"
	"net/http"
	"time"

	"github.com/groboclown/vex-catalog-go/vexcatalog"
	"github.com/groboclown/vex-catalog-go/vexcatalog/cache"
	"github.com/groboclown/vex-catalog-go/vexcatalog/internal"
	"github.com/groboclown/vex-catalog-go/vexcatalog/vexloader"
	"github.com/package-url/packageurl-go"
)

type VexUrlCatalogLoader[T any] struct {
	loader         vexloader.VexMarshaller[T]
	catalog        *Catalog
	urlGetter      func(purl *packageurl.PackageURL, vulnId string) string
	cache          cache.PackageCacheFactory
	updateInterval time.Duration
	client         http.Client
}

var _ vexcatalog.VexLoader[int] = (*VexUrlCatalogLoader[int])(nil)

// NewVexUrlCatalogLoader creates a new VEX catalog loader for a catalog that pulls from a URL.
func NewVexUrlCatalogLoader[T any](
	catalog *Catalog,
	loader vexloader.VexMarshaller[T],
	urlGetter func(purl *packageurl.PackageURL, vulnId string) string,
	cache cache.PackageCacheFactory,
	updateInterval time.Duration,
	client http.Client,
) *VexUrlCatalogLoader[T] {
	return &VexUrlCatalogLoader[T]{
		loader:         loader,
		catalog:        catalog,
		urlGetter:      urlGetter,
		cache:          cache,
		updateInterval: updateInterval,
		client:         client,
	}
}

func (v *VexUrlCatalogLoader[T]) LoadVex(
	ctx context.Context,
	purl *packageurl.PackageURL,
	vulnId string,
	vexChan chan<- T,
	errChan chan<- error,
) {
	if v == nil || v.catalog == nil {
		return
	}
	if !v.catalog.MatchesPurl(purl) || !v.catalog.MatchesVulnerability(vulnId) {
		return
	}
	entry, err := v.cache.Cache(*purl, v.updateInterval, func() (io.ReadCloser, time.Time, error) {
		url := v.urlGetter(purl, vulnId)
		return internal.UrlModGet(url, v.client)
	})
	if err != nil {
		errChan <- err
		return
	}
	body, err := entry.Get()
	if err != nil {
		errChan <- err
		return
	}
	defer body.Close()
	vexDoc, err := v.loader.LoadVex(
		body,
		v.catalog.FileFormat.Standard,
		v.catalog.FileFormat.Version,
		v.catalog.FileFormat.Compression,
	)
	if err != nil {
		errChan <- err
		return
	}
	vexChan <- vexDoc
}

func (v *VexUrlCatalogLoader[T]) Close() error {
	return nil
}
