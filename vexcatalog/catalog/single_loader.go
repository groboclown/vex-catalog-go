package catalog

import (
	"net/http"
	"time"

	"github.com/groboclown/vex-catalog-go/vexcatalog/cache"
	"github.com/groboclown/vex-catalog-go/vexcatalog/vexloader"
	"github.com/package-url/packageurl-go"
)

// NewVexSingleCatalogLoader creates a new VEX catalog loader for a single-style catalog.
func NewVexSingleCatalogLoader[T any](
	catalog *Catalog,
	loader vexloader.VexMarshaller[T],
	cache cache.PackageCacheFactory,
	updateInterval time.Duration,
	client http.Client,
) *VexUrlCatalogLoader[T] {
	if catalog == nil || catalog.Kind != "single" {
		return nil
	}

	return NewVexUrlCatalogLoader(
		catalog,
		loader,
		func(purl *packageurl.PackageURL, vulnId string) string {
			return catalog.URL
		},
		cache,
		updateInterval,
		client,
	)
}
