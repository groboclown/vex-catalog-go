package catalog

import (
	"net/http"
	"time"

	"github.com/groboclown/vex-catalog-go/vexcatalog/cache"
	"github.com/groboclown/vex-catalog-go/vexcatalog/vexloader"
	"github.com/package-url/packageurl-go"
)

// NewVexTemplateCatalogLoader creates a new VEX loader for a template-style catalog.
func NewVexTemplateCatalogLoader[T any](
	catalog *Catalog,
	loader vexloader.VexMarshaller[T],
	cache cache.PackageCache,
	updateInterval time.Duration,
	client http.Client,
) *VexUrlCatalogLoader[T] {
	if catalog == nil || catalog.Kind != "template" {
		return nil
	}

	return NewVexUrlCatalogLoader(
		catalog,
		loader,
		func(purl *packageurl.PackageURL, vulnId string) string {
			return catalog.URLTemplate.Evaluate(purl, vulnId)
		},
		cache,
		updateInterval,
		client,
	)
}
