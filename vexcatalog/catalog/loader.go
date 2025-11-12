package catalog

import (
	"net/http"
	"time"

	"github.com/groboclown/vex-catalog-go/vexcatalog"
	"github.com/groboclown/vex-catalog-go/vexcatalog/cache"
	"github.com/groboclown/vex-catalog-go/vexcatalog/vexloader"
)

func NewVexCatalogLoader[T any](
	doc *VexCatalogDoc,
	loader vexloader.VexMarshaller[T],
	cache cache.PackageCache,
	updateInterval time.Duration,
	client http.Client,
) (*vexcatalog.ProxyVexLoader[T], error) {
	if doc == nil {
		return nil, nil
	}
	loaders := make([]vexcatalog.VexLoader[T], 0, len(doc.Catalogs))
	for _, catalog := range doc.Catalogs {
		switch catalog.Kind {
		case "single":
			singleLoader := NewVexSingleCatalogLoader(&catalog, loader, cache, updateInterval, client)
			if singleLoader != nil {
				loaders = append(loaders, singleLoader)
			}
		case "template":
			templateLoader := NewVexTemplateCatalogLoader(&catalog, loader, cache, updateInterval, client)
			if templateLoader != nil {
				loaders = append(loaders, templateLoader)
			}
		case "vex-repo":
			repoLoader, err := NewVexRepoCatalogLoader(&catalog, loader, cache, client)
			if err != nil {
				return nil, err
			}
			if repoLoader != nil {
				loaders = append(loaders, repoLoader)
			}
		}
	}
	if len(loaders) == 0 {
		return nil, nil
	}
	return vexcatalog.NewProxyVexLoader(loaders...), nil
}

// VexCatalogLoaderFromUrl creates a new VEX catalog loader by fetching the catalog from the URL.
// This helper uses the provided HTTP client to fetch the catalog.
func VexCatalogLoaderFromUrl[T any](
	catalogUrl string,
	loader vexloader.VexMarshaller[T],
	cache cache.PackageCache,
	updateInterval time.Duration,
	client http.Client,
) (*vexcatalog.ProxyVexLoader[T], error) {
	resp, err := client.Get(catalogUrl)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}
	defer resp.Body.Close()
	doc, err := FromJsonReader(resp.Body)
	if err != nil {
		return nil, err
	}
	return NewVexCatalogLoader(
		doc,
		loader,
		cache,
		updateInterval,
		client,
	)
}
