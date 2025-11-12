package catalog

import (
	"fmt"
	"net/http"

	"github.com/groboclown/vex-catalog-go/vexcatalog"
	"github.com/groboclown/vex-catalog-go/vexcatalog/cache"
	"github.com/groboclown/vex-catalog-go/vexcatalog/vexloader"
	"github.com/groboclown/vex-catalog-go/vexcatalog/vexrepo"
)

// NewVexRepoCatalogLoader creates a new VEX catalog loader for a VEX repository-style catalog.
func NewVexRepoCatalogLoader[T any](
	catalog *Catalog,
	loader vexloader.VexMarshaller[T],
	cache cache.PackageCache,
	client http.Client,
) (vexcatalog.VexLoader[T], error) {
	if catalog == nil {
		return nil, nil
	}
	if catalog.Kind != "vex-repo" {
		// Not a VEX repository catalog.
		return nil, fmt.Errorf("requires catalog kind 'vex-repo', found '%s'", catalog.Kind)
	}
	repo, _, err := vexrepo.DownloadJsonVexRepository(
		catalog.URL,
		client,
	)
	if err != nil {
		return nil, err
	}
	r, ok := vexrepo.NewVexRepositoryLoader(
		repo,
		loader,
		cache,
		client,
	)
	if !ok {
		return nil, fmt.Errorf("no supported locations in VEX repository at '%s'", catalog.URL)
	}
	return r, nil
}
