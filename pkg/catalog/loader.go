package catalog

import (
	"context"
	"net/http"

	"github.com/groboclown/vex-catalog-go/pkg"
	"github.com/package-url/packageurl-go"
)

type VexCatalogLoader struct {
	catalog *VexCatalogDoc
	client  http.Client
}

var _ pkg.VexLoader = (*VexCatalogLoader)(nil)

func NewVexCatalogLoader(catalog *VexCatalogDoc, client http.Client) *VexCatalogLoader {
	return &VexCatalogLoader{
		catalog: catalog,
		client:  client,
	}
}

func (v *VexCatalogLoader) LoadVex(
	ctx context.Context,
	purl *packageurl.PackageURL,
	cveId string,
	vexChan chan<- *pkg.VexDocument,
	errChan chan<- error,
) {
	if v == nil || v.catalog == nil {
		return
	}
	for _, cat := range v.catalog.Catalogs {
		go func(cat *Catalog) {
			vexDoc, err := cat.LoadVex(v.client, purl, cveId)
			if err != nil {
				errChan <- err
			}
			if vexDoc != nil {
				vexChan <- vexDoc
			}
		}(&cat)
	}
}
