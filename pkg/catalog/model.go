package catalog

import (
	"time"

	"github.com/groboclown/vex-catalog-go/pkg/catalog/template"
	"github.com/package-url/packageurl-go"
)

// VexCatalogDoc contains the data referenced in the vex-catalog schema.
type VexCatalogDoc struct {
	Comment  string          `json:"$comment,omitempty"`
	Schema   string          `json:"$schema"`
	Metadata CatalogMetadata `json:"metadata"`
	Catalogs []Catalog       `json:"catalogs"`
}

type CatalogMetadata struct {
	Comment     string   `json:"$comment,omitempty"`
	Id          string   `json:"id"`
	Authors     []string `json:"authors"`
	LastUpdated time.Time
}

type Catalog struct {
	Comment           string                  `json:"$comment,omitempty"`
	Kind              string                  `json:"kind"`
	Purls             []packageurl.PackageURL `json:"purls,omitempty"`
	FileFormat        VexFileFormat           `json:"file_format"`
	VulnerabilityType string                  `json:"vulnerability_type,omitempty"`
	URL               string                  `json:"url,omitempty"`
	URLTemplate       *template.Pattern
}

type VexFileFormat struct {
	Compression string `json:"compression,omitempty"`
	Standard    string `json:"standard"`
	Version     string `json:"version,omitempty"`
}
