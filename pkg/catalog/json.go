package catalog

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/groboclown/vex-catalog-go/pkg/catalog/template"
	"github.com/groboclown/vex-catalog-go/pkg/internal"
	"github.com/package-url/packageurl-go"
)

func FromJsonBytes(data []byte) (*VexCatalogDoc, error) {
	var doc VexCatalogDoc
	err := json.Unmarshal(data, &doc)
	if err != nil {
		return nil, err
	}
	return &doc, nil
}

func FromJsonReader(r io.Reader) (*VexCatalogDoc, error) {
	var doc VexCatalogDoc
	dec := json.NewDecoder(r)
	err := dec.Decode(&doc)
	if err != nil {
		return nil, err
	}
	return &doc, nil
}

// DownloadJsonVexCatalog downloads the catalog from the given URL using the provided HTTP client.
// It returns the parsed VexRepository, the time it was last modified, and any error that occurred.
// If the time can't be determined, the current time is returned.
func DownloadJsonVexCatalog(url string, client http.Client) (*VexCatalogDoc, time.Time, error) {
	body, updatedAt, err := internal.UrlModGet(url, client)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer body.Close()
	index, err := FromJsonReader(body)
	return index, updatedAt, err
}

func (doc *VexCatalogDoc) ToJsonBytes() ([]byte, error) {
	return json.MarshalIndent(doc, "", " ")
}

func (doc *VexCatalogDoc) ToJsonWriter(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", " ")
	return enc.Encode(doc)
}

func (doc *CatalogMetadata) MarshalJSON() ([]byte, error) {
	type Alias CatalogMetadata
	return json.Marshal(&struct {
		LastUpdated string `json:"last_updated"`
		*Alias
	}{
		LastUpdated: doc.LastUpdated.Format(time.RFC3339),
		Alias:       (*Alias)(doc),
	})
}

func (doc *CatalogMetadata) UnmarshalJSON(data []byte) error {
	type Alias CatalogMetadata
	aux := &struct {
		LastUpdated string `json:"last_updated"`
		*Alias
	}{
		Alias: (*Alias)(doc),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	t, err := time.Parse(time.RFC3339, aux.LastUpdated)
	if err != nil {
		return err
	}
	doc.LastUpdated = t
	return nil
}

func (c *Catalog) MarshalJSON() ([]byte, error) {
	type Alias Catalog
	aux := &struct {
		Purls       []string `json:"purls,omitempty"`
		URLTemplate string   `json:"url_template,omitempty"`
		*Alias
	}{
		Alias: (*Alias)(c),
	}
	if len(c.Purls) > 0 {
		aux.Purls = make([]string, 0, len(c.Purls))
		for _, p := range c.Purls {
			aux.Purls = append(aux.Purls, p.String())
		}
	}
	if c.URLTemplate != nil {
		aux.URLTemplate = c.URLTemplate.Template
	}
	return json.Marshal(aux)
}

func (c *Catalog) UnmarshalJSON(data []byte) error {
	type Alias Catalog
	aux := &struct {
		Purls       []string `json:"purls,omitempty"`
		URLTemplate string   `json:"url_template,omitempty"`
		*Alias
	}{
		Alias: (*Alias)(c),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if len(aux.Purls) > 0 {
		c.Purls = make([]packageurl.PackageURL, 0, len(aux.Purls))
		for _, p := range aux.Purls {
			cp, err := packageurl.FromString(p)
			if err != nil {
				return err
			}
			c.Purls = append(c.Purls, cp)
		}
	}
	if aux.URLTemplate != "" {
		p := template.ParsePattern(aux.URLTemplate)
		c.URLTemplate = &p
	}
	return nil
}
