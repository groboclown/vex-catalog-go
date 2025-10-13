package catalog

import (
	"net/http"
	"strings"

	"github.com/groboclown/vex-catalog-go/pkg"
	"github.com/package-url/packageurl-go"
)

func (c *Catalog) LoadVex(
	client http.Client,
	purl *packageurl.PackageURL,
	vulnId string,
) (*pkg.VexDocument, error) {
	if !c.MatchesPurl(purl) || !c.MatchesVulnerability(vulnId) {
		return nil, nil
	}
	url := c.URL
	if c.URLTemplate != nil {
		url = c.URLTemplate.Evaluate(purl, vulnId)
	}
	if url != "" {
		resp, err := client.Get(c.URL)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, nil
		}
		return LoadVexFromReader(resp.Body, c.FileFormat.Standard, c.FileFormat.Version, c.FileFormat.Compression)
	}
	return nil, nil
}

// MatchesPurl checks if the given purl matches any of the catalog's purls.
func (c *Catalog) MatchesPurl(purl *packageurl.PackageURL) bool {
	if purl == nil || len(c.Purls) == 0 {
		return true
	}
	for _, cp := range c.Purls {
		if cp.Type == purl.Type && cp.Namespace == purl.Namespace && cp.Name == purl.Name {
			return true
		}
	}
	return false
}

func (c *Catalog) MatchesVulnerability(vulnId string) bool {
	if c.VulnerabilityType == "" || vulnId == "" {
		return true
	}
	return strings.HasPrefix(c.VulnerabilityType, strings.ToLower(vulnId))
}
