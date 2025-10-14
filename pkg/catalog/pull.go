package catalog

import (
	"io"
	"strings"

	"github.com/package-url/packageurl-go"
)

type VexReference struct {
	Reader io.ReadCloser
	Format VexFileFormat
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
