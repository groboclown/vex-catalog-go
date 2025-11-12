package catalog_test

import (
	"testing"

	"github.com/groboclown/vex-catalog-go/vexcatalog/catalog"
	"github.com/package-url/packageurl-go"
)

func Test_MatchesVulnerability(t *testing.T) {
	t.Parallel()

	data := []struct {
		vulnType    string
		vulnId      string
		expectMatch bool
	}{
		{"cve", "CVE-2023-12345", true},
		{"cve", "cve-2023-12345", true},
		{"cve", "GHSA-xxxx-yyyy-zzzz", false},
		{"ghsa", "GHSA-xxxx-yyyy-zzzz", true},
		{"ghsa", "CVE-2023-12345", false},
		{"cve", "", true}, // empty vulnId matches; indicates no filtering
	}

	for _, d := range data {
		t.Run(d.vulnType+"_"+d.vulnId, func(t *testing.T) {
			c := &catalog.Catalog{
				VulnerabilityType: d.vulnType,
			}
			match := c.MatchesVulnerability(d.vulnId)
			if match != d.expectMatch {
				t.Fatalf("expected match=%v, got %v", d.expectMatch, match)
			}
		})
	}
}

func Test_MatchesPurl(t *testing.T) {
	t.Parallel()

	data := []struct {
		catalogPurls []packageurl.PackageURL
		testPurl     *packageurl.PackageURL
		expectMatch  bool
	}{
		{
			catalogPurls: []packageurl.PackageURL{
				{Type: "npm", Namespace: "@mui", Name: "x-license"},
			},
			testPurl:    &packageurl.PackageURL{Type: "npm", Namespace: "@mui", Name: "x-license"},
			expectMatch: true,
		},
		{
			catalogPurls: []packageurl.PackageURL{
				{Type: "npm", Namespace: "@mui", Name: "x-license"},
			},
			testPurl:    &packageurl.PackageURL{Type: "npm", Namespace: "@mui", Name: "other-package"},
			expectMatch: false,
		},
		{
			catalogPurls: []packageurl.PackageURL{},
			testPurl:     &packageurl.PackageURL{Type: "npm", Namespace: "@mui", Name: "x-license"},
			expectMatch:  true, // empty catalog purls means match all
		},
		{
			catalogPurls: []packageurl.PackageURL{
				{Type: "generic", Namespace: "", Name: "test1"},
				{Type: "generic", Namespace: "", Name: "test2"},
			},
			testPurl:    &packageurl.PackageURL{Type: "generic", Namespace: "", Name: "test2"},
			expectMatch: true,
		},
		{
			catalogPurls: []packageurl.PackageURL{
				{Type: "generic", Namespace: "", Name: "test"},
			},
			testPurl:    &packageurl.PackageURL{Type: "generic", Namespace: "tuna", Name: "test"},
			expectMatch: false,
		},
		{
			catalogPurls: []packageurl.PackageURL{
				{Type: "generic", Namespace: "", Name: "test"},
			},
			testPurl:    nil,
			expectMatch: true, // nil test purl means match all
		},
	}

	for _, d := range data {
		t.Run("", func(t *testing.T) {
			c := &catalog.Catalog{
				Purls: d.catalogPurls,
			}
			match := c.MatchesPurl(d.testPurl)
			if match != d.expectMatch {
				t.Fatalf("expected match=%v, got %v", d.expectMatch, match)
			}
		})
	}
}
