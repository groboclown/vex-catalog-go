package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/groboclown/vex-catalog-go/vexcatalog"
	"github.com/groboclown/vex-catalog-go/vexcatalog/cache"
	"github.com/groboclown/vex-catalog-go/vexcatalog/catalog"
	"github.com/groboclown/vex-catalog-go/vexcatalog/catalog/template"
	"github.com/groboclown/vex-catalog-go/vexcatalog/vexloader"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"github.com/package-url/packageurl-go"
)

// An example of using the VEX catalog library to load VEX documents from Canonical's Ubuntu repository.
func main() {
	// CVE-2018-0488: ARM mbed TLS before 1.3.22, before 2.1.10, and before 2.7.0,
	// when the truncated HMAC extension and CBC are used, allows remote attackers to
	// execute arbitrary code or cause a denial of service (heap corruption) via a crafted
	// application packet within a TLS or DTLS session.
	cve := "CVE-2018-0488"
	purl, err := packageurl.FromString("pkg:deb/ubuntu/libmbedx509-0-dbgsym")
	if err != nil {
		panic(err)
	}

	client := http.DefaultClient

	// Because Canonical's repository does not use the catalog schema,
	// this uses the template catalog loader directly.
	secNoticePattern := template.ParsePattern(
		"https://raw.githubusercontent.com/canonical/ubuntu-security-notices/refs/heads/main/osv/cve/{VULN:5:8}/UBUNTU-{VULN}.json",
	)
	ubuntuCatalog := &catalog.Catalog{
		Kind:        "template",
		URLTemplate: &secNoticePattern,
		FileFormat: catalog.VexFileFormat{
			Standard: "osv",
			Version:  "",
		},
		VulnerabilityType: "cve",
	}
	loader := catalog.NewVexTemplateCatalogLoader(
		ubuntuCatalog,
		openVexMarshaller{},
		cache.NewMemoryCache(cache.NotPooled),
		time.Duration(24)*time.Hour,
		*client,
	)
	defer loader.Close()

	docs, errs := vexcatalog.CollectVexDocuments(
		context.Background(),
		&purl, // Look for this package.
		cve,   // Filter on a specific vulnerability ID.

		// Use the constructed loader from above.
		// The loader uses generics based on the type of the
		// everythingLoader, which returns *vexloader.VexDocument
		// objects.
		[]vexcatalog.VexLoader[*osvschema.Vulnerability]{loader},
	)
	if len(errs) > 0 {
		panic(errors.Join(errs...))
	}
	fmt.Println("Found", len(docs), "documents")
	for _, doc := range docs {
		if doc == nil {
			continue
		}
		fmt.Println(
			"Found OpenVex document:",
			doc.ID,
			"with",
			len(doc.Affected),
			"affected entries",
		)
	}
}

type openVexMarshaller struct{}

var _ vexloader.VexMarshaller[*osvschema.Vulnerability] = openVexMarshaller{}

func (e openVexMarshaller) LoadVex(r io.Reader, standard, version, compression string) (*osvschema.Vulnerability, error) {
	return vexloader.LoadOsvFromReader(r, version)
}

// For testing
func RunExample() {
	main()
}
