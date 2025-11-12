package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/groboclown/vex-catalog-go/vexcatalog"
	"github.com/groboclown/vex-catalog-go/vexcatalog/cache"
	"github.com/groboclown/vex-catalog-go/vexcatalog/vexloader"
	"github.com/groboclown/vex-catalog-go/vexcatalog/vexrepo"
	"github.com/package-url/packageurl-go"
)

// An example of using the VEX catalog library to load VEX documents from the vexhub repository.
func main() {
	purl, err := packageurl.FromString("pkg:golang/github.com/longhorn/longhorn-engine@v1.8.1")
	if err != nil {
		panic(err)
	}

	client := http.DefaultClient
	repoDoc, _, err := vexrepo.DownloadJsonVexRepository(
		"https://raw.githubusercontent.com/aquasecurity/vexhub/refs/heads/main/vex-repository.json",
		*client,
	)
	if err != nil {
		panic(err)
	}

	// Create a VEX repository loader for the VEX repository document.
	// The loader reads from the repository, using the cache where
	// possible, and the HTTP client for downloading documents.
	// It extracts the corresponding VEX documents using the
	// everythingMarshaller, which transforms the documents pulled
	// into *vexloader.VexDocument objects.
	// The cache here uses the no-op cache.
	// The HTTP client allows for replacing with a custom client,
	// such as for testing or for adding additional functionality
	// where needed.
	loader, ok := vexrepo.NewVexRepositoryLoader(
		repoDoc,
		everythingMarshaller{},
		cache.None,
		*client,
	)
	if !ok {
		panic("no supported locations in VEX repository")
	}
	defer loader.Close()

	docs, errs := vexcatalog.CollectVexDocuments(
		context.Background(),
		&purl, // Filter documents by this package URL
		"",    // Do not filter by any vulnerability ID

		// Use the constructed loader from above.
		// The loader uses generics based on the type of the
		// everythingLoader, which returns *vexloader.VexDocument
		// objects.
		[]vexcatalog.VexLoader[*vexloader.VexDocument]{loader},
	)
	if len(errs) > 0 {
		panic(errors.Join(errs...))
	}
	fmt.Println("Found", len(docs), "documents")
	for _, doc := range docs {
		if doc == nil {
			continue
		}
		if doc.Csaf != nil {
			fmt.Println("Found CSAF document: ", doc.Csaf.Document.Title)
		}
		if doc.CycloneDX != nil {
			fmt.Println("Found CycloneDX document: ", doc.CycloneDX.Metadata.Component.Name)
		}
		if doc.OpenVex != nil {
			fmt.Println("Found OpenVex document: ", doc.OpenVex.Metadata.ID)
		}
		if doc.Osv != nil {
			fmt.Println("Found OSV document: ", doc.Osv.ID)
		}
	}
}

type everythingMarshaller struct{}

var _ vexloader.VexMarshaller[*vexloader.VexDocument] = everythingMarshaller{}

func (e everythingMarshaller) LoadVex(r io.Reader, standard, version, compression string) (*vexloader.VexDocument, error) {
	return vexloader.LoadVexFromReader(r, standard, version, compression)
}

// For testing
func RunExample() {
	main()
}
