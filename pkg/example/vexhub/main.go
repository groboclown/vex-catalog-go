package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/groboclown/vex-catalog-go/pkg"
	"github.com/groboclown/vex-catalog-go/pkg/cache"
	"github.com/groboclown/vex-catalog-go/pkg/vexloader"
	"github.com/groboclown/vex-catalog-go/pkg/vexrepo"
	"github.com/package-url/packageurl-go"
)

// An example of using the VEX catalog library to load VEX documents from the vexhub repository.
func main() {
	purl, err := packageurl.FromString("pkg:golang/github.com/longhorn/longhorn-engine@v1.8.1")
	if err != nil {
		panic(err)
	}

	client := http.DefaultClient
	cache := &cache.NoneCacheFactory{}
	repoDoc, _, err := vexrepo.DownloadJsonVexRepository(
		"https://raw.githubusercontent.com/aquasecurity/vexhub/refs/heads/main/vex-repository.json",
		*client,
	)
	if err != nil {
		panic(err)
	}

	loader, ok := vexrepo.NewVexRepositoryLoader(
		repoDoc,
		everythingMarshaller{},
		cache,
		*client,
	)
	if !ok {
		panic("no supported locations in VEX repository")
	}
	defer loader.Close()

	docs, errs := pkg.CollectVexDocuments(
		context.Background(),
		&purl,
		"",
		[]pkg.VexLoader[*vexloader.VexDocument]{loader},
	)
	if len(errs) > 0 {
		panic(errors.Join(errs...))
	}
	fmt.Println("Found ", len(docs), "documents")
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
