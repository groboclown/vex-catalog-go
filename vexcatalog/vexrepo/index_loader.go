package vexrepo

import (
	"context"
	"fmt"
	"io"

	"github.com/groboclown/vex-catalog-go/vexcatalog"
	"github.com/groboclown/vex-catalog-go/vexcatalog/cache"
	"github.com/groboclown/vex-catalog-go/vexcatalog/vexloader"
	"github.com/package-url/packageurl-go"
)

type VexRepoIndexLoader[T any] struct {
	loader       vexloader.VexMarshaller[T]
	indexCache   IndexCache
	packageCache cache.PackageCache
}

var _ vexcatalog.VexLoader[int] = (*VexRepoIndexLoader[int])(nil)

type IndexCache interface {
	ReadIndex() (*RepositoryIndex, error)
	ReadFile(path string) (io.ReadCloser, error)
	Flush()
}

func NewVexRepoIndexLoader[T any](
	loader vexloader.VexMarshaller[T],
	indexCache IndexCache,
	packageCache cache.PackageCache,
) *VexRepoIndexLoader[T] {
	return &VexRepoIndexLoader[T]{
		loader:       loader,
		indexCache:   indexCache,
		packageCache: packageCache,
	}
}

func (v *VexRepoIndexLoader[T]) LoadVex(
	ctx context.Context,
	purl *packageurl.PackageURL,
	cveId string,
	vexChan chan<- T,
	errChan chan<- error,
) {
	if v == nil {
		return
	}

	index, err := v.indexCache.ReadIndex()
	if err != nil {
		errChan <- err
		return
	}
	if index == nil || len(index.Packages) == 0 {
		// Nothing in the index.
		return
	}

	// Find the package in the index.
	var purlMatch string
	if purl.Namespace != "" {
		purlMatch = fmt.Sprintf("pkg:%s/%s/%s", purl.Type, purl.Namespace, purl.Name)
	} else {
		purlMatch = fmt.Sprintf("pkg:%s/%s", purl.Type, purl.Name)
	}

	// Should only need to read one package file, however, that's not guaranteed.
	for _, pkg := range index.Packages {
		if pkg.PURL == purlMatch {
			// Found it.
			reader, err := v.indexCache.ReadFile(pkg.Location)
			if err != nil {
				errChan <- err
				continue
			}
			defer reader.Close()
			// Fortunately, the index format and the VEX document format align.
			vexDoc, err := v.loader.LoadVex(reader, pkg.Format, "", "")
			if err != nil {
				errChan <- err
			} else {
				vexChan <- vexDoc
			}
			continue
		}
	}
}

func (v *VexRepoIndexLoader[T]) Close() error {
	// Could flush the cache, but that may not be appropriate.
	// v.indexCache.Flush()
	return nil
}
