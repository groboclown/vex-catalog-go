package vexrepo

import (
	"context"
	"fmt"

	"github.com/groboclown/vex-catalog-go/pkg"
	"github.com/groboclown/vex-catalog-go/pkg/internal/archive"
	"github.com/groboclown/vex-catalog-go/pkg/vexloader"
	"github.com/package-url/packageurl-go"
)

// VexRepositoryArchiveLoader accesses an archive file that hosts a VEX repository.
// It requires a locally downloaded version of the archive file.
type VexRepositoryArchiveFileLoader[T any] struct {
	loader  vexloader.VexMarshaller[T]
	index   *RepositoryIndex
	subdir  string
	archive archive.ArchiveStore
}

var _ pkg.VexLoader[int] = (*VexRepositoryArchiveFileLoader[int])(nil)

func NewVexRepositoryArchiveFileLoader[T any](
	loader vexloader.VexMarshaller[T],
	subdir string,
	archiveFile string,
) *VexRepositoryArchiveFileLoader[T] {
	return newVexRepositoryArchiveFileTypedLoader[T](loader, subdir, archiveFile, archive.GuessArchiveType(archiveFile))
}

func newVexRepositoryArchiveFileTypedLoader[T any](
	loader vexloader.VexMarshaller[T],
	subdir string,
	archiveFile string,
	aType archive.ArchiveType,
) *VexRepositoryArchiveFileLoader[T] {
	a, err := archive.NewArchiveStoreOfType(archiveFile, aType)
	if err != nil {
		return nil
	}
	indexReader, err := a.GetReader(pathTo(subdir, "index.json"))
	if err != nil {
		a.Close()
		return nil
	}
	index, err := RepositoryIndexFromJsonReader(indexReader)
	if err != nil {
		a.Close()
		return nil
	}
	return &VexRepositoryArchiveFileLoader[T]{
		loader:  loader,
		index:   index,
		subdir:  subdir,
		archive: a,
	}
}

func (v *VexRepositoryArchiveFileLoader[T]) LoadVex(
	ctx context.Context,
	purl *packageurl.PackageURL,
	vulnId string,
	vexChan chan<- T,
	errChan chan<- error,
) {
	if v == nil || v.loader == nil || v.index == nil || v.archive == nil {
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
	for _, pkg := range v.index.Packages {
		if pkg.PURL == purlMatch {
			// Found it.
			reader, err := v.archive.GetReader(pathTo(v.subdir, pkg.Location))
			if err != nil {
				errChan <- err
				continue
			}
			defer reader.Close()
			// Fortunately, the index format and the VEX document format align.
			format := pkg.Format
			version := ""
			if format == "" {
				format = "openvex"
				version = "0.2.0"
			}
			vexDoc, err := v.loader.LoadVex(reader, format, version, "")
			if err != nil {
				errChan <- err
			} else {
				vexChan <- vexDoc
			}
			continue
		}
	}
}

func (v *VexRepositoryArchiveFileLoader[T]) Close() error {
	if v == nil || v.archive == nil {
		return nil
	}
	return v.archive.Close()
}

func pathTo(subdir, file string) string {
	if subdir == "" {
		return file
	}
	return fmt.Sprintf("%s/%s", subdir, file)
}
