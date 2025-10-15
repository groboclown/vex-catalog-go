package vexrepo

import (
	"context"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/groboclown/vex-catalog-go/vexcatalog"
	"github.com/groboclown/vex-catalog-go/vexcatalog/internal"
	"github.com/groboclown/vex-catalog-go/vexcatalog/internal/archive"
	"github.com/groboclown/vex-catalog-go/vexcatalog/vexloader"
	"github.com/package-url/packageurl-go"
)

// VexRepositoryArchiveLoader accesses an archive file that hosts a VEX repository.
// It requires a locally downloaded version of the archive file.
type VexRepositoryArchiveUrlLoader[T any] struct {
	loader         vexloader.VexMarshaller[T]
	url            string
	client         http.Client
	lastUpdate     time.Time
	updateInterval time.Duration
	subdir         string
	aType          archive.ArchiveType
	archive        *VexRepositoryArchiveFileLoader[T]
	mutex          sync.Mutex
}

var _ vexcatalog.VexLoader[int] = (*VexRepositoryArchiveUrlLoader[int])(nil)

func NewVexRepositoryArchiveUrlLoader[T any](
	loader vexloader.VexMarshaller[T],
	client http.Client,
	url string,
	updateInterval time.Duration,
	subdir string,
) *VexRepositoryArchiveUrlLoader[T] {
	return &VexRepositoryArchiveUrlLoader[T]{
		loader:         loader,
		url:            url,
		lastUpdate:     time.Time{},
		updateInterval: updateInterval,
		subdir:         subdir,
		aType:          archive.GuessArchiveType(url),
		archive:        nil,
	}
}

func newVexRepositoryArchiveUrlLoaderTyped[T any](
	loader vexloader.VexMarshaller[T],
	client http.Client,
	url string,
	updateInterval time.Duration,
	subdir string,
	aType archive.ArchiveType,
) *VexRepositoryArchiveUrlLoader[T] {
	return &VexRepositoryArchiveUrlLoader[T]{
		loader:         loader,
		url:            url,
		lastUpdate:     time.Time{},
		updateInterval: updateInterval,
		subdir:         subdir,
		aType:          aType,
		archive:        nil,
	}
}

func (v *VexRepositoryArchiveUrlLoader[T]) LoadVex(
	ctx context.Context,
	purl *packageurl.PackageURL,
	vulnId string,
	vexChan chan<- T,
	errChan chan<- error,
) {
	if v == nil {
		return
	}
	archive, err := v.getArchive()
	if err != nil {
		errChan <- err
		return
	}
	if archive != nil {
		archive.LoadVex(ctx, purl, vulnId, vexChan, errChan)
	}
}

func (v *VexRepositoryArchiveUrlLoader[T]) Close() error {
	if v == nil {
		return nil
	}
	v.mutex.Lock()
	defer v.mutex.Unlock()
	if v.archive != nil {
		err := v.archive.Close()
		v.archive = nil
		return err
	}
	return nil
}

func (v *VexRepositoryArchiveUrlLoader[T]) getArchive() (*VexRepositoryArchiveFileLoader[T], error) {
	v.mutex.Lock()
	defer v.mutex.Unlock()

	if v.archive == nil || time.Since(v.lastUpdate) > v.updateInterval {
		// Need to (re)load the archive file.
		r, updated, err := internal.UrlModGet(v.url, v.client)
		if err != nil {
			return nil, err
		}
		archiveFile, err := os.CreateTemp("", "vexrepo-archive-*")
		if err != nil {
			return nil, err
		}
		_, err = io.Copy(archiveFile, r)
		if err != nil {
			archiveFile.Close()
			os.Remove(archiveFile.Name())
			return nil, err
		}
		v.archive = newVexRepositoryArchiveFileTypedLoader(v.loader, v.subdir, archiveFile.Name(), v.aType)
		v.lastUpdate = updated
	}
	return v.archive, nil
}
