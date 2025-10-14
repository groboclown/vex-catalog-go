package archive

import (
	"archive/zip"
	"io"
	"strings"
)

type ZipStore struct {
	archive *zip.ReadCloser
}

var _ ArchiveStore = (*ZipStore)(nil)

func NewZipStore(archive string) (*ZipStore, error) {
	archiveReader, err := zip.OpenReader(archive)
	if err != nil {
		return nil, err
	}
	return &ZipStore{
		archive: archiveReader,
	}, nil
}

func (z *ZipStore) Close() error {
	return z.archive.Close()
}

func (z *ZipStore) GetReader(location string) (io.ReadCloser, error) {
	// The location is relative to the root of the archive.
	trimmed := strings.TrimPrefix(location, "/")
	for _, f := range z.archive.File {
		if f.Name == trimmed {
			return f.Open()
		}
	}
	return nil, nil
}
