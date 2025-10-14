package archive

import (
	"archive/tar"
	"errors"
	"io"
	"os"
)

type TarStore struct {
	archive string
	isTmp   bool
	entries map[string]int64
}

var _ ArchiveStore = (*TarStore)(nil)

func NewTarStore(archive string) (*TarStore, error) {
	return NewTempTarStore(archive, false)
}

// NewTempTarStore creates a new TarStore that will delete the archive file on Close if isTmp is true.
// If the creation fails, the archive file is deleted.
func NewTempTarStore(archive string, isTmp bool) (*TarStore, error) {
	f, err := os.Open(archive)
	if err != nil {
		err2 := os.Remove(archive)
		return nil, errors.Join(err, err2)
	}
	t := tar.NewReader(f)
	entries := make(map[string]int64)
	var index int64
	for {
		hdr, err := t.Next()
		if err != nil {
			if err != io.EOF {
				f.Close()
				err2 := os.Remove(archive)
				return nil, errors.Join(err, err2)
			}
			break
		}
		entries[hdr.Name] = index
		index++
	}
	f.Close()
	return &TarStore{
		archive: archive,
		entries: entries,
	}, nil
}

func (t *TarStore) Close() error {
	if t.isTmp {
		return os.Remove(t.archive)
	}
	return nil
}

func (t *TarStore) GetReader(location string) (io.ReadCloser, error) {
	index, ok := t.entries[location]
	if !ok {
		return nil, nil
	}
	f, err := os.Open(t.archive)
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(f)
	var current int64
	for {
		_, err := tr.Next()
		if err != nil {
			// EOF or other error
			f.Close()
			return nil, err
		}
		if current == index {
			return struct {
				io.Reader
				io.Closer
			}{
				Reader: tr,
				Closer: f,
			}, nil
		}
		current++
	}
}
