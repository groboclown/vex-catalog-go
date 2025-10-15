package archive

import (
	"compress/bzip2"
	"compress/gzip"
	"errors"
	"io"
	"os"

	"github.com/ulikunitz/xz"
)

// NewGzTarStore creates a TarStore from a .tar.gz or .tgz archive file.
func NewGzTarStore(archive string) (*TarStore, error) {
	return NewCompressedTarStore(archive, func(r io.Reader) (io.ReadCloser, error) {
		return gzip.NewReader(r)
	})
}

// NewBzip2TarStore creates a TarStore from a .tar.bz2 or .tbz2 archive file.
func NewBzip2TarStore(archive string) (*TarStore, error) {
	return NewCompressedTarStore(archive, func(r io.Reader) (io.ReadCloser, error) {
		return io.NopCloser(bzip2.NewReader(r)), nil
	})
}

// NewXzTarStore creates a TarStore from a .tar.xz or .txz archive file.
func NewXzTarStore(archive string) (*TarStore, error) {
	return NewCompressedTarStore(archive, func(r io.Reader) (io.ReadCloser, error) {
		z, e := xz.NewReader(r)
		if e != nil {
			return nil, e
		}
		return io.NopCloser(z), nil
	})
}

// NewCompressedTarStore creates a TarStore from a compressed tar archive file.
func NewCompressedTarStore(
	archive string,
	decompress func(io.Reader) (io.ReadCloser, error),
) (*TarStore, error) {
	f, err := os.CreateTemp("", "vexrepo-*.tar")
	if err != nil {
		return nil, err
	}
	s, err := os.Open(archive)
	if err != nil {
		f.Close()
		err2 := os.Remove(f.Name())
		return nil, errors.Join(err, err2)
	}
	r, err := decompress(s)
	if err != nil {
		s.Close()
		f.Close()
		err2 := os.Remove(f.Name())
		return nil, errors.Join(err, err2)
	}
	_, err = io.Copy(f, r)
	r.Close()
	s.Close()
	if err != nil {
		f.Close()
		err2 := os.Remove(f.Name())
		return nil, errors.Join(err, err2)
	}
	f.Close()
	return NewTempTarStore(f.Name(), true)
}
