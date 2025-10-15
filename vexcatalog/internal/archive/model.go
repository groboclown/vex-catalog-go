package archive

import "io"

type ArchiveStore interface {
	io.Closer
	GetReader(location string) (io.ReadCloser, error)
}
