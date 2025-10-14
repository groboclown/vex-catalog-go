package archive

import (
	"os"
)

// NewArchiveStore creates an ArchiveStore based on the file extension of the archive file.
// It returns nil if the archive type is not recognized.
func NewArchiveStore(archive string) (ArchiveStore, error) {
	return NewArchiveStoreOfType(archive, GuessArchiveType(archive))
}

func NewArchiveStoreOfType(archive string, t ArchiveType) (ArchiveStore, error) {
	switch t {
	case ArchiveTypeZip:
		return NewZipStore(archive)
	case ArchiveTypeTar:
		return NewTarStore(archive)
	case ArchiveTypeTarGz:
		return NewGzTarStore(archive)
	case ArchiveTypeTarBz2:
		return NewBzip2TarStore(archive)
	case ArchiveTypeTarXz:
		return NewXzTarStore(archive)
	default:
		return nil, os.ErrNotExist
	}
}
