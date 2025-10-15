package archive

import "strings"

type ArchiveType int

const (
	ArchiveTypeNone ArchiveType = iota
	ArchiveTypeZip
	ArchiveTypeTar
	ArchiveTypeTarGz
	ArchiveTypeTarBz2
	ArchiveTypeTarXz

	// Groboclown: The spec supports file types with these formats.
	// I'm not sure how to handle these in the context
	// of a VEX repository, since they aren't archives that can
	// contain multiple files.  The spec doesn't say.
	ArchiveTypeGz
	ArchiveTypeBz2
	ArchiveTypeXz
)

func GuessArchiveType(url string) ArchiveType {
	lower := strings.ToLower(url)
	if strings.HasSuffix(lower, "/") {
		// A path ending in a slash is not an archive.
		return ArchiveTypeNone
	}
	if strings.HasSuffix(lower, ".zip") {
		return ArchiveTypeZip
	}
	if strings.HasSuffix(lower, ".tar") {
		return ArchiveTypeTar
	}
	if strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz") {
		return ArchiveTypeTarGz
	}
	if strings.HasSuffix(lower, ".tar.bz2") || strings.HasSuffix(lower, ".tbz2") {
		return ArchiveTypeTarBz2
	}
	if strings.HasSuffix(lower, ".tar.xz") || strings.HasSuffix(lower, ".txz") {
		return ArchiveTypeTarXz
	}
	if strings.HasSuffix(lower, ".gz") {
		return ArchiveTypeGz
	}
	if strings.HasSuffix(lower, ".bz2") {
		return ArchiveTypeBz2
	}
	if strings.HasSuffix(lower, ".xz") {
		return ArchiveTypeXz
	}
	return ArchiveTypeNone
}
