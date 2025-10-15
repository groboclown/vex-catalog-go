package vexrepo

import (
	"net/http"
	"strings"
	"time"

	"github.com/groboclown/vex-catalog-go/vexcatalog"
	"github.com/groboclown/vex-catalog-go/vexcatalog/cache"
	"github.com/groboclown/vex-catalog-go/vexcatalog/internal/archive"
	"github.com/groboclown/vex-catalog-go/vexcatalog/vexloader"
)

// NewVexRepositoryLoader creates a VEX repository loader for the given VEX repository.
// It returns false if the repository is nil, has no versions, or has no supported locations.
//
// At the moment, only URL-based (non-archive) loaders are supported.
func NewVexRepositoryLoader[T any](
	repo *VexRepository,
	loader vexloader.VexMarshaller[T],
	cache cache.PackageCacheFactory,
	client http.Client,
) (vexcatalog.VexLoader[T], bool) {
	if repo == nil || len(repo.Versions) == 0 {
		return nil, false
	}
	// This only supports up to version 1.0 of the spec.
	version := repo.ClosestVersion("1.0")
	if version == nil || len(version.Locations) == 0 {
		return nil, false
	}

	// At the moment, only the non-archive URL loader is implemented.
	for _, loc := range version.Locations {
		url := loc.URL
		subdir := ""

		// The format requires a "//" to indicate a subdirectory in an archive.
		// The prefix should include a "scheme://" as well.
		parts := strings.Split(loc.URL, "//")
		if len(parts) == 1 || len(parts) > 3 {
			// == 1: Not a HTTPS url.  Maybe a file location?  Skip it.
			// > 3: Too many parts.  Invalid.
			continue
		}
		if len(parts) == 3 {
			// This is a URL + subdirectory.
			url = parts[0] + "//" + parts[1]
			subdir = parts[2]
		}

		aType := archive.GuessArchiveType(url)
		if aType == archive.ArchiveTypeNone {
			return NewVexRepositoryUrlLoader(loader, version, &loc, cache, client), true
		} else {
			return newVexRepositoryArchiveUrlLoaderTyped(loader, client, url, 24*time.Hour, subdir, aType), true
		}
	}
	return nil, false
}
