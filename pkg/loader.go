package pkg

import (
	"context"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/openvex/go-vex/pkg/csaf"
	"github.com/openvex/go-vex/pkg/vex"
	"github.com/package-url/packageurl-go"
)

type VexDocument struct {
	CycloneDX *cyclonedx.BOM
	Csaf      *csaf.CSAF
	OpenVex   *vex.VEX
}

// VexLoader defines the interface for loading VEX documents associated with a given package URL.
// The loader is designed to run in parallel.
type VexLoader interface {
	// LoadVex retrieves VEX documents related to the specified package URL.
	// The VEX may have its own method of discovering the VEX corresponding to the Purl, which
	// may include loading multiple VEX documents.
	// The operation should exit when all loading completes.
	// Because of the way the VEX statements need access, it may require asking for a package's
	// CVE attestations.  In some cases, the loader may not have that level of access before
	// submitting the request, and so may need some post processing.
	LoadVex(
		ctx context.Context,
		purl *packageurl.PackageURL,
		cveId string,
		vexChan chan<- *VexDocument,
		errChan chan<- error,
	)
}
