package catalog

import (
	"compress/bzip2"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/groboclown/vex-catalog-go/pkg"
	"github.com/klauspost/compress/zstd"
	"github.com/mikelolasagasti/xz"
	"github.com/openvex/go-vex/pkg/csaf"
	"github.com/openvex/go-vex/pkg/vex"
)

func LoadVexFromReader(r io.Reader, standard, version, compression string) (*pkg.VexDocument, error) {
	r, err := decompressStream(r, compression)
	if err != nil {
		return nil, err
	}
	switch standard {
	case "cyclonedx":
		return LoadCycloneDXFromReader(r, version)
	case "csaf":
		return LoadCsafFromReader(r, version)
	case "openvex":
		return LoadOpenVexFromReader(r, version)
	default:
		return nil, nil
	}
}

func decompressStream(r io.Reader, compression string) (io.Reader, error) {
	switch compression {
	case "", "none":
		return r, nil
	case "gzip":
		return gzip.NewReader(r)
	case "zstd":
		return zstd.NewReader(r)
	case "xz":
		return xz.NewReader(r, 0)
	case "bzip2":
		return bzip2.NewReader(r), nil
	default:
		return nil, nil
	}
}

func LoadCycloneDXFromReader(r io.Reader, version string) (*pkg.VexDocument, error) {
	var cdxBOM cyclonedx.BOM
	err := cyclonedx.NewBOMDecoder(r, cyclonedx.BOMFileFormatJSON).Decode(&cdxBOM)
	if err != nil {
		return nil, err
	}
	return &pkg.VexDocument{CycloneDX: &cdxBOM}, nil
}

func LoadCsafFromReader(r io.Reader, version string) (*pkg.VexDocument, error) {
	csafDoc := &csaf.CSAF{}
	err := json.NewDecoder(r).Decode(csafDoc)
	if err != nil {
		return nil, fmt.Errorf("csaf: failed to decode document: %w", err)
	}
	return &pkg.VexDocument{Csaf: csafDoc}, nil
}

func LoadOpenVexFromReader(r io.Reader, version string) (*pkg.VexDocument, error) {
	// This is for OpenVEX 0.2.0.
	// Note that the package also supports openvex v0.0.1, but it's harder to get to.
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	doc, err := vex.Parse(data)
	if err != nil {
		return nil, err
	}
	return &pkg.VexDocument{OpenVex: doc}, nil
}
