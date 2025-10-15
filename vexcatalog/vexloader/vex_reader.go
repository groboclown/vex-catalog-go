package vexloader

import (
	"compress/bzip2"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/klauspost/compress/zstd"
	"github.com/mikelolasagasti/xz"
	"github.com/openvex/go-vex/pkg/csaf"
	"github.com/openvex/go-vex/pkg/vex"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// VexDocument is a generic container for different types of VEX documents.
// Here as a helper for tooling that wants simple access to any of the supported types.
// However, as the catalog interface allows for generic types, implementations are free
// to use their own method for loading VEX documents.
type VexDocument struct {
	CycloneDX *cyclonedx.BOM
	Csaf      *csaf.CSAF
	OpenVex   *vex.VEX
	Osv       *osvschema.Vulnerability
}

// LoadVexFromReader loads a VEX document from the given reader, based on the specified standard, version, and compression.
// This is a helper on top of implementations for the VexLoader interface, if they support
// generic document types.
func LoadVexFromReader(r io.Reader, standard, version, compression string) (*VexDocument, error) {
	r, err := DecompressStream(r, compression)
	if err != nil {
		return nil, err
	}
	switch standard {
	case "cyclonedx":
		r, e := LoadCycloneDXFromReader(r, version)
		if e != nil {
			return nil, e
		}
		return &VexDocument{CycloneDX: r}, nil
	case "csaf":
		r, e := LoadCsafFromReader(r, version)
		if e != nil {
			return nil, e
		}
		return &VexDocument{Csaf: r}, nil
	case "openvex":
		r, e := LoadOpenVexFromReader(r, version)
		if e != nil {
			return nil, e
		}
		return &VexDocument{OpenVex: r}, nil
	case "osv":
		r, e := LoadOsvFromReader(r, version)
		if e != nil {
			return nil, e
		}
		return &VexDocument{Osv: r}, nil
	default:
		return nil, nil
	}
}

// DecompressStream wraps the given reader with a decompression reader, if the compression
// is known.  If the compression is empty or "none", the original reader is returned.
// If the compression is unknown, (nil, nil) is returned.
func DecompressStream(r io.Reader, compression string) (io.Reader, error) {
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

func LoadCycloneDXFromReader(r io.Reader, version string) (*cyclonedx.BOM, error) {
	var cdxBOM cyclonedx.BOM
	err := cyclonedx.NewBOMDecoder(r, cyclonedx.BOMFileFormatJSON).Decode(&cdxBOM)
	if err != nil {
		return nil, err
	}
	return &cdxBOM, nil
}

func LoadCsafFromReader(r io.Reader, version string) (*csaf.CSAF, error) {
	csafDoc := &csaf.CSAF{}
	err := json.NewDecoder(r).Decode(csafDoc)
	if err != nil {
		return nil, fmt.Errorf("csaf: failed to decode document: %w", err)
	}
	return csafDoc, nil
}

func LoadOpenVexFromReader(r io.Reader, version string) (*vex.VEX, error) {
	switch version {
	case "0.2.0":
		data, err := io.ReadAll(r)
		if err != nil {
			return nil, err
		}
		doc, err := vex.Parse(data)
		if err != nil {
			return nil, err
		}
		return doc, nil
	case "0.2.0-canonical":
		// It uses a different time stamp in some places.
		data, err := io.ReadAll(r)
		if err != nil {
			return nil, err
		}
		data = convertF1ToRFC3339(data)
		doc, err := vex.Parse(data)
		if err != nil {
			return nil, err
		}
		return doc, nil
	default:
		// Version 0.0.1 is deprecated, but still supported.
		// However, loading it through the openvex package takes a hack,
		// as it can only call getLegacyVersionParser through the file-based Load function.
		// This will also load CSAF documents.
		tmpFile, err := os.CreateTemp("", "openvex-*.json")
		if err != nil {
			return nil, fmt.Errorf("openvex: failed to create temp file: %w", err)
		}
		defer os.Remove(tmpFile.Name())
		_, err = io.Copy(tmpFile, r)
		if err != nil {
			tmpFile.Close()
			return nil, fmt.Errorf("openvex: failed to copy to temp file: %w", err)
		}
		err = tmpFile.Close()
		if err != nil {
			return nil, fmt.Errorf("openvex: failed to close temp file: %w", err)
		}
		doc, err := vex.Open(tmpFile.Name())
		if err != nil {
			return nil, fmt.Errorf("openvex: failed to load document: %w", err)
		}
		return doc, nil
	}
}

func LoadOsvFromReader(r io.Reader, version string) (*osvschema.Vulnerability, error) {
	osvDoc := &osvschema.Vulnerability{}
	err := json.NewDecoder(r).Decode(osvDoc)
	if err != nil {
		return nil, fmt.Errorf("osv: failed to decode document: %w", err)
	}
	return osvDoc, nil
}

var timeFormat1 = regexp.MustCompile(`"timestamp":\s*"(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}) UTC"`)
var timeFormat1Replace = []byte(`"timestamp": "${1}T${2}Z"`)

func convertF1ToRFC3339(b []byte) []byte {
	// Convert the format "2006-01-02 15:04:05 MST" to RFC3339.
	// This currently only works if the timezone is "UTC".
	// As a hack, this could perform the conversion and incorrectly ignore the timezone.

	return timeFormat1.ReplaceAll(b, timeFormat1Replace)
}
