package catalog

import (
	"compress/bzip2"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/groboclown/vex-catalog-go/pkg"
	"github.com/klauspost/compress/zstd"
	"github.com/mikelolasagasti/xz"
	"github.com/openvex/go-vex/pkg/csaf"
	"github.com/openvex/go-vex/pkg/vex"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
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
	case "osv":
		return LoadOsvFromReader(r, version)
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
		return &pkg.VexDocument{OpenVex: doc}, nil
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
		return &pkg.VexDocument{OpenVex: doc}, nil
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
		return &pkg.VexDocument{OpenVex: doc}, nil
	}
}

func LoadOsvFromReader(r io.Reader, version string) (*pkg.VexDocument, error) {
	osvDoc := &osvschema.Vulnerability{}
	err := json.NewDecoder(r).Decode(osvDoc)
	if err != nil {
		return nil, fmt.Errorf("osv: failed to decode document: %w", err)
	}
	return &pkg.VexDocument{Osv: osvDoc}, nil
}

var timeFormat1 = regexp.MustCompile(`"timestamp":\s*"(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}) UTC"`)
var timeFormat1Replace = []byte(`"timestamp": "${1}T${2}Z"`)

func convertF1ToRFC3339(b []byte) []byte {
	// Convert the format "2006-01-02 15:04:05 MST" to RFC3339.
	// This currently only works if the timezone is "UTC".
	// As a hack, this could perform the conversion and incorrectly ignore the timezone.

	return timeFormat1.ReplaceAll(b, timeFormat1Replace)
}
