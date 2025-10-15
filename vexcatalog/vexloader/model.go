package vexloader

import (
	"io"
)

// VexMarshaller reads VEX documents from an io.Reader, given the standard, version, and compression.
type VexMarshaller[T any] interface {
	// LoadVex reads from the given reader, expecting the given standard, version, and compression.
	LoadVex(r io.Reader, standard, version, compression string) (T, error)
}
