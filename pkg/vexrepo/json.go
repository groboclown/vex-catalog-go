package vexrepo

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/groboclown/vex-catalog-go/pkg/internal"
)

func VexRepositoryFromJsonBytes(data []byte) (*VexRepository, error) {
	var doc VexRepository
	err := json.Unmarshal(data, &doc)
	if err != nil {
		return nil, err
	}
	return &doc, nil
}

func VexRepositoryFromJsonReader(r io.Reader) (*VexRepository, error) {
	var doc VexRepository
	dec := json.NewDecoder(r)
	err := dec.Decode(&doc)
	if err != nil {
		return nil, err
	}
	return &doc, nil
}

// DownloadJsonRepositoryIndex downloads the repository manifest from the given URL using the provided HTTP client.
// It returns the parsed VexRepository, the time it was last modified, and any error that occurred.
// If the time can't be determined, the current time is returned.
func DownloadJsonVexRepository(url string, client http.Client) (*VexRepository, time.Time, error) {
	body, updatedAt, err := internal.UrlModGet(url, client)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer body.Close()
	index, err := VexRepositoryFromJsonReader(body)
	return index, updatedAt, err
}

func (doc *VexRepository) ToJsonBytes() ([]byte, error) {
	return json.MarshalIndent(doc, "", " ")
}

func (doc *VexRepository) ToJsonWriter(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", " ")
	return enc.Encode(doc)
}

func RepositoryIndexFromJsonBytes(data []byte) (*RepositoryIndex, error) {
	var doc RepositoryIndex
	err := json.Unmarshal(data, &doc)
	if err != nil {
		return nil, err
	}
	return &doc, nil
}

func RepositoryIndexFromJsonReader(r io.Reader) (*RepositoryIndex, error) {
	var doc RepositoryIndex
	dec := json.NewDecoder(r)
	err := dec.Decode(&doc)
	if err != nil {
		return nil, err
	}
	return &doc, nil
}

// DownloadJsonRepositoryIndex downloads the repository index from the given URL using the provided HTTP client.
// It returns the parsed RepositoryIndex, the time it was last modified, and any error that occurred.
// If the time can't be determined, the current time is returned.
func DownloadJsonRepositoryIndex(url string, client http.Client) (*RepositoryIndex, time.Time, error) {
	body, updatedAt, err := internal.UrlModGet(url, client)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer body.Close()
	index, err := RepositoryIndexFromJsonReader(body)
	if err != nil {
		return nil, time.Time{}, err
	}
	if t, err := index.ParseUpdatedAt(); err == nil {
		updatedAt = t
	}
	return index, updatedAt, nil
}

func (doc *RepositoryIndex) ToJsonBytes() ([]byte, error) {
	return json.MarshalIndent(doc, "", " ")
}

func (doc *RepositoryIndex) ToJsonWriter(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", " ")
	return enc.Encode(doc)
}
