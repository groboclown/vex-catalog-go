package vexrepo

// RepositoryIndex implements the JSON storage of the repository index file.
// See https://github.com/aquasecurity/vex-repo-spec/blob/main/index.schema.json
type RepositoryIndex struct {
	UpdatedAt string               `json:"updated_at"`
	Packages  []RepositoryIndexPkg `json:"packages"`
}

// RepositoryIndexPkg describes a package entry in the repository index file.
//
// PURL is the package URL (PURL) of the package.
//
// Location is the URL where the VEX documents for this package can be found,
// relative to the repository root URL.
//
// Format is an optional field that describes the format of the VEX documents.
// If not provided, the default is "openvex".  It must be one of
// "openvex", "csaf".
type RepositoryIndexPkg struct {
	PURL     string `json:"id"`
	Location string `json:"location"`
	Format   string `json:"format,omitempty"`
}
