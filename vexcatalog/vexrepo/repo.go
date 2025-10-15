package vexrepo

import (
	"strconv"
	"strings"
)

// VexRepository contains the JSON structure of a VEX repository.
// See https://github.com/aquasecurity/vex-repo-spec/blob/main/vex-repository.schema.json
//
// Name is the name of the repository.
//
// Description is a brief description of the repository.
//
// Versions is an array containing details of available versions.
// Each object in the array represents a version implementing a
// VEX Repository Specification version. Versions MUST be sorted
// in ascending order, from oldest to newest.
type VexRepository struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Versions    []VexRepositoryVersion `json:"versions"`
}

// VexRepositoryVersion describes an available VEX specification version.
//
// SpecVersion contains the version of the VEX Repository Specification implemented (e.g., '0.1', '1.0')
//
// UpdateInterval is a duration string (e.g., '24h') that describes how often the repository is updated.
//
// Locations is an array of objects describing VEX data locations. MUST contain at least one
// location object.
type VexRepositoryVersion struct {
	SpecVersion        string                  `json:"spec_version"`
	Locations          []VexRepositoryLocation `json:"locations"`
	UpdateInterval     string                  `json:"update_interval"`
	RepositorySpecific map[string]any          `json:"repository_specific,omitempty"`
}

// VexRepositoryLocation describes VEX data locations
//
// URL is a URL for the VEX data location, starting with "https://". The content adheres to the
// repository structure specifications. The URL may include a subdirectory specification by
// appending '//' followed by the subdirectory path, which applies to archive files (such as zip files).
type VexRepositoryLocation struct {
	URL string `json:"url"`
}

func (r *VexRepository) LatestVersion() *VexRepositoryVersion {
	if r == nil || len(r.Versions) == 0 {
		return nil
	}
	latest := &r.Versions[0]
	for i := 1; i < len(r.Versions); i++ {
		if r.Versions[i].CmpVersion(latest) > 0 {
			latest = &r.Versions[i]
		}
	}
	return latest
}

// ClosestVersion returns the VexRepositoryVersion that is the closest match to the given specVersion, but not above it.
func (r *VexRepository) ClosestVersion(specVersion string) *VexRepositoryVersion {
	if r == nil || len(r.Versions) == 0 {
		return nil
	}
	var closest *VexRepositoryVersion
	for i := 0; i < len(r.Versions); i++ {
		cmp := cmpSimpleVersion(specVersion, r.Versions[i].SpecVersion)
		if cmp == 0 {
			return &r.Versions[i]
		}
		if cmp > 0 {
			closest = &r.Versions[i]
		}
	}
	return closest
}

// CmpVersion compares two VexRepositoryVersion instances based on their SpecVersion.
// It returns <0 if the receiver is less than the other, 0 if they are equal, and >0 if the receiver is greater.
// It handles semantic versioning with dot-separated integers (e.g., "1.0", "2.1.3").
// If versions have different lengths, the shorter one is considered lesser if all compared segments are equal.
func (v *VexRepositoryVersion) CmpVersion(o *VexRepositoryVersion) int {
	if v == nil && o == nil {
		return 0
	}
	if v == nil {
		return -1
	}
	if o == nil {
		return 1
	}
	return cmpSimpleVersion(v.SpecVersion, o.SpecVersion)
}

// cmpSimpleVersion compares two simple dot-separated version strings.
// It returns <0 if v1 < v2, 0 if v1 == v2, and >0 if v1 > v2.
// Non-numeric segments are compared lexicographically.
func cmpSimpleVersion(v1, v2 string) int {
	if v1 == v2 {
		return 0
	}
	s1 := strings.Split(v1, ".")
	s2 := strings.Split(v2, ".")
	minLen := len(s1)
	if len(s2) < minLen {
		minLen = len(s2)
	}
	for i := 0; i < minLen; i++ {
		if s1[i] == s2[i] {
			continue
		}
		v1, err1 := strconv.Atoi(s1[i])
		v2, err2 := strconv.Atoi(s2[i])
		if err1 != nil && err2 != nil {
			return strings.Compare(s1[i], s2[i])
		}
		if err1 != nil {
			return -1
		}
		if err2 != nil {
			return 1
		}
		return v1 - v2
	}
	return len(s1) - len(s2)
}
