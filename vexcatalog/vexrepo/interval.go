package vexrepo

import "time"

func (v *VexRepositoryVersion) ParseUpdateInterval() (time.Duration, error) {
	if v.UpdateInterval == "" {
		// Default to 24 hours if not specified.
		return 24 * time.Hour, nil
	}
	return time.ParseDuration(v.UpdateInterval)
}

func (v *RepositoryIndex) ParseUpdatedAt() (time.Time, error) {
	return time.Parse(time.RFC3339, v.UpdatedAt)
}
