package cache

// Package cache provides interfaces and implementations for caching VEX documents
// associated with software packages. This helps to reduce redundant network requests
// and improve performance when accessing VEX data.
//
// By placing this into its own interface, it allows implementors to create custom caching
// strategies, such as in-memory caching, temporary file-based caching, per-user shared
// caches, or distributed caching solutions.
