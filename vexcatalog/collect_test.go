package vexcatalog_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/groboclown/vex-catalog-go/vexcatalog"
	"github.com/package-url/packageurl-go"
)

// fakeLoader is a spy implementation of pkg.VexLoader[string].
type fakeLoader struct {
	mu      sync.Mutex
	called  bool
	ctxs    []context.Context
	purls   []*packageurl.PackageURL
	vulnIds []string
	results []string
	errs    []error
}

func (f *fakeLoader) LoadVex(
	ctx context.Context,
	purl *packageurl.PackageURL,
	vulnId string,
	vexChan chan<- string,
	errChan chan<- error,
) {
	f.mu.Lock()
	f.called = true
	f.ctxs = append(f.ctxs, ctx)
	f.purls = append(f.purls, purl)
	f.vulnIds = append(f.vulnIds, vulnId)
	f.mu.Unlock()

	for _, r := range f.results {
		vexChan <- r
	}
	for _, e := range f.errs {
		errChan <- e
	}
}

func (f *fakeLoader) Close() error {
	return nil
}

func equalUnordered(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := make(map[string]int, len(a))
	for _, s := range a {
		m[s]++
	}
	for _, s := range b {
		m[s]--
	}
	for _, v := range m {
		if v != 0 {
			return false
		}
	}
	return true
}

// Test_CollectVexDocuments_NoLoaders tests that no loaders results in no data and no errors.
func Test_CollectVexDocuments_NoLoaders(t *testing.T) {
	ctx := context.Background()
	purl, _ := packageurl.FromString("pkg:npm/%40angular/animation@12.3.1")
	results, errs := vexcatalog.CollectVexDocuments[string](ctx, &purl, "VULN-1", nil)

	if len(results) != 0 {
		t.Errorf("expected no results, got %v", results)
	}
	if len(errs) != 0 {
		t.Errorf("expected no errors, got %v", errs)
	}
}

// Test_CollectVexDocuments_MultipleLoaders tests that multiple loaders are invoked and their results/errors are collected.
func Test_CollectVexDocuments_MultipleLoaders(t *testing.T) {
	ctx := context.Background()
	purl, _ := packageurl.FromString("pkg:npm/%40angular/animation@12.3.1")

	loader1 := &fakeLoader{
		results: []string{"r1", "r2"},
		errs:    []error{errors.New("e1")},
	}
	loader2 := &fakeLoader{
		results: []string{"r3"},
		errs:    []error{errors.New("e2"), errors.New("e3")},
	}

	loaders := []vexcatalog.VexLoader[string]{loader1, loader2}
	results, errs := vexcatalog.CollectVexDocuments(ctx, &purl, "ID-42", loaders)

	// Verify both loaders were invoked
	if !loader1.called || !loader2.called {
		t.Fatalf("expected both loaders to be called; got called1=%v called2=%v", loader1.called, loader2.called)
	}

	// Verify parameters forwarded correctly
	for i, l := range []*fakeLoader{loader1, loader2} {
		if len(l.ctxs) != 1 || l.ctxs[0] != ctx {
			t.Errorf("loader %d: expected ctx %v, got %v", i+1, ctx, l.ctxs)
		}
		if len(l.purls) != 1 || l.purls[0] != &purl {
			t.Errorf("loader %d: expected purl %v, got %v", i+1, &purl, l.purls)
		}
		if len(l.vulnIds) != 1 || l.vulnIds[0] != "ID-42" {
			t.Errorf("loader %d: expected vulnId %q, got %v", i+1, "ID-42", l.vulnIds)
		}
	}

	// Verify collected results (order-insensitive)
	expectedResults := []string{"r1", "r2", "r3"}
	if !equalUnordered(results, expectedResults) {
		t.Errorf("expected results %v, got %v", expectedResults, results)
	}

	// Verify collected errors (order-insensitive)
	var gotErrs []string
	for _, e := range errs {
		gotErrs = append(gotErrs, e.Error())
	}
	expectedErrs := []string{"e1", "e2", "e3"}
	if !equalUnordered(gotErrs, expectedErrs) {
		t.Errorf("expected errors %v, got %v", expectedErrs, gotErrs)
	}
}

// Test_CollectVexDocuments_ConcurrentSafety checks concurrent send.
func Test_CollectVexDocuments_ConcurrentSafety(t *testing.T) {
	ctx := context.Background()
	purl, _ := packageurl.FromString("pkg:npm/%40angular/animation@12.3.1")

	const n = 100
	loader := &fakeLoader{}
	// push a burst of ints in a goroutine
	loader.results = make([]string, n)
	for i := range n {
		loader.results[i] = fmt.Sprintf("%d", i)
	}
	loaders := []vexcatalog.VexLoader[string]{loader}

	results, errs := vexcatalog.CollectVexDocuments(ctx, &purl, "C-100", loaders)

	if len(errs) != 0 {
		t.Errorf("expected no errors, got %v", errs)
	}
	if len(results) != n {
		t.Fatalf("expected %d results, got %d", n, len(results))
	}
	// verify all ints 0..n-1 are present
	m := make(map[string]bool, n)
	for _, v := range results {
		m[v] = true
	}
	for i := range n {
		if !m[fmt.Sprintf("%d", i)] {
			t.Errorf("missing result %d", i)
		}
	}
}

// Test_CollectVexDocuments_MultipleLoaders tests that multiple loaders are invoked and their results/errors are collected.
func Test_CollectVexDocuments_Proxy(t *testing.T) {
	ctx := context.Background()
	purl, _ := packageurl.FromString("pkg:npm/%40angular/animation@12.3.1")

	loader1 := &fakeLoader{
		results: []string{"r1", "r2"},
		errs:    []error{errors.New("e1")},
	}
	loader2 := &fakeLoader{
		results: []string{"r3"},
		errs:    []error{errors.New("e2"), errors.New("e3")},
	}

	loaders := []vexcatalog.VexLoader[string]{loader1, loader2}
	proxy := vexcatalog.NewProxyVexLoader(loaders...)
	results, errs := vexcatalog.CollectVexDocuments(ctx, &purl, "ID-42", []vexcatalog.VexLoader[string]{proxy})

	// Verify both loaders were invoked
	if !loader1.called || !loader2.called {
		t.Fatalf("expected both loaders to be called; got called1=%v called2=%v", loader1.called, loader2.called)
	}

	// Verify parameters forwarded correctly
	for i, l := range []*fakeLoader{loader1, loader2} {
		if len(l.ctxs) != 1 || l.ctxs[0] != ctx {
			t.Errorf("loader %d: expected ctx %v, got %v", i+1, ctx, l.ctxs)
		}
		if len(l.purls) != 1 || l.purls[0] != &purl {
			t.Errorf("loader %d: expected purl %v, got %v", i+1, &purl, l.purls)
		}
		if len(l.vulnIds) != 1 || l.vulnIds[0] != "ID-42" {
			t.Errorf("loader %d: expected vulnId %q, got %v", i+1, "ID-42", l.vulnIds)
		}
	}

	// Verify collected results (order-insensitive)
	expectedResults := []string{"r1", "r2", "r3"}
	if !equalUnordered(results, expectedResults) {
		t.Errorf("expected results %v, got %v", expectedResults, results)
	}

	// Verify collected errors (order-insensitive)
	var gotErrs []string
	for _, e := range errs {
		gotErrs = append(gotErrs, e.Error())
	}
	expectedErrs := []string{"e1", "e2", "e3"}
	if !equalUnordered(gotErrs, expectedErrs) {
		t.Errorf("expected errors %v, got %v", expectedErrs, gotErrs)
	}
}
