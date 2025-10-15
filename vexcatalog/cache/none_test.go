package cache_test

import (
	"io"
	"testing"
	"time"

	"github.com/groboclown/vex-catalog-go/vexcatalog/cache"
	"github.com/package-url/packageurl-go"
)

func Test_NoneCacheFactory(t *testing.T) {
	f := &cache.NoneCacheFactory{}
	pkg := packageurl.PackageURL{Type: "generic", Name: "test"}
	pullerCalled := false
	puller := func() (io.ReadCloser, time.Time, error) {
		pullerCalled = true
		return &ReadCloserSpy{}, time.Now(), nil
	}
	cache, err := f.Cache(pkg, time.Minute, puller)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if cache == nil {
		t.Fatal("expected a cache instance, got nil")
	}
	if pullerCalled {
		t.Fatal("expected puller not to be called during cache creation")
	}

	// Test Get method
	pullerCalled = false
	r, err := cache.Get()
	if err != nil {
		t.Fatalf("expected no error from Get, got %v", err)
	}
	if r == nil {
		t.Fatal("expected a ReadCloser from Get, got nil")
	}
	if !pullerCalled {
		t.Fatal("expected puller to be called during Get")
	}
	rcSpy, ok := r.(*ReadCloserSpy)
	if !ok {
		t.Fatal("expected ReadCloser to be of type ReadCloserSpy")
	}
	if rcSpy.ReadCount != 0 {
		t.Fatalf("expected ReadCount to be 0, got %d", rcSpy.ReadCount)
	}
	if rcSpy.CloseCount != 0 {
		t.Fatalf("expected CloseCount to be 0, got %d", rcSpy.CloseCount)
	}

	// Test Flush method (should be a no-op)
	cache.Flush()
}

type ReadCloserSpy struct {
	CloseCount int
	ReadCount  int
	Err        error
}

var _ io.ReadCloser = (*ReadCloserSpy)(nil)

func (r *ReadCloserSpy) Read(p []byte) (n int, err error) {
	r.ReadCount++
	return 0, r.Err
}

func (r *ReadCloserSpy) Close() error {
	r.CloseCount++
	return nil
}
