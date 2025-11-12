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
	r, err := f.Cache(pkg, time.Minute, puller)
	if err != nil {
		t.Fatalf("expected no error, found %v", err)
	}
	if r == nil {
		t.Fatal("expected a reader instance, found nil")
	}
	if !pullerCalled {
		t.Fatal("expected pull to be called, but it was not")
	}
	rcSpy, ok := r.(*ReadCloserSpy)
	if !ok {
		t.Fatal("expected ReadCloser to be of type ReadCloserSpy")
	}
	if rcSpy.ReadCount != 0 {
		t.Fatalf("expected ReadCount to be 0, found %d", rcSpy.ReadCount)
	}
	if rcSpy.CloseCount != 0 {
		t.Fatalf("expected CloseCount to be 0, found %d", rcSpy.CloseCount)
	}
	err = r.Close()
	if err != nil {
		t.Fatalf("expected no error on close, found %v", err)
	}
	if rcSpy.CloseCount != 1 {
		t.Fatalf("expected CloseCount to be 1 after close, found %d", rcSpy.CloseCount)
	}
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
