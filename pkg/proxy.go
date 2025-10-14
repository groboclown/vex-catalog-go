package pkg

import (
	"context"
	"errors"
	"sync"

	"github.com/package-url/packageurl-go"
)

// ProxyVexLoader is a VexLoader that delegates to multiple underlying VexLoaders.
type ProxyVexLoader[T any] struct {
	loaders []VexLoader[T]
}

var _ VexLoader[int] = (*ProxyVexLoader[int])(nil)

// NewProxyVexLoader creates a new ProxyVexLoader that calls to the provided loaders concurrently.
func NewProxyVexLoader[T any](loaders ...VexLoader[T]) *ProxyVexLoader[T] {
	return &ProxyVexLoader[T]{
		loaders: loaders,
	}
}

func (p *ProxyVexLoader[T]) LoadVex(
	ctx context.Context,
	purl *packageurl.PackageURL,
	vulnId string,
	vexChan chan<- T,
	errChan chan<- error,
) {
	if p == nil || len(p.loaders) == 0 {
		return
	}
	var wg sync.WaitGroup
	for _, l := range p.loaders {
		wg.Go(func() {
			l.LoadVex(ctx, purl, vulnId, vexChan, errChan)
		})
	}
	wg.Wait()
}

func (p *ProxyVexLoader[T]) Close() error {
	if p == nil || len(p.loaders) == 0 {
		return nil
	}
	errs := make([]error, 0)
	for _, l := range p.loaders {
		if err := l.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
