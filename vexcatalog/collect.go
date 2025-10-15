package vexcatalog

import (
	"context"
	"sync"

	"github.com/package-url/packageurl-go"
)

// CollectVexDocuments collects VEX documents from multiple loaders concurrently.
func CollectVexDocuments[T any](
	ctx context.Context,
	purl *packageurl.PackageURL,
	vulnId string,
	loaders []VexLoader[T],
) ([]T, []error) {
	vexChan := make(chan T)
	errChan := make(chan error)

	var loaderWg sync.WaitGroup
	for _, loader := range loaders {
		loaderWg.Add(1)
		go func(l VexLoader[T]) {
			defer loaderWg.Done()
			l.LoadVex(ctx, purl, vulnId, vexChan, errChan)
		}(loader)
	}

	var collectorWg sync.WaitGroup
	var vext []T
	collectorWg.Go(func() {
		for v := range vexChan {
			vext = append(vext, v)
		}
	})

	var errs []error
	collectorWg.Go(func() {
		for err := range errChan {
			errs = append(errs, err)
		}
	})

	loaderWg.Wait()
	close(vexChan)
	close(errChan)
	collectorWg.Wait()

	return vext, errs
}
