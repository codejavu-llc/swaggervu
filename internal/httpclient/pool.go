package httpclient

import (
	"context"
	"sync"
)

// ForEach runs fn over items using up to `concurrency` workers.
// It stops early if ctx is cancelled.
func ForEach[T any](ctx context.Context, concurrency int, items []T, fn func(ctx context.Context, item T)) {
	if concurrency < 1 {
		concurrency = 1
	}
	ch := make(chan T)
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range ch {
				select {
				case <-ctx.Done():
					return
				default:
				}
				fn(ctx, item)
			}
		}()
	}
	for _, it := range items {
		select {
		case <-ctx.Done():
			close(ch)
			wg.Wait()
			return
		case ch <- it:
		}
	}
	close(ch)
	wg.Wait()
}
