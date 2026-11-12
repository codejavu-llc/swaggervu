package httpclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

type budgetTestTransport struct{ calls *atomic.Int64 }

func (tr budgetTestTransport) RoundTrip(*http.Request) (*http.Response, error) {
	tr.calls.Add(1)
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("OK"))}, nil
}

func TestContextRequestBudget(t *testing.T) {
	newClient := func(t *testing.T, calls *atomic.Int64, limit int64) *Client {
		t.Helper()
		opts := DefaultOptions()
		opts.AllowPrivate, opts.RatePerSecond, opts.MaxRequests = true, 0, limit
		client, err := New(opts)
		if err != nil {
			t.Fatal(err)
		}
		// Only count transport calls. These tests never make a network request.
		client.hc.Transport = budgetTestTransport{calls: calls}
		return client
	}
	const target = "http://127.0.0.1/example"
	t.Run("distinct clients and child contexts share allowance", func(t *testing.T) {
		var calls atomic.Int64
		ctx := WithRequestBudget(context.Background(), 1)
		child, cancel := context.WithCancel(ctx)
		defer cancel()
		if _, err := newClient(t, &calls, 0).Get(child, target); err != nil {
			t.Fatal(err)
		}
		if _, err := newClient(t, &calls, 0).Get(ctx, target); !errors.Is(err, ErrRequestBudget) {
			t.Fatalf("got %v, want request budget error", err)
		}
		if calls.Load() != 1 {
			t.Fatalf("transport calls = %d, want 1", calls.Load())
		}
	})
	t.Run("standalone client keeps its limit", func(t *testing.T) {
		var calls atomic.Int64
		client := newClient(t, &calls, 1)
		if _, err := client.Get(context.Background(), target); err != nil {
			t.Fatal(err)
		}
		if _, err := client.Get(context.Background(), target); !errors.Is(err, ErrRequestBudget) {
			t.Fatalf("got %v, want request budget error", err)
		}
		if calls.Load() != 1 {
			t.Fatalf("transport calls = %d, want 1", calls.Load())
		}
	})
	t.Run("shared allowance preserves smaller client limit", func(t *testing.T) {
		var calls atomic.Int64
		client := newClient(t, &calls, 1)
		ctx := WithRequestBudget(context.Background(), 2)
		if _, err := client.Get(ctx, target); err != nil {
			t.Fatal(err)
		}
		if _, err := client.Get(ctx, target); !errors.Is(err, ErrRequestBudget) {
			t.Fatalf("got %v, want client limit error", err)
		}
		if calls.Load() != 1 {
			t.Fatalf("transport calls = %d, want 1", calls.Load())
		}
	})
	t.Run("fresh invocation gets a fresh allowance", func(t *testing.T) {
		var calls atomic.Int64
		client := newClient(t, &calls, 0)
		for i := 0; i < 2; i++ {
			ctx := WithRequestBudget(context.Background(), 1)
			if _, err := client.Get(ctx, target); err != nil {
				t.Fatal(err)
			}
		}
		if calls.Load() != 2 {
			t.Fatalf("transport calls = %d, want 2", calls.Load())
		}
	})
	t.Run("zero is unlimited", func(t *testing.T) {
		var calls atomic.Int64
		ctx := WithRequestBudget(context.Background(), 0)
		for i := 0; i < 3; i++ {
			if _, err := newClient(t, &calls, 0).Get(ctx, target); err != nil {
				t.Fatal(err)
			}
		}
		if calls.Load() != 3 {
			t.Fatalf("transport calls = %d, want 3", calls.Load())
		}
	})
	t.Run("concurrent clients share one limit", func(t *testing.T) {
		var calls atomic.Int64
		ctx := WithRequestBudget(context.Background(), 3)
		results := make(chan error, 8)
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			client := newClient(t, &calls, 0)
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := client.Get(ctx, target)
				results <- err
			}()
		}
		wg.Wait()
		close(results)
		var succeeded, limited int
		for err := range results {
			switch {
			case err == nil:
				succeeded++
			case errors.Is(err, ErrRequestBudget):
				limited++
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}
		if succeeded != 3 || limited != 5 || calls.Load() != 3 {
			t.Fatalf("successful=%d limited=%d transport calls=%d; want 3, 5, 3", succeeded, limited, calls.Load())
		}
	})
}
