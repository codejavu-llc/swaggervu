package httpclient

import (
	"context"
	"sync/atomic"
)

type requestBudgetKey struct{}

type requestBudget struct {
	limit int64
	used  atomic.Int64
}

// WithRequestBudget gives a command one request allowance shared by all clients
// using the returned context or its children. Call it once per invocation.
// A nonpositive limit is unlimited. Existing per-client limits still apply.
func WithRequestBudget(ctx context.Context, limit int64) context.Context {
	return context.WithValue(ctx, requestBudgetKey{}, &requestBudget{limit: limit})
}

func takeContextRequest(ctx context.Context) error {
	budget, _ := ctx.Value(requestBudgetKey{}).(*requestBudget)
	if budget != nil && budget.limit > 0 && budget.used.Add(1) > budget.limit {
		return ErrRequestBudget
	}
	return nil
}
