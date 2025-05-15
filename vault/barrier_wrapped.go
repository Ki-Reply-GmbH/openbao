package vault

import (
	"context"
	"errors"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/sdk/v2/physical"
)

var _ physical.Backend = (*WrappedBarrier)(nil)

// WrappedBarrier implements physical.Backend on top of a logical.Storage
type WrappedBarrier struct {
	wrapped logical.Storage
}

func NewWrappedBarrier(wrapped logical.Storage) *WrappedBarrier {
	return &WrappedBarrier{
		wrapped: wrapped,
	}
}

// NewNamespaceBarrier constructs a new wrapped Barrier for the given namespace.
// The passed parent SecurityBarrier must be the closest parent namespace barrier.
func NewNamespaceBarrier(parent logical.Storage, ns *namespace.Namespace) (logical.Storage, error) {
	if ns.IsRoot() {
		return nil, errors.New("can't construct namespace barrier for root namespace")
	}
	metaPrefix := namespaceBarrierPrefix + ns.UUID + "/"
	return NewAESGCMBarrier(NewWrappedBarrier(parent), metaPrefix)
}

func (w *WrappedBarrier) Delete(ctx context.Context, path string) error {
	return w.wrapped.Delete(ctx, path)
}

func (w *WrappedBarrier) Get(ctx context.Context, path string) (*physical.Entry, error) {
	se, err := w.wrapped.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	if se == nil {
		return nil, nil
	}
	pe := physical.Entry{
		Key:      se.Key,
		Value:    se.Value,
		SealWrap: se.SealWrap,
	}
	return &pe, nil
}

func (w *WrappedBarrier) Put(ctx context.Context, pe *physical.Entry) error {
	se := logical.StorageEntry{
		Key:      pe.Key,
		Value:    pe.Value,
		SealWrap: pe.SealWrap,
	}
	return w.wrapped.Put(ctx, &se)
}

func (w *WrappedBarrier) List(ctx context.Context, prefix string) ([]string, error) {
	return w.wrapped.List(ctx, prefix)
}

func (w *WrappedBarrier) ListPage(ctx context.Context, prefix string, after string, limit int) ([]string, error) {
	return w.wrapped.ListPage(ctx, prefix, after, limit)
}
