package vault

import (
	"context"
	"errors"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/sdk/v2/physical"
)

var _ physical.Backend = (*ForwardingBackend)(nil)

// ForwardingBackend implements physical.Backend on top of a logical.Storage
type ForwardingBackend struct {
	target logical.Storage
}

func NewForwardingBackend(wrapped logical.Storage) *ForwardingBackend {
	return &ForwardingBackend{
		target: wrapped,
	}
}

// NewNamespaceBarrier constructs a new wrapped Barrier for the given namespace.
// The passed parent SecurityBarrier must be the closest parent namespace barrier.
func NewNamespaceBarrier(parent logical.Storage, ns *namespace.Namespace) (SecurityBarrier, error) {
	if ns.IsRoot() {
		return nil, errors.New("can't construct namespace barrier for root namespace")
	}
	metaPrefix := namespaceBarrierPrefix + ns.UUID + "/"
	return NewAESGCMBarrier(NewForwardingBackend(parent), metaPrefix)
}

func (f *ForwardingBackend) Delete(ctx context.Context, path string) error {
	return f.target.Delete(ctx, path)
}

func (f *ForwardingBackend) Get(ctx context.Context, path string) (*physical.Entry, error) {
	se, err := f.target.Get(ctx, path)
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

func (f *ForwardingBackend) Put(ctx context.Context, pe *physical.Entry) error {
	se := logical.StorageEntry{
		Key:      pe.Key,
		Value:    pe.Value,
		SealWrap: pe.SealWrap,
	}
	return f.target.Put(ctx, &se)
}

func (f *ForwardingBackend) List(ctx context.Context, prefix string) ([]string, error) {
	return f.target.List(ctx, prefix)
}

func (f *ForwardingBackend) ListPage(ctx context.Context, prefix string, after string, limit int) ([]string, error) {
	return f.target.ListPage(ctx, prefix, after, limit)
}
