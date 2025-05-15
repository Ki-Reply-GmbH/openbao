package vault

import (
	"context"

	"github.com/armon/go-radix"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/logical"
)

type BarrierManager struct {
	core *Core

	barriersByNamespace *radix.Tree
}

func (c *Core) setupBarrierManager(_ context.Context) error {
	c.barrierManager = &BarrierManager{
		core:                c,
		barriersByNamespace: radix.New(),
	}
	return nil
}

func (bm *BarrierManager) BarrierForNamespace(ns *namespace.Namespace) (logical.Storage, string) {
	var barrier SecurityBarrier
	var nsPath string
	bm.barriersByNamespace.WalkPath(ns.Path, func(s string, v any) bool {
		barrier = v.(SecurityBarrier)
		nsPath = s
		return true
	})
	return barrier, nsPath
}

func (bm *BarrierManager) AddBarrier(ns *namespace.Namespace, barrier logical.Storage) {
	bm.barriersByNamespace.Insert(ns.Path, barrier)
}

func (bm *BarrierManager) RemoveBarrier(ns *namespace.Namespace) {
	bm.barriersByNamespace.Delete(ns.Path)
}
