package externalkeys

import (
	"fmt"
	"sync"

	"github.com/hashicorp/go-memdb"
	"github.com/openbao/openbao/sdk/v2/helper/cryptoutil"
)

type NamespacedCache[T any] struct {
	db    *memdb.MemDB
	locks []*sync.Mutex
}

type cacheEntry[T any] struct {
	value T

	// These are used for indexing in MemDB.
	NamespacePath string
	ConfigName    string
}

const (
	// Table name for [NamespacedCache].
	cacheTable = "cache"

	// Index by namespace path + config name.
	indexID = "id"
	// Index by namespace path.
	indexNamespace = "ns"
	// Index by namespace path prefix.
	indexNamespacePrefix = indexNamespace + "_prefix"
)

var cacheSchema = &memdb.DBSchema{
	Tables: map[string]*memdb.TableSchema{
		cacheTable: {
			Name: cacheTable,
			Indexes: map[string]*memdb.IndexSchema{
				indexID: {
					Name:   indexID,
					Unique: true,
					Indexer: &memdb.CompoundIndex{
						Indexes: []memdb.Indexer{
							&memdb.StringFieldIndex{Field: "NamespacePath"},
							&memdb.StringFieldIndex{Field: "ConfigName"},
						},
					},
				},
				indexNamespace: {
					Name:    indexNamespace,
					Unique:  false,
					Indexer: &memdb.StringFieldIndex{Field: "NamespacePath"},
				},
			},
		},
	},
}

func must[T any](v T, err error) T {
	switch err {
	case nil:
		return v
	default:
		panic(fmt.Errorf("memdb misuse: %w", err))
	}
}

func NewCache[T any]() *NamespacedCache[T] {
	locks := make([]*sync.Mutex, 256)
	for i := range locks {
		locks[i] = new(sync.Mutex)
	}

	return &NamespacedCache[T]{
		db:    must(memdb.NewMemDB(cacheSchema)),
		locks: locks,
	}
}

func (c *NamespacedCache[T]) lock(path, name string) func() {
	key := fmt.Sprintf("%s/%s", path, name)
	idx := uint8(cryptoutil.Blake2b256Hash(key)[0])

	lock := c.locks[idx]
	lock.Lock()

	return lock.Unlock
}

func (c *NamespacedCache[T]) GetOrCreate(path, name string, create func() (T, error)) (T, error) {
	rtxn := c.db.Txn(false)

	fetch := func() *cacheEntry[T] {
		if raw := must(rtxn.First(cacheTable, indexID, path, name)); raw != nil {
			return raw.(*cacheEntry[T])
		} else {
			return nil
		}
	}

	if entry := fetch(); entry != nil {
		return entry.value, nil
	}

	unlock := c.lock(path, name)
	defer unlock()

	if entry := fetch(); entry != nil {
		return entry.value, nil
	}

	value, err := create()
	if err != nil {
		var empty T
		return empty, err
	}

	entry := &cacheEntry[T]{
		value:         value,
		NamespacePath: path,
		ConfigName:    name,
	}

	wtxn := c.db.Txn(true)
	wtxn.Insert(cacheTable, entry)
	wtxn.Commit()

	return value, nil
}

func (c *NamespacedCache[T]) Remove(path, name string, destroy func(T, string, string)) {
	txn := c.db.Txn(true)
	defer txn.Commit()

	if raw := must(txn.First(cacheTable, indexID, path, name)); raw != nil {
		entry := raw.(*cacheEntry[T])
		must(0, txn.Delete(cacheTable, entry))
		destroy(entry.value, entry.NamespacePath, entry.ConfigName)
	}
}

func (c *NamespacedCache[T]) Drain(prefix string, destroy func(T, string, string), keep func(T) bool) {
	txn := c.db.Txn(true)
	defer txn.Commit()

	iter := must(txn.Get(cacheTable, indexID))
	for raw := iter.Next(); raw != nil; raw = iter.Next() {
		entry := raw.(*cacheEntry[T])
		must(0, txn.Delete(cacheTable, entry))
		if keep == nil || !keep(entry.value) {
			destroy(entry.value, entry.NamespacePath, entry.ConfigName)
		}
	}
}

func (c *NamespacedCache[T]) Clear(destroy func(T, string, string)) {
	txn := c.db.Txn(true)
	defer txn.Commit()

	iter := must(txn.Get(cacheTable, indexID))
	for raw := iter.Next(); raw != nil; raw = iter.Next() {
		entry := raw.(*cacheEntry[T])
		destroy(entry.value, entry.NamespacePath, entry.ConfigName)
	}

	must(txn.DeleteAll(cacheTable, indexID))
}
