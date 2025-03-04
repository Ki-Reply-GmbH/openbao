package vault

import (
	"context"
	"math/rand"
	"strconv"
	"testing"

	"github.com/openbao/openbao/helper/benchhelpers"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/stretchr/testify/require"
)

func TestNamespaceStore(t *testing.T) {
	t.Parallel()

	c, keys, root := TestCoreUnsealed(t)
	s := c.namespaceStore

	ctx := context.TODO()

	// Initial store should be empty.
	ns, err := s.ListNamespaceUUIDs(ctx, false)
	require.NoError(t, err)
	require.Empty(t, ns)

	ns, err = s.ListNamespaceAccessors(ctx, false)
	require.NoError(t, err)
	require.Empty(t, ns)

	ns, err = s.ListNamespacePaths(ctx, false)
	require.NoError(t, err)
	require.Empty(t, ns)

	// Creating an item should save it, set IDs, and canonicalize path.
	item := &NamespaceEntry{
		Namespace: &namespace.Namespace{
			Path: "ns1",
		},
	}

	err = s.SetNamespace(ctx, item)
	require.NoError(t, err)
	require.NotEmpty(t, item.UUID)
	require.NotEmpty(t, item.Namespace.ID)
	require.Equal(t, item.Namespace.Path, namespace.Canonicalize("ns1"))
	require.Equal(t, item.Namespace.Path, "ns1/")

	itemUUID := item.UUID
	itemAccessor := item.Namespace.ID
	itemPath := item.Namespace.Path

	// We should now have one item.
	ns, err = s.ListNamespaceUUIDs(ctx, false)
	require.NoError(t, err)
	require.NotEmpty(t, ns)
	require.Equal(t, ns[0], itemUUID)

	ns, err = s.ListNamespaceAccessors(ctx, false)
	require.NoError(t, err)
	require.NotEmpty(t, ns)
	require.Equal(t, ns[0], itemAccessor)

	ns, err = s.ListNamespacePaths(ctx, false)
	require.NoError(t, err)
	require.NotEmpty(t, ns)
	require.Equal(t, ns[0], itemPath)

	// Modifying our copy shouldn't affect anything.
	item.Namespace.CustomMetadata = map[string]string{"openbao": "true"}
	item.Namespace.Path = "modified"
	item.Namespace.ID = "modified"
	item.UUID = "modified"

	fetched, err := s.GetNamespace(ctx, itemUUID)
	require.NoError(t, err)
	require.NotNil(t, fetched)
	require.Equal(t, fetched.UUID, itemUUID)
	require.Equal(t, fetched.Namespace.ID, itemAccessor)
	require.Equal(t, fetched.Namespace.Path, itemPath)
	require.Empty(t, fetched.Namespace.CustomMetadata)

	// Fetching the modified ID should fail.
	fetched, err = s.GetNamespace(ctx, item.UUID)
	require.NoError(t, err)
	require.Nil(t, fetched)

	// Sealing the core and unsealing it should yield the same result.
	err = c.Seal(root)
	require.NoError(t, err)

	for i, key := range keys {
		unseal, err := TestCoreUnseal(c, key)
		require.NoError(t, err)

		if i+1 == len(keys) && !unseal {
			t.Fatal("err: should be unsealed")
		}
	}

	// We should still have one item.
	ns, err = s.ListNamespaceUUIDs(ctx, false)
	require.NoError(t, err)
	require.NotEmpty(t, ns)
	require.Equal(t, ns[0], itemUUID)

	ns, err = s.ListNamespaceAccessors(ctx, false)
	require.NoError(t, err)
	require.NotEmpty(t, ns)
	require.Equal(t, ns[0], itemAccessor)

	ns, err = s.ListNamespacePaths(ctx, false)
	require.NoError(t, err)
	require.NotEmpty(t, ns)
	require.Equal(t, ns[0], itemPath)

	// Delete that item.
	err = s.DeleteNamespace(ctx, itemUUID)
	require.NoError(t, err)

	// Store should be empty.
	ns, err = s.ListNamespaceUUIDs(ctx, false)
	require.NoError(t, err)
	require.Empty(t, ns)

	ns, err = s.ListNamespaceAccessors(ctx, false)
	require.NoError(t, err)
	require.Empty(t, ns)

	ns, err = s.ListNamespacePaths(ctx, false)
	require.NoError(t, err)
	require.Empty(t, ns)

	// Sealing the core and unsealing it should yield the same result.
	err = c.Seal(root)
	require.NoError(t, err)

	for i, key := range keys {
		unseal, err := TestCoreUnseal(c, key)
		require.NoError(t, err)

		if i+1 == len(keys) && !unseal {
			t.Fatal("err: should be unsealed")
		}
	}

	ns, err = s.ListNamespaceUUIDs(ctx, false)
	require.NoError(t, err)
	require.Empty(t, ns)

	ns, err = s.ListNamespaceAccessors(ctx, false)
	require.NoError(t, err)
	require.Empty(t, ns)

	ns, err = s.ListNamespacePaths(ctx, false)
	require.NoError(t, err)
	require.Empty(t, ns)

	// Creating a new version of item should yield a new id even though the
	// path is the same.
	item = &NamespaceEntry{
		Namespace: &namespace.Namespace{
			Path: "ns1/",
		},
	}

	err = s.SetNamespace(ctx, item)
	require.NoError(t, err)
	require.NotEmpty(t, item.UUID)
	require.NotEqual(t, item.UUID, itemUUID)
	require.NotEmpty(t, item.Namespace.ID)
	require.NotEqual(t, item.Namespace.ID, itemAccessor)
	require.Equal(t, item.Namespace.Path, namespace.Canonicalize("ns1"))
	require.Equal(t, item.Namespace.Path, "ns1/")
	require.Equal(t, item.Namespace.Path, itemPath)
}

func BenchmarkNamespaceStore(b *testing.B) {
	c, _, _ := TestCoreUnsealed(benchhelpers.TBtoT(b))
	s := c.namespaceStore

	ctx := context.TODO()

	n := 10_000

	for i := range n {
		item := &NamespaceEntry{
			Namespace: &namespace.Namespace{
				Path: "ns" + strconv.Itoa(i),
			},
		}
		s.SetNamespace(ctx, item)
	}

	require.Equal(b, n+1, len(s.namespaces))

	b.Run("GetNamespace", func(b *testing.B) {
		n := s.size()
		for b.Loop() {
			idx := rand.Intn(n)
			uuid := s.namespaces[idx].UUID
			s.GetNamespace(ctx, uuid)
		}
	})

	b.Run("GetNamespaceByAccessor", func(b *testing.B) {
		n := s.size()
		for b.Loop() {
			idx := rand.Intn(n)
			accessor := s.namespaces[idx].Namespace.ID
			s.GetNamespaceByAccessor(ctx, accessor)
		}
	})

	b.Run("GetNamespaceByPath", func(b *testing.B) {
		n := s.size()
		for b.Loop() {
			idx := rand.Intn(n)
			path := s.namespaces[idx].Namespace.Path
			s.GetNamespaceByPath(ctx, path)
		}
	})

	b.Run("ModifyNamespaceByPath", func(b *testing.B) {
		n := s.size()
		for b.Loop() {
			idx := rand.Intn(n)
			path := s.namespaces[idx].Namespace.Path
			s.ModifyNamespaceByPath(ctx, path, testModifyNamespace)
		}
	})

	b.Run("ListNamespaces", func(b *testing.B) {
		for b.Loop() {
			s.ListNamespaces(ctx, false)
		}
	})

	b.Run("ListNamespaceUUIDs", func(b *testing.B) {
		for b.Loop() {
			s.ListNamespaceUUIDs(ctx, false)
		}
	})

	b.Run("ListNamespaceAccessors", func(b *testing.B) {
		for b.Loop() {
			s.ListNamespaceAccessors(ctx, false)
		}
	})

	b.Run("ListNamespacePaths", func(b *testing.B) {
		for b.Loop() {
			s.ListNamespacePaths(ctx, false)
		}
	})

	b.Run("ResolveNamespaceFromRequest", func(b *testing.B) {
		rootCtx := namespace.RootContext(context.TODO())
		n := s.size()
		for b.Loop() {
			idx := rand.Intn(n)
			ns := s.namespaces[idx].Namespace
			ctx := namespace.ContextWithNamespace(rootCtx, ns)
			s.ResolveNamespaceFromRequest(rootCtx, ctx, "/sys/namespaces")
		}
	})

	b.Run("DeleteNamespace", func(b *testing.B) {
		for b.Loop() {
			n := s.size()
			idx := rand.Intn(n)
			uuid := s.namespaces[idx].UUID
			s.DeleteNamespace(ctx, uuid)
		}
	})
}
func testModifyNamespace(_ context.Context, ns *NamespaceEntry) (*NamespaceEntry, error) {
	uuid := ns.UUID
	accessor := ns.Namespace.ID
	ns.Namespace.CustomMetadata["uuid"] = uuid
	ns.Namespace.CustomMetadata["accessor"] = accessor

	return ns, nil
}
