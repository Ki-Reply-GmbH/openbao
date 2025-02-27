package vault

import (
	"context"
	"testing"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func testGetParentNs(b *SystemBackend, parent string) (*namespace.Namespace, error) {
	var parentNs *namespace.Namespace
	if parent == "root" || parent == "" {
		parentNs = namespace.RootNamespace
	} else {
		parentNsEntry, err := b.Core.namespaceStore.GetNamespaceByPath(context.TODO(), parent)
		if err != nil {
			return nil, err
		}

		parentNs = parentNsEntry.Namespace
	}

	return parentNs, nil
}

func testCreateNamespace(b *SystemBackend, name, parent string) (*logical.Response, error) {
	f := b.handleNamespacesSet()
	parentNs, err := testGetParentNs(b, parent)
	if err != nil {
		return nil, err
	}

	ctx := namespace.ContextWithNamespace(context.TODO(), parentNs)
	req := logical.Request{}
	fd := framework.FieldData{
		Raw: map[string]any{
			"path": name,
		},
		Schema: map[string]*framework.FieldSchema{
			"path": {
				Type:     framework.TypeString,
				Required: true,
			},
		},
	}
	return f(ctx, &req, &fd)
}

func testListNamespaces(b *SystemBackend, parent string) (*logical.Response, error) {
	f := b.handleNamespacesList()
	parentNs, err := testGetParentNs(b, parent)
	if err != nil {
		return nil, err
	}
	ctx := namespace.ContextWithNamespace(context.TODO(), parentNs)
	req := logical.Request{}
	fd := framework.FieldData{}
	return f(ctx, &req, &fd)
}

func testReadNamespaces(b *SystemBackend, path, parent string) (*logical.Response, error) {
	f := b.handleNamespacesRead()
	parentNs, err := testGetParentNs(b, parent)
	if err != nil {
		return nil, err
	}
	ctx := namespace.ContextWithNamespace(context.TODO(), parentNs)
	req := logical.Request{}
	fd := framework.FieldData{
		Raw: map[string]any{
			"path": path,
		},
		Schema: map[string]*framework.FieldSchema{
			"path": {
				Type:     framework.TypeString,
				Required: true,
			},
		},
	}
	return f(ctx, &req, &fd)
}

func TestSystemBackend_NamespacesList(t *testing.T) {
	b := testSystemBackend(t)
	be := b.(*SystemBackend)

	res, err := testCreateNamespace(be, "foo", "")
	require.NoError(t, err)
	require.Empty(t, res)

	res, err = testCreateNamespace(be, "bar", "foo")
	require.NoError(t, err)
	require.Empty(t, res)

	res, err = testListNamespaces(be, "")
	require.NoError(t, err)
	keys := res.Data["keys"].([]string)
	require.Len(t, keys, 1)
	require.Equal(t, "foo/", keys[0])

	res, err = testListNamespaces(be, "foo")
	require.NoError(t, err)
	keys = res.Data["keys"].([]string)
	require.Len(t, keys, 1)
	require.Equal(t, "bar/", keys[0])

}

func TestSystemBackend_NamespacesRead(t *testing.T) {
	b := testSystemBackend(t)
	be := b.(*SystemBackend)

	res, err := testCreateNamespace(be, "foo", "")
	require.NoError(t, err)
	require.Empty(t, res)

	res, err = testCreateNamespace(be, "bar", "foo")
	require.NoError(t, err)
	require.Empty(t, res)

	res, err = testReadNamespaces(be, "foo/", "")
	require.NoError(t, err)
	require.NotEmpty(t, res)
	require.Equal(t, res.Data["path"], "foo/")

	res, err = testReadNamespaces(be, "foo/bar", "")
	require.NoError(t, err)
	require.NotEmpty(t, res)
	require.Equal(t, res.Data["path"], "foo/bar/")

	res, err = testReadNamespaces(be, "bar", "foo")
	require.NoError(t, err)
	require.NotEmpty(t, res)
	require.Equal(t, res.Data["path"], "foo/bar/")

	res, err = testReadNamespaces(be, "bar", "")
	require.NoError(t, err)
	require.Empty(t, res)
}
