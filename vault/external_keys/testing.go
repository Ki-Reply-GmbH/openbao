package externalkeys

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/logical"
)

type TestNamespacer struct {
	storage    map[string]*logical.InmemStorage
	namespaces map[string]*namespace.Namespace
}

func NewTestNamespacer() *TestNamespacer {
	n := &TestNamespacer{
		namespaces: make(map[string]*namespace.Namespace),
		storage:    make(map[string]*logical.InmemStorage),
	}

	n.Add(namespace.RootNamespace)
	return n
}

func (n *TestNamespacer) Add(ns *namespace.Namespace) context.Context {
	n.namespaces[ns.Path] = ns
	n.storage[ns.Path] = &logical.InmemStorage{}
	// Return a context with the namespace for covenience.
	return namespace.ContextWithNamespace(context.Background(), ns)
}

func (n *TestNamespacer) View(ns *namespace.Namespace) logical.Storage {
	return n.storage[ns.Path]
}

func (n *TestNamespacer) ParentOf(ctx context.Context, ns *namespace.Namespace) (*namespace.Namespace, error) {
	path, ok := namespace.ParentOf(ns.Path)
	if !ok {
		return nil, fmt.Errorf("namespace has no parent")
	}

	ns, ok = n.namespaces[path]
	if !ok {
		return nil, fmt.Errorf("cannot find namespace %q", path)
	}

	return ns, nil
}

func (n *TestNamespacer) TypeAllowed(ctx context.Context, ns *namespace.Namespace, ty string) error {
	if ns.Path == namespace.RootNamespace.Path {
		return nil
	}

	segments := strings.SplitAfter(ns.Path, "/")
	segments = segments[:len(segments)-1]

	var path string
	for _, segment := range segments {
		path += segment
		ns, ok := n.namespaces[path]
		if !ok {
			return fmt.Errorf("cannot find namespace %q", path)
		}

		if !slices.Contains(ns.ExternalKeyTypes, ty) {
			return fmt.Errorf("namespace %q cannot use key of this type", ns.Path)
		}
	}

	return nil
}

func TestRegistry(config ServerConfig) (*Registry, *TestNamespacer) {
	namespacer := NewTestNamespacer()
	registry := NewRegistry(hclog.Default(), config, namespacer)
	return registry, namespacer
}
