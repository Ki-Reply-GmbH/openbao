package vault

import (
	"errors"
	"fmt"
	"strings"

	"github.com/openbao/openbao/helper/namespace"
)

// namespaceTree represents a tree structure for efficient namespace path lookups.
// IMPORTANT: This structure is NOT thread-safe on its own and must be protected
// by the NamespaceStore's lock when being accessed or modified.
type namespaceTree struct {
	root *namespaceNode
}

type namespaceNode struct {
	parent      *namespaceNode
	descendants int
	children    map[string]*namespaceNode
	entry       *NamespaceEntry
}

// newNamespaceTree creates a new namespaceTree with the given NamespaceEntry as
// root namespace
func newNamespaceTree(root *NamespaceEntry) *namespaceTree {
	node := &namespaceNode{
		entry:    root,
		children: make(map[string]*namespaceNode),
	}
	return &namespaceTree{
		root: node,
	}
}

// Get returns the namespace at a given path
func (nt *namespaceTree) Get(path string) (*NamespaceEntry, bool) {
	path = namespace.Canonicalize(path)
	var segments []string
	if path != "" {
		segments = strings.SplitAfter(path, "/")
		segments = segments[:len(segments)-1]
	}
	node := nt.root
	for _, segment := range segments {
		n, ok := node.children[segment]
		if !ok {
			return nil, false
		}

		node = n
	}

	return node.entry, true
}

// LongestPrefix finds the longest prefix of path that leads to a namespace
// entry. It returns the path to the namespace, the namespace entry and the
// remaining part of the input path.
func (nt *namespaceTree) LongestPrefix(path string) (string, *NamespaceEntry, string) {
	cpath := namespace.Canonicalize(path)
	var segments []string
	if path != "" {
		segments = strings.SplitAfter(cpath, "/")
		segments = segments[:len(segments)-1]
	}
	node := nt.root
	for i := range segments {
		n, ok := node.children[segments[i]]
		if !ok {
			break
		}

		node = n
	}

	namespacePrefix := node.entry.Namespace.Path
	pathSuffix := strings.TrimPrefix(path, namespacePrefix)
	return namespacePrefix, node.entry, pathSuffix
}

// List lists child Namespace entries at a given path, optionally including the
// namespace at the given path, optionally recursing down into all child
// namespaces.
func (nt *namespaceTree) List(path string, includeParent bool, recursive bool) ([]*NamespaceEntry, error) {
	path = namespace.Canonicalize(path)
	var segments []string
	if path != "" {
		segments = strings.SplitAfter(path, "/")
		segments = segments[:len(segments)-1]
	}
	node := nt.root
	for i, segment := range segments {
		n, ok := node.children[segment]
		if !ok {
			return nil, fmt.Errorf("unknown path: %s", namespace.Canonicalize(strings.Join(segments[:i], "/")))
		}

		node = n
	}

	numNodes := len(node.children)
	if recursive {
		numNodes = node.descendants
	}
	nodes := make([]*namespaceNode, 0, numNodes+1)
	nodes = append(nodes, node)
	entries := make([]*NamespaceEntry, 0, numNodes)
	if includeParent {
		entries = append(entries, node.entry)
	}

	for idx := 0; idx < len(nodes); idx++ {
		node = nodes[idx]
		for _, child := range node.children {
			entries = append(entries, child.entry.Clone())
			if recursive {
				nodes = append(nodes, child)
			}
		}
	}

	return entries, nil
}

// Insert adds or updates the namespace with the given entry. It refuses to add
// the namespace if the parent namespace does not exist in the tree.
func (nt *namespaceTree) Insert(entry *NamespaceEntry) error {
	path := namespace.Canonicalize(entry.Namespace.Path)
	if path == "" {
		return errors.New("can't insert root namespace")
	}
	segments := strings.SplitAfter(path, "/")
	segments = segments[:len(segments)-1]
	l := len(segments)
	node := nt.root
	nodes := make([]*namespaceNode, 0, l)
	for i, segment := range segments {
		nodes = append(nodes, node)
		n, ok := node.children[segment]
		if !ok {
			if i != l-1 {
				return errors.New("can't insert namespace with missing parent")
			}
			node.children[segment] = &namespaceNode{
				parent:   node,
				children: make(map[string]*namespaceNode),
				entry:    entry,
			}
			for _, node := range nodes {
				node.descendants += 1
			}
			return nil
		}

		node = n
	}

	node.entry = entry

	return nil
}

// Delete removes a namespace from the tree using the path. The delete is not
// cascading and refuses to remove namespaces with existing children.
func (nt *namespaceTree) Delete(path string) error {
	path = namespace.Canonicalize(path)
	if path == "" {
		return errors.New("can't delete root namespace")
	}
	segments := strings.SplitAfter(path, "/")
	segments = segments[:len(segments)-1]
	node := nt.root
	nodes := make([]*namespaceNode, 0, len(segments))
	for _, segment := range segments {
		nodes = append(nodes, node)
		n, ok := node.children[segment]
		if !ok {
			return nil
		}

		node = n
	}

	if len(node.children) > 0 {
		return errors.New("can't delete namespace with children")
	}

	delete(node.parent.children, segments[len(segments)-1])
	for _, node := range nodes {
		node.descendants -= 1
	}

	return nil
}

// validate validates that all nodes in the tree have entry set
func (nt *namespaceTree) validate() error {
	nodes := make([]*namespaceNode, 0, nt.size())
	nodes = append(nodes, nt.root)

	var errs []error

	for idx := 0; idx < len(nodes); idx++ {
		node := nodes[idx]
		desc := node.descendants
		calcDesc := 0
		for _, child := range node.children {
			if node.entry == nil {
				errs = append(errs, fmt.Errorf("orphan namespace found: %s", child.entry.Namespace.Path))
			}
			calcDesc += child.descendants + 1
			nodes = append(nodes, child)
		}
		if desc != calcDesc {
			errs = append(errs, fmt.Errorf("node descendant calculation is wrong. Expected %d, found %d", desc, calcDesc))
		}
	}

	return errors.Join(errs...)
}

func (nt *namespaceTree) size() int {
	return nt.root.descendants + 1
}

// unsafeInsert performs an unsafe insert of the namespace entry. It will create
// any intermediate tree entries as necessary and will not perform validation of
// the tree. You MUST call validate yourself when done inserting.
func (nt *namespaceTree) unsafeInsert(entry *NamespaceEntry) {
	segments := strings.SplitAfter(entry.Namespace.Path, "/")
	segments = segments[:len(segments)-1]
	node := nt.root
	nodes := make([]*namespaceNode, 0, len(segments))

	for _, segment := range segments {
		nodes = append(nodes, node)
		n, ok := node.children[segment]
		if !ok {
			child := &namespaceNode{
				parent:   node,
				children: make(map[string]*namespaceNode),
			}
			node.children[segment] = child
			node = child
			for _, node := range nodes {
				node.descendants += 1
			}
			continue
		}

		node = n
	}
	node.entry = entry
}
