package vault

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/openbao/openbao/sdk/v2/physical"
)

// --- MOCK BACKEND (Isolated Test Implementation) ---
// We remove the dependency on 'physical/inmem' to avoid circular imports.

type MockPhysicalBackend struct {
	data map[string][]byte
	mu   sync.RWMutex
}

func NewMockBackend() *MockPhysicalBackend {
	return &MockPhysicalBackend{
		data: make(map[string][]byte),
	}
}

func (m *MockPhysicalBackend) Put(ctx context.Context, entry *physical.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[entry.Key] = entry.Value
	return nil
}

func (m *MockPhysicalBackend) Get(ctx context.Context, key string) (*physical.Entry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	val, ok := m.data[key]
	if !ok {
		// Standard pattern for "key not found" in physical backends.
		return nil, nil //nolint:nilnil
	}
	return &physical.Entry{Key: key, Value: val}, nil
}

func (m *MockPhysicalBackend) Delete(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
	return nil
}

func (m *MockPhysicalBackend) List(ctx context.Context, prefix string) ([]string, error) {
	return nil, nil // Not required for this specific test.
}

// ListPage satisfies the OpenBao SDK v2 physical backend interface.
func (m *MockPhysicalBackend) ListPage(ctx context.Context, prefix string, page string, limit int) ([]string, error) {
	return nil, nil
}

// --- FAULTY WRAPPER (For Error Injection) ---

// FaultyPhysicalBackend wraps a real backend but fails on Put if configured.
type FaultyPhysicalBackend struct {
	physical.Backend // Embedded backend implementation
	FailPut          bool
}

// Put intercepts the write and returns an error if FailPut is true.
func (f *FaultyPhysicalBackend) Put(ctx context.Context, entry *physical.Entry) error {
	if f.FailPut {
		return errors.New("simulated io error")
	}
	return f.Backend.Put(ctx, entry)
}

// --- ACTUAL TEST SUITE ---

func TestCore_SelfInit_StateTransition(t *testing.T) {
	// 0. Setup Context (Required for all backend calls).
	ctx := context.Background()

	// 1. Setup
	backend := NewMockBackend()
	core := &Core{
		physical: backend,
	}

	// PHASE 1: Clean Slate Verification
	// Ensure the system correctly identifies an uninitialized state.
	complete, err := core.IsSelfInitComplete(ctx)
	if err != nil {
		t.Fatalf("Unexpected error on empty storage: %v", err)
	}
	if complete {
		t.Fatal("SAFETY VIOLATION: Returned true (initialized) on empty storage")
	}

	// PHASE 2: State Transition
	// Attempt to mark initialization as complete.
	if err := core.MarkSelfInitComplete(ctx); err != nil {
		t.Fatalf("Write operation failed: %v", err)
	}

	// PHASE 3: Consistency Verification
	// Ensure the state is persistently reflected immediately after write.
	complete, err = core.IsSelfInitComplete(ctx)
	if err != nil {
		t.Fatalf("Read operation failed: %v", err)
	}
	if !complete {
		t.Fatal("CONSISTENCY VIOLATION: Returned false (uninitialized) after successful write")
	}

	// PHASE 4: Raw Integrity Check
	// Verify the actual bytes written to the backend match expectations.
	entry, _ := backend.Get(ctx, coreStatusSelfInit)
	if entry == nil {
		t.Fatalf("INTEGRITY VIOLATION: Key not found in storage")
	}
	if string(entry.Value) != "true" {
		t.Fatalf("INTEGRITY VIOLATION: Invalid payload written to storage")
	}
}

func TestCore_SelfInit_FaultInjection(t *testing.T) {
	// 0. Setup Context.
	ctx := context.Background()

	// Setup a faulty backend to simulate storage failure.
	faulty := &FaultyPhysicalBackend{
		Backend: NewMockBackend(),
		FailPut: true,
	}
	core := &Core{physical: faulty}

	// Ensure errors are propagated up the stack and not swallowed.
	if err := core.MarkSelfInitComplete(ctx); err == nil {
		t.Fatal("SAFETY VIOLATION: Swallowed critical storage error")
	}
}
