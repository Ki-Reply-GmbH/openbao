// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// CreateNamespaceInput is the input for the CreateNamespace operation.
type CreateNamespaceInput struct {
	CustomMetadata map[string]string `json:"custom_metadata"`
}

// CreateNamespaceResponse is the response from the CreateNamespace operation.
type CreateNamespaceResponse struct {
	UUID           string            `json:"uuid"`
	ID             string            `json:"id"`
	Path           string            `json:"path"`
	Tainted        bool              `json:"tainted"`
	Locked         bool              `json:"locked"`
	CustomMetadata map[string]string `json:"custom_metadata"`
	KeyShares      []string          `json:"key_shares"`
}

// ReadNamespaceResponse is the response from the ReadNamespace operation.
type ReadNamespaceResponse struct {
	UUID           string            `json:"uuid"`
	ID             string            `json:"id"`
	Path           string            `json:"path"`
	Tainted        bool              `json:"tainted"`
	Locked         bool              `json:"locked"`
	CustomMetadata map[string]string `json:"custom_metadata"`
	KeyShares      []string          `json:"key_shares"`
}

// DeleteNamespaceResponse is the response from the DeleteNamespace operation.
type DeleteNamespaceResponse struct {
	Status string `json:"status"`
}

// PatchNamespaceInput is the input for the PatchNamespace operation.
// CustomMetadata values can be nil to remove a key.
type PatchNamespaceInput struct {
	CustomMetadata map[string]interface{} `json:"custom_metadata"`
}

// PatchNamespaceResponse is the response from the PatchNamespace operation.
type PatchNamespaceResponse struct {
	UUID           string            `json:"uuid"`
	ID             string            `json:"id"`
	Path           string            `json:"path"`
	Tainted        bool              `json:"tainted"`
	Locked         bool              `json:"locked"`
	CustomMetadata map[string]string `json:"custom_metadata"`
	KeyShares      []string          `json:"key_shares"`
}

// ListNamespacesResponse is the response from the ListNamespaces operation.
type ListNamespacesResponse struct {
	Keys    []string                         `json:"keys"`
	KeyInfo map[string]ReadNamespaceResponse `json:"key_info"`
}

// ListNamespaces lists all child namespaces relative to the current namespace.
func (c *Sys) ListNamespaces() (*ListNamespacesResponse, error) {
	return c.ListNamespacesWithContext(context.Background())
}

// ListNamespacesWithContext lists all child namespaces relative to the current namespace.
func (c *Sys) ListNamespacesWithContext(ctx context.Context) (*ListNamespacesResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, "/v1/sys/namespaces/")
	r.Params.Set("list", "true")

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck

	secret, err := ParseSecret(resp.Body)
	if err != nil {
		return nil, err
	}
	if secret == nil || secret.Data == nil {
		return nil, errors.New("data from server response is empty")
	}

	dataJSON, err := json.Marshal(secret.Data)
	if err != nil {
		return nil, err
	}
	result := &ListNamespacesResponse{}
	if err := json.Unmarshal(dataJSON, result); err != nil {
		return nil, err
	}
	return result, nil
}

// CreateNamespace creates a new namespace at the given path.
func (c *Sys) CreateNamespace(path string, i *CreateNamespaceInput) (*CreateNamespaceResponse, error) {
	return c.CreateNamespaceWithContext(context.Background(), path, i)
}

// CreateNamespaceWithContext creates a new namespace at the given path.
func (c *Sys) CreateNamespaceWithContext(ctx context.Context, path string, i *CreateNamespaceInput) (*CreateNamespaceResponse, error) {
	if path == "" {
		return nil, errors.New("path must not be empty")
	}
	if i == nil {
		i = &CreateNamespaceInput{}
	}

	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodPost, fmt.Sprintf("/v1/sys/namespaces/%s", path))
	if err := r.SetJSONBody(i); err != nil {
		return nil, err
	}

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck

	var result struct {
		Data *CreateNamespaceResponse
	}
	if err := resp.DecodeJSON(&result); err != nil {
		return nil, err
	}
	return result.Data, nil
}

// PatchNamespace updates the metadata of an existing namespace at the given path.
func (c *Sys) PatchNamespace(path string, i *PatchNamespaceInput) (*PatchNamespaceResponse, error) {
	return c.PatchNamespaceWithContext(context.Background(), path, i)
}

// PatchNamespaceWithContext updates the metadata of an existing namespace at the given path.
func (c *Sys) PatchNamespaceWithContext(ctx context.Context, path string, i *PatchNamespaceInput) (*PatchNamespaceResponse, error) {
	if path == "" {
		return nil, errors.New("path must not be empty")
	}
	if i == nil {
		return nil, errors.New("input must not be nil")
	}

	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodPatch, fmt.Sprintf("/v1/sys/namespaces/%s", path))
	r.Headers.Set("Content-Type", "application/merge-patch+json")
	if err := r.SetJSONBody(i); err != nil {
		return nil, err
	}

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck

	var result struct {
		Data *PatchNamespaceResponse
	}
	if err := resp.DecodeJSON(&result); err != nil {
		return nil, err
	}
	return result.Data, nil
}

// DeleteNamespace removes the namespace at the given path.
func (c *Sys) DeleteNamespace(path string) (*DeleteNamespaceResponse, error) {
	return c.DeleteNamespaceWithContext(context.Background(), path)
}

// DeleteNamespaceWithContext removes the namespace at the given path.
func (c *Sys) DeleteNamespaceWithContext(ctx context.Context, path string) (*DeleteNamespaceResponse, error) {
	if path == "" {
		return nil, errors.New("path must not be empty")
	}

	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodDelete, fmt.Sprintf("/v1/sys/namespaces/%s", path))

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck

	var result struct {
		Data *DeleteNamespaceResponse
	}
	if err := resp.DecodeJSON(&result); err != nil {
		return nil, err
	}
	return result.Data, nil
}

// ReadNamespace returns information about the namespace at the given path.
func (c *Sys) ReadNamespace(path string) (*ReadNamespaceResponse, error) {
	return c.ReadNamespaceWithContext(context.Background(), path)
}

// ReadNamespaceWithContext returns information about the namespace at the given path.
func (c *Sys) ReadNamespaceWithContext(ctx context.Context, path string) (*ReadNamespaceResponse, error) {
	if path == "" {
		return nil, errors.New("path must not be empty")
	}

	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, fmt.Sprintf("/v1/sys/namespaces/%s", path))

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if resp != nil {
		defer resp.Body.Close() //nolint:errcheck
		if resp.StatusCode == http.StatusNotFound {
			return nil, nil
		}
	}
	if err != nil {
		return nil, err
	}

	var result struct {
		Data *ReadNamespaceResponse
	}
	if err := resp.DecodeJSON(&result); err != nil {
		return nil, err
	}
	return result.Data, nil
}
