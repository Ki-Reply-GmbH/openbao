// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-viper/mapstructure/v2"
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
type ReadNamespaceResponse = CreateNamespaceResponse

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
type PatchNamespaceResponse = CreateNamespaceResponse

// ListNamespaces lists all child namespaces relative to the current namespace.
func (c *Sys) ListNamespaces() (map[string]ReadNamespaceResponse, error) {
	return c.ListNamespacesWithContext(context.Background())
}

// ListNamespacesWithContext lists all child namespaces relative to the current namespace.
func (c *Sys) ListNamespacesWithContext(ctx context.Context) (map[string]ReadNamespaceResponse, error) {
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

	keyInfoRaw, ok := secret.Data["key_info"]
	if !ok {
		return map[string]ReadNamespaceResponse{}, nil
	}

	result := map[string]ReadNamespaceResponse{}
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		TagName: "json",
		Result:  &result,
	})
	if err != nil {
		return nil, err
	}
	if err := decoder.Decode(keyInfoRaw); err != nil {
		return nil, err
	}
	return result, nil
}

// CreateNamespace creates a new namespace with the given name.
func (c *Sys) CreateNamespace(name string, i *CreateNamespaceInput) (*CreateNamespaceResponse, error) {
	return c.CreateNamespaceWithContext(context.Background(), name, i)
}

// CreateNamespaceWithContext creates a new namespace with the given name.
func (c *Sys) CreateNamespaceWithContext(ctx context.Context, name string, i *CreateNamespaceInput) (*CreateNamespaceResponse, error) {
	if name == "" {
		return nil, errors.New("name must not be empty")
	}
	if i == nil {
		i = &CreateNamespaceInput{}
	}

	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodPost, fmt.Sprintf("/v1/sys/namespaces/%s", name))
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

// PatchNamespace updates the metadata of an existing namespace with the given name.
func (c *Sys) PatchNamespace(name string, i *PatchNamespaceInput) (*PatchNamespaceResponse, error) {
	return c.PatchNamespaceWithContext(context.Background(), name, i)
}

// PatchNamespaceWithContext updates the metadata of an existing namespace with the given name.
func (c *Sys) PatchNamespaceWithContext(ctx context.Context, name string, i *PatchNamespaceInput) (*PatchNamespaceResponse, error) {
	if name == "" {
		return nil, errors.New("name must not be empty")
	}
	if i == nil {
		return nil, errors.New("input must not be nil")
	}

	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodPatch, fmt.Sprintf("/v1/sys/namespaces/%s", name))
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

// DeleteNamespace removes the namespace with the given name.
func (c *Sys) DeleteNamespace(name string) (*DeleteNamespaceResponse, error) {
	return c.DeleteNamespaceWithContext(context.Background(), name)
}

// DeleteNamespaceWithContext removes the namespace with the given name.
func (c *Sys) DeleteNamespaceWithContext(ctx context.Context, name string) (*DeleteNamespaceResponse, error) {
	if name == "" {
		return nil, errors.New("name must not be empty")
	}

	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodDelete, fmt.Sprintf("/v1/sys/namespaces/%s", name))

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

// ReadNamespace returns information about the namespace with the given name.
func (c *Sys) ReadNamespace(name string) (*ReadNamespaceResponse, error) {
	return c.ReadNamespaceWithContext(context.Background(), name)
}

// ReadNamespaceWithContext returns information about the namespace with the given name.
func (c *Sys) ReadNamespaceWithContext(ctx context.Context, name string) (*ReadNamespaceResponse, error) {
	if name == "" {
		return nil, errors.New("name must not be empty")
	}

	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, fmt.Sprintf("/v1/sys/namespaces/%s", name))

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
