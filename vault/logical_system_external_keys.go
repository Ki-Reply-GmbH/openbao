// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"net/http"
	"path"
	"strings"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/vault/extkey"
)

func (b *SystemBackend) externalKeyPaths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "external-keys/configs/?",

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "external-keys",
				OperationSuffix: "configs",
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.handleExternalKeysConfigList,
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: http.StatusText(http.StatusOK),
							Fields: map[string]*framework.FieldSchema{
								"keys": {
									Type:        framework.TypeStringSlice,
									Description: "List of configuration names",
								},
							},
						}},
					},
					Summary: "List configs.",
				},
			},

			HelpSynopsis:    "List configs.",
			HelpDescription: strings.TrimSpace(sysExternalKeysHelp["list-configs"]),
		},

		{
			Pattern: "external-keys/configs/" + framework.GenericNameRegex("config"),

			Fields: map[string]*framework.FieldSchema{
				"config": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "Name of the config.",
				},
				"provider": {
					Type:        framework.TypeString,
					Required:    false,
					Description: "Name of the KMS provider.",
				},
			},

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "external-keys",
				OperationSuffix: "configs",
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleExternalKeysConfigRead,
					Responses: map[int][]framework.Response{
						http.StatusOK: {{Description: http.StatusText(http.StatusOK)}},
					},
					Summary: "Read a config.",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleExternalKeysConfigWrite,
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{Description: http.StatusText(http.StatusNoContent)}},
					},
					Summary: "Create or update a config.",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handleExternalKeysConfigDelete,
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{Description: http.StatusText(http.StatusNoContent)}},
					},
					Summary: "Remove a config.",
				},
			},

			HelpSynopsis:    "Manage configs.",
			HelpDescription: strings.TrimSpace(sysExternalKeysHelp["manage-configs"]),
		},

		{
			Pattern: "external-keys/configs/" + framework.GenericNameRegex("config") + "/keys/?",

			Fields: map[string]*framework.FieldSchema{
				"config": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "Name of the config.",
				},
			},

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "external-keys",
				OperationSuffix: "keys",
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.handleExternalKeysKeyList,
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: http.StatusText(http.StatusOK),
							Fields: map[string]*framework.FieldSchema{
								"keys": {
									Type:        framework.TypeStringSlice,
									Description: "List of key names",
								},
							},
						}},
					},
					Summary: "List keys.",
				},
			},

			HelpSynopsis:    "List keys.",
			HelpDescription: strings.TrimSpace(sysExternalKeysHelp["list-keys"]),
		},

		{
			Pattern: "external-keys/configs/" + framework.GenericNameRegex("config") +
				"/keys/" + framework.GenericNameRegex("key"),

			Fields: map[string]*framework.FieldSchema{
				"config": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "Name of the config.",
				},
				"key": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "Name of the key.",
				},
			},

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "external-keys",
				OperationSuffix: "keys",
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleExternalKeysKeyRead,
					Responses: map[int][]framework.Response{
						http.StatusOK: {{Description: http.StatusText(http.StatusOK)}},
					},
					Summary: "Read a key.",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleExternalKeysKeyWrite,
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{Description: http.StatusText(http.StatusNoContent)}},
					},
					Summary: "Create or update a key.",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handleExternalKeysKeyDelete,
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{Description: http.StatusText(http.StatusNoContent)}},
					},
					Summary: "Remove a key.",
				},
			},

			HelpSynopsis:    "Manage keys.",
			HelpDescription: strings.TrimSpace(sysExternalKeysHelp["manage-keys"]),
		},

		{
			Pattern: "external-keys/configs/" + framework.GenericNameRegex("config") +
				"/keys/" + framework.GenericNameRegex("key") + "/grants/?",

			Fields: map[string]*framework.FieldSchema{
				"config": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "Name of the config.",
				},
				"key": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "Name of the key.",
				},
			},

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "external-keys",
				OperationSuffix: "grants",
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.handleExternalKeysGrantList,
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: http.StatusText(http.StatusOK),
							Fields: map[string]*framework.FieldSchema{
								"keys": {
									Type:        framework.TypeStringSlice,
									Description: "List of grant paths",
								},
							},
						}},
					},
					Summary: "List grants.",
				},
			},

			HelpSynopsis:    "List grants.",
			HelpDescription: strings.TrimSpace(sysExternalKeysHelp["list-grants"]),
		},

		{
			Pattern: "external-keys/configs/" + framework.GenericNameRegex("config") +
				"/keys/" + framework.GenericNameRegex("key") + "/grants/(?P<mount>.+)",

			Fields: map[string]*framework.FieldSchema{
				"config": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "Name of the config.",
				},
				"key": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "Name of the key.",
				},
				"mount": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "Path of the mount.",
				},
			},

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "external-keys",
				OperationSuffix: "grants",
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleExternalKeysGrantAdd,
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{Description: http.StatusText(http.StatusNoContent)}},
					},
					Summary: "Create a grant.",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handleExternalKeysGrantRemove,
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{Description: http.StatusText(http.StatusNoContent)}},
					},
					Summary: "Remove a grant.",
				},
			},

			HelpSynopsis:    "Manage grants.",
			HelpDescription: strings.TrimSpace(sysExternalKeysHelp["manage-grants"]),
		},
	}
}

// LIST /sys/external-keys/configs
func (b *SystemBackend) handleExternalKeysConfigList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	keys, err := req.Storage.List(ctx, extkey.KMSConfigPath)
	if err != nil {
		return handleError(err)
	}
	return logical.ListResponse(keys), nil
}

// GET /sys/external-keys/configs/:config-name
func (b *SystemBackend) handleExternalKeysConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("config").(string)
	config, err := extkey.ReadKMSConfig(ctx, req.Storage, path.Join(extkey.KMSConfigPath, name))
	switch {
	case err != nil:
		return handleError(err)
	case config == nil:
		return nil, nil
	}
	return &logical.Response{Data: config.AsMap()}, nil
}

// PUT /sys/external-keys/configs/:config-name
func (b *SystemBackend) handleExternalKeysConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return nil, nil
}

// DELETE /sys/external-keys/configs/:config-name
func (b *SystemBackend) handleExternalKeysConfigDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("config").(string)

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	defer b.Core.externalKeys.Lock(ns.Path)()

	// First, delete all key entries.
	view := logical.NewStorageView(req.Storage, path.Join(extkey.KeyConfigPath, name))
	if err := logical.ClearViewWithLogging(ctx, view, b.logger); err != nil {
		return handleError(err)
	}

	// Then delete the config entry itself.
	if err := req.Storage.Delete(ctx, path.Join(extkey.KMSConfigPath, name)); err != nil {
		return handleError(err)
	}

	return nil, nil
}

// LIST /sys/external-keys/configs/:config-name/keys
func (b *SystemBackend) handleExternalKeysKeyList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	keys, err := req.Storage.List(ctx, path.Join(extkey.KeyConfigPath, d.Get("config").(string))+"/")
	if err != nil {
		return handleError(err)
	}
	return logical.ListResponse(keys), nil
}

// GET /sys/external-keys/configs/:config-name/keys/:key-name
func (b *SystemBackend) handleExternalKeysKeyRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	configName, keyName := d.Get("config").(string), d.Get("key").(string)
	config, err := extkey.ReadKeyConfig(ctx, req.Storage, path.Join(extkey.KeyConfigPath, configName, keyName))
	switch {
	case err != nil:
		return handleError(err)
	case config == nil:
		return nil, logical.CodedError(http.StatusNotFound, "key %q not found", keyName)
	}
	return &logical.Response{Data: config.ConfigMap}, nil
}

// PUT /sys/external-keys/configs/:config-name/keys/:key-name
func (b *SystemBackend) handleExternalKeysKeyWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return nil, nil
}

// DELETE /sys/external-keys/configs/:config-name/keys/:key-name
func (b *SystemBackend) handleExternalKeysKeyDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(
		ctx,
		path.Join(extkey.KeyConfigPath, d.Get("config").(string), d.Get("key").(string)),
	); err != nil {
		return handleError(err)
	}
	return nil, nil
}

// LIST /sys/external-keys/configs/:config-name/keys/:key-name/grants
func (b *SystemBackend) handleExternalKeysGrantList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return nil, nil
}

// PUT /sys/external-keys/configs/:config-name/keys/:key-name/grants/:mount-path
func (b *SystemBackend) handleExternalKeysGrantAdd(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return nil, nil
}

// DELETE /sys/external-keys/configs/:config-name/keys/:key-name/grants/:mount-path
func (b *SystemBackend) handleExternalKeysGrantRemove(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return nil, nil
}

var sysExternalKeysHelp = map[string]string{
	"list-configs": `
This path responds to the following HTTP methods.

	LIST /configs
		List configs.
`,
	"manage-configs": `
This path responds to the following HTTP methods.

	GET /configs/<config>
		Read a config.

	PUT /configs/<config>
		Create or update a config.

	DELETE /configs/<config>
		Remove a config.
`,
	"list-keys": `
This path responds to the following HTTP methods.

	LIST /configs/<config>/keys
		List keys.
`,
	"manage-keys": `
This path responds to the following HTTP methods.

	GET /configs/<config>/keys/<key>
		Read a key.

	PUT /configs/<config>/keys/<key>
		Create or update a key.

	DELETE /configs/<config>/keys/<key>
		Remove a key.
`,
	"list-grants": `
This path responds to the following HTTP methods.

	LIST /configs/<config>/keys/<key>/grants
		List grants.
`,
	"manage-grants": `
This path responds to the following HTTP methods.

	PUT /configs/<config>/keys/<key>/grants/<mount>
		Create a grant.

	DELETE /configs/<config>/keys/<key>/grants/<mount>
		Remove a grant.
`,
}
