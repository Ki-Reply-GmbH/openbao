// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"net/http"
	"strings"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
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
				"config": &framework.FieldSchema{
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
				"config": &framework.FieldSchema{
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
				"config": &framework.FieldSchema{
					Type:        framework.TypeString,
					Required:    true,
					Description: "Name of the config.",
				},
				"key": &framework.FieldSchema{
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
				"config": &framework.FieldSchema{
					Type:        framework.TypeString,
					Required:    true,
					Description: "Name of the config.",
				},
				"key": &framework.FieldSchema{
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
				"config": &framework.FieldSchema{
					Type:        framework.TypeString,
					Required:    true,
					Description: "Name of the config.",
				},
				"key": &framework.FieldSchema{
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
	return nil, nil
}

// GET /sys/external-keys/configs/:config-name
func (b *SystemBackend) handleExternalKeysConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return nil, nil
}

// PUT /sys/external-keys/configs/:config-name
func (b *SystemBackend) handleExternalKeysConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return nil, nil
}

// DELETE /sys/external-keys/configs/:config-name
func (b *SystemBackend) handleExternalKeysConfigDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return nil, nil
}

// LIST /sys/external-keys/configs/:config-name/keys
func (b *SystemBackend) handleExternalKeysKeyList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return nil, nil
}

// GET /sys/external-keys/configs/:config-name/keys/:key-name
func (b *SystemBackend) handleExternalKeysKeyRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return nil, nil
}

// PUT /sys/external-keys/configs/:config-name/keys/:key-name
func (b *SystemBackend) handleExternalKeysKeyWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return nil, nil
}

// DELETE /sys/external-keys/configs/:config-name/keys/:key-name
func (b *SystemBackend) handleExternalKeysKeyDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
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
