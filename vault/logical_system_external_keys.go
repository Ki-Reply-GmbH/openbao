package vault

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	externalkeys "github.com/openbao/openbao/vault/external_keys"
)

func (b *SystemBackend) externalKeyPaths() []*framework.Path {
	fieldConfig := &framework.FieldSchema{
		Type:        framework.TypeString,
		Required:    true,
		Description: "Name of the config.",
	}

	fieldKey := &framework.FieldSchema{
		Type:        framework.TypeString,
		Required:    true,
		Description: "Name of the key.",
	}

	fieldMount := &framework.FieldSchema{
		Type:        framework.TypeString,
		Required:    true,
		Description: "Path of the mount.",
	}

	return []*framework.Path{
		{
			Pattern: "external-keys/configs/?",

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "external-keys",
				OperationSuffix: "configs",
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.handleExternalKeysConfigList(),
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
				"config": fieldConfig,
			},

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "external-keys",
				OperationSuffix: "configs",
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleExternalKeysConfigRead(),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{Description: http.StatusText(http.StatusOK)}},
					},
					Summary: "Read a config.",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleExternalKeysConfigWrite(),
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{Description: http.StatusText(http.StatusNoContent)}},
					},
					Summary: "Create or overwrite a config.",
				},
				logical.PatchOperation: &framework.PathOperation{
					Callback: b.handleExternalKeysConfigPatch(),
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{Description: http.StatusText(http.StatusNoContent)}},
					},
					Summary: "Patch a config.",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handleExternalKeysConfigDelete(),
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
				"config": fieldConfig,
			},

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "external-keys",
				OperationSuffix: "keys",
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.handleExternalKeysKeyList(),
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
				"config": fieldConfig, "key": fieldKey,
			},

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "external-keys",
				OperationSuffix: "keys",
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleExternalKeysKeyRead(),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{Description: http.StatusText(http.StatusOK)}},
					},
					Summary: "Read a key.",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleExternalKeysKeyWrite(),
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{Description: http.StatusText(http.StatusNoContent)}},
					},
					Summary: "Create or overwrite a key.",
				},
				logical.PatchOperation: &framework.PathOperation{
					Callback: b.handleExternalKeysKeyPatch(),
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{Description: http.StatusText(http.StatusNoContent)}},
					},
					Summary: "Update a key.",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handleExternalKeysKeyDelete(),
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
				"config": fieldConfig, "key": fieldKey,
			},

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "external-keys",
				OperationSuffix: "grants",
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.handleExternalKeysGrantList(),
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
				"config": fieldConfig, "key": fieldKey, "mount": fieldMount,
			},

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "external-keys",
				OperationSuffix: "grants",
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleExternalKeysGrantRead(),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{Description: http.StatusText(http.StatusNoContent)}},
					},
					Summary: "Check existence of a grant.",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleExternalKeysGrantWrite(),
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{Description: http.StatusText(http.StatusNoContent)}},
					},
					Summary: "Create a grant.",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handleExternalKeysGrantDelete(),
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
func (b *SystemBackend) handleExternalKeysConfigList() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		keys, err := b.Core.externalKeys.ListConfigs(ctx)
		if err != nil {
			return handleError(err)
		}

		return &logical.Response{
			Data: map[string]any{
				"keys": keys,
			},
		}, nil
	}
}

// GET /sys/external-keys/configs/<config>
func (b *SystemBackend) handleExternalKeysConfigRead() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		args := &externalkeys.Args{
			Config: data.Get("config").(string),
		}

		config, err := b.Core.externalKeys.ReadConfig(ctx, args)
		if err != nil {
			return handleError(err)
		}

		var resp logical.Response
		resp.Data = make(map[string]any)
		for k, v := range config.Values {
			resp.Data[k] = v
		}

		return &resp, nil
	}
}

// PUT /sys/external-keys/configs/<config>
func (b *SystemBackend) handleExternalKeysConfigWrite() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		args := &externalkeys.Args{
			Config: data.Get("config").(string),
		}

		callback := func(config *externalkeys.Config) error {
			return anyMapToStringMap(req.Data, config.Values)
		}

		if err := b.Core.externalKeys.UpdateConfig(ctx, args, true, callback); err != nil {
			return handleError(err)
		}

		return nil, nil
	}
}

// PATCH /sys/external-keys/configs/<config>
func (b *SystemBackend) handleExternalKeysConfigPatch() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		args := &externalkeys.Args{
			Config: data.Get("config").(string),
		}

		callback := func(config *externalkeys.Config) error {
			return mergePatchStringMap(config.Values, req.Data)
		}

		if err := b.Core.externalKeys.UpdateConfig(ctx, args, false, callback); err != nil {
			return handleError(err)
		}

		return nil, nil
	}
}

// DELETE /sys/external-keys/configs/<config>
func (b *SystemBackend) handleExternalKeysConfigDelete() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		args := &externalkeys.Args{
			Config: data.Get("config").(string),
		}

		if err := b.Core.externalKeys.DeleteConfig(ctx, args); err != nil {
			return handleError(err)
		}

		return nil, nil
	}
}

// LIST /sys/external-keys/configs/<config>/keys
func (b *SystemBackend) handleExternalKeysKeyList() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		args := &externalkeys.Args{
			Config: data.Get("config").(string),
		}

		keys, err := b.Core.externalKeys.ListKeys(ctx, args)
		if err != nil {
			return handleError(err)
		}

		return &logical.Response{
			Data: map[string]any{
				"keys": keys,
			},
		}, nil
	}
}

// GET /sys/external-keys/configs/<config>/keys/<key>
func (b *SystemBackend) handleExternalKeysKeyRead() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		args := &externalkeys.Args{
			Config: data.Get("config").(string),
			Key:    data.Get("key").(string),
		}

		key, err := b.Core.externalKeys.ReadKey(ctx, args)
		if err != nil {
			return handleError(err)
		}

		resp := &logical.Response{Data: make(map[string]any)}
		for k, v := range key.Values {
			resp.Data[k] = v
		}

		return resp, nil
	}
}

// PUT /sys/external-keys/configs/<config>/keys/<key>
func (b *SystemBackend) handleExternalKeysKeyWrite() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		args := &externalkeys.Args{
			Config: data.Get("config").(string),
			Key:    data.Get("key").(string),
		}

		callback := func(key *externalkeys.Key) error {
			return anyMapToStringMap(req.Data, key.Values)
		}

		if err := b.Core.externalKeys.UpdateKey(ctx, args, true, callback); err != nil {
			return handleError(err)
		}

		return nil, nil
	}
}

// PATCH /sys/external-keys/configs/<config>/keys/<key>
func (b *SystemBackend) handleExternalKeysKeyPatch() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		args := &externalkeys.Args{
			Config: data.Get("config").(string),
			Key:    data.Get("key").(string),
		}

		callback := func(key *externalkeys.Key) error {
			return mergePatchStringMap(key.Values, req.Data)
		}

		if err := b.Core.externalKeys.UpdateKey(ctx, args, false, callback); err != nil {
			return handleError(err)
		}

		return nil, nil
	}
}

// DELETE /sys/external-keys/configs/<config>/keys/<key>
func (b *SystemBackend) handleExternalKeysKeyDelete() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		args := &externalkeys.Args{
			Config: data.Get("config").(string),
			Key:    data.Get("key").(string),
		}

		if err := b.Core.externalKeys.DeleteKey(ctx, args); err != nil {
			return handleError(err)
		}

		return nil, nil
	}
}

// LIST /sys/external-keys/configs/<config>/keys/<key>/grants
func (b *SystemBackend) handleExternalKeysGrantList() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		args := &externalkeys.Args{
			Config: data.Get("config").(string),
			Key:    data.Get("key").(string),
		}

		key, err := b.Core.externalKeys.ReadKey(ctx, args)
		if err != nil {
			return handleError(err)
		}

		return &logical.Response{
			Data: map[string]any{
				"keys": key.Grants,
			},
		}, nil
	}
}

// GET /sys/external-keys/configs/<config>/keys/<key>/grants/<mount>
func (b *SystemBackend) handleExternalKeysGrantRead() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		args := &externalkeys.Args{
			Config: data.Get("config").(string),
			Key:    data.Get("key").(string),
			Mount:  data.Get("mount").(string),
		}

		key, err := b.Core.externalKeys.ReadKey(ctx, args)
		if err != nil {
			return handleError(err)
		}

		if !slices.Contains(key.Grants, args.Mount) {
			return nil, logical.CodedError(http.StatusNotFound, "grant not found")
		}

		return nil, nil
	}
}

// PUT /sys/external-keys/configs/<config>/keys/<key>/grants/<mount>
func (b *SystemBackend) handleExternalKeysGrantWrite() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		args := &externalkeys.Args{
			Config: data.Get("config").(string),
			Key:    data.Get("key").(string),
			Mount:  data.Get("mount").(string),
		}

		callback := func(key *externalkeys.Key) error {
			if !slices.Contains(key.Grants, args.Mount) {
				key.Grants = append(key.Grants, args.Mount)
			}
			return nil
		}

		if err := b.Core.externalKeys.UpdateKey(ctx, args, false, callback); err != nil {
			return handleError(err)
		}

		return nil, nil
	}
}

// DELETE /sys/external-keys/configs/<config>/keys/<key>/grants/<mount>
func (b *SystemBackend) handleExternalKeysGrantDelete() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		args := &externalkeys.Args{
			Config: data.Get("config").(string),
			Key:    data.Get("key").(string),
			Mount:  data.Get("mount").(string),
		}

		callback := func(key *externalkeys.Key) error {
			key.Grants = slices.DeleteFunc(key.Grants, func(mount string) bool {
				return mount == args.Mount
			})
			return nil
		}

		if err := b.Core.externalKeys.UpdateKey(ctx, args, false, callback); err != nil {
			return handleError(err)
		}

		return nil, nil
	}
}

func anyMapToStringMap(src map[string]any, dst map[string]string) error {
	for k, v := range src {
		str, ok := v.(string)
		if !ok {
			return fmt.Errorf("field '%s' is not a string", k)
		}
		dst[k] = str
	}
	return nil
}

func mergePatchStringMap(values map[string]string, patch map[string]any) error {
	for k, v := range patch {
		switch v := v.(type) {
		case string:
			values[k] = v
		case nil:
			delete(values, k)
		default:
			return fmt.Errorf("expected field '%s' to be a string", k)
		}
	}
	return nil
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
		Create or overwrite a config.

	PATCH /configs/<config>
		Patch a config.

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
		Create or overwrite a key.

	PATCH /configs/<config>/keys/<key>
		Patch a key.

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

	GET /configs/<config>/keys/<key>/grants/<mount>
		Check existence of a grant.

	PUT /configs/<config>/keys/<key>/grants/<mount>
		Create a grant.

	DELETE /configs/<config>/keys/<key>/grants/<mount>
		Remove a grant.
`,
}
