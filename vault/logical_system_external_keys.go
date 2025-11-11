// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/vault/extkey"
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
				"config": fieldConfig,
				"provider": {
					Type:        framework.TypeString,
					Required:    false,
					Description: "Name of the external keys provider.",
				},
				"inherits": {
					Type:        framework.TypeString,
					Required:    false,
					Description: "Name of the config to inherit from the parent namespace.",
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
					Summary: "Create or overwrite a config.",
				},
				logical.PatchOperation: &framework.PathOperation{
					Callback: b.handleExternalKeysConfigPatch,
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{Description: http.StatusText(http.StatusNoContent)}},
					},
					Summary: "Patch a config.",
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
				"config": fieldConfig,
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
				"config": fieldConfig, "key": fieldKey,
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
					Summary: "Create or overwrite a key.",
				},
				logical.PatchOperation: &framework.PathOperation{
					Callback: b.handleExternalKeysKeyPatch,
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{Description: http.StatusText(http.StatusNoContent)}},
					},
					Summary: "Update a key.",
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
				"config": fieldConfig, "key": fieldKey,
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
				"config": fieldConfig, "key": fieldKey,
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

		{
			Pattern: "external-keys/configs/" + framework.GenericNameRegex("config") +
				"/keys/" + framework.GenericNameRegex("key") + "/test/sign",

			Fields: map[string]*framework.FieldSchema{
				"config": fieldConfig, "key": fieldKey,
			},

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "external-keys",
				OperationSuffix: "test",
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleExternalKeysTestSign,
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{Description: http.StatusText(http.StatusNoContent)}},
					},
					Summary: "Test sign a random message and verify the result.",
				},
			},

			HelpSynopsis:    "Test sign/verify.",
			HelpDescription: strings.TrimSpace(sysExternalKeysHelp["test-sign"]),
		},
	}
}

// LIST /sys/external-keys/configs
func (b *SystemBackend) handleExternalKeysConfigList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	keys, err := req.Storage.List(ctx, extkey.ConfigsPath)
	if err != nil {
		return handleError(err)
	}

	return logical.ListResponse(keys), nil
}

// GET /sys/external-keys/configs/:config-name
func (b *SystemBackend) handleExternalKeysConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("config").(string)
	config, exists, err := extkey.ReadConfig(ctx, req.Storage, extkey.ConfigPath(name))
	switch {
	case err != nil:
		return handleError(err)
	case !exists:
		return nil, logical.CodedError(http.StatusNotFound, "config %q not found", name)
	}

	return &logical.Response{Data: config.ToMap()}, nil
}

// PUT /sys/external-keys/configs/:config-name
func (b *SystemBackend) handleExternalKeysConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	config := &extkey.Config{
		Values:   maps.Clone(req.Data),
		Provider: d.GetWithExplicitDefault("provider", "").(string),
		Inherits: d.GetWithExplicitDefault("inherits", "").(string),
	}

	delete(config.Values, "inherits")
	delete(config.Values, "provider")

	if err := config.Validate(); err != nil {
		return handleError(err)
	}

	name := d.Get("config").(string)

	unlock, invalidate := b.Core.externalKeys.LockStorage(ctx, name)
	defer unlock()

	path := extkey.ConfigPath(name)
	prev, exists, err := extkey.ReadConfig(ctx, req.Storage, path)
	switch {
	case err != nil:
		return handleError(err)
	case exists:
		// Edge cases when mutating an existing config:
		if prev.Provider != "" && config.Inherits != "" {
			return handleError(errors.New("conversion to inherited config is forbidden"))
		}
	}

	if config.Inherits != "" {
		// Write back to storage.
		if err := extkey.WriteConfig(ctx, req.Storage, path, config); err != nil {
			return handleError(err)
		}
		return nil, nil
	}

	if config.Provider != "" {
		p, err := b.Core.externalKeys.GetProvider(config.Provider)
		if err != nil {
			return handleError(err)
		}
		config.Values, err = p.ParseConfigData(config.Values, true)
		if err != nil {
			return handleError(err)
		}
	}

	// Write back to storage.
	if err := extkey.WriteConfig(ctx, req.Storage, path, config); err != nil {
		return handleError(err)
	}

	invalidate()

	return nil, nil
}

// PATCH /sys/external-keys/configs/:config-name
func (b *SystemBackend) handleExternalKeysConfigPatch(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("config").(string)

	unlock, invalidate := b.Core.externalKeys.LockStorage(ctx, name)
	defer unlock()

	// The config must already exist.
	path := extkey.ConfigPath(name)
	prev, exists, err := extkey.ReadConfig(ctx, req.Storage, path)
	switch {
	case err != nil:
		return handleError(err)
	case !exists:
		return nil, logical.CodedError(http.StatusNotFound, "config %q not found", name)
	}

	input := &framework.FieldData{
		Raw: req.Data,
		Schema: map[string]*framework.FieldSchema{
			"provider": {Type: framework.TypeString},
			"inherits": {Type: framework.TypeString},
		},
	}

	var p *extkey.Provider

	// Get the "next" provider's schema if we're changing providers, else use
	// the existing one, if any.
	if provider, ok := d.GetOk("provider"); ok {
		p, err = b.Core.externalKeys.GetProvider(provider.(string))
	} else if prev.Provider != "" {
		p, err = b.Core.externalKeys.GetProvider(prev.Provider)
		if err != nil {
			return handleError(err)
		}
	}

	switch {
	case err != nil:
		return handleError(err)
	case p != nil:
		maps.Copy(input.Schema, p.ConfigSchema)
	}

	patched, err := framework.HandlePatchOperation(input, prev.ToMap(), nil)
	if err != nil {
		return handleError(err)
	}

	output := &framework.FieldData{Schema: d.Schema}
	if err := json.Unmarshal(patched, &output.Raw); err != nil {
		return handleError(err)
	}

	config := &extkey.Config{
		Values:   output.Raw,
		Provider: output.GetWithExplicitDefault("provider", "").(string),
		Inherits: output.GetWithExplicitDefault("inherits", "").(string),
	}

	delete(config.Values, "inherits")
	delete(config.Values, "provider")

	if err := config.Validate(); err != nil {
		return handleError(err)
	}

	if prev.Provider != "" && config.Inherits != "" {
		return handleError(errors.New("conversion to inherited config is forbidden"))
	}

	if p != nil {
		config.Values, err = p.ParseConfigData(config.Values, true)
		if err != nil {
			return handleError(err)
		}
	}

	// Write back to storage.
	if err := extkey.WriteConfig(ctx, req.Storage, path, config); err != nil {
		return handleError(err)
	}

	invalidate()

	return nil, nil
}

// DELETE /sys/external-keys/configs/:config-name
func (b *SystemBackend) handleExternalKeysConfigDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("config").(string)

	unlock, invalidate := b.Core.externalKeys.LockStorage(ctx, name)
	defer unlock()

	// First, delete all key entries.
	view := logical.NewStorageView(req.Storage, extkey.KeyListPath(name))
	if err := logical.ClearViewWithLogging(ctx, view, b.logger); err != nil {
		return handleError(err)
	}

	// Then delete the config entry itself.
	if err := req.Storage.Delete(ctx, extkey.ConfigPath(name)); err != nil {
		return handleError(err)
	}

	invalidate()

	return nil, nil
}

// LIST /sys/external-keys/configs/:config-name/keys
func (b *SystemBackend) handleExternalKeysKeyList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	path := extkey.KeyListPath(d.Get("config").(string))
	keys, err := req.Storage.List(ctx, path)
	if err != nil {
		return handleError(err)
	}

	return logical.ListResponse(keys), nil
}

// GET /sys/external-keys/configs/:config-name/keys/:key-name
func (b *SystemBackend) handleExternalKeysKeyRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	configName, keyName := d.Get("config").(string), d.Get("key").(string)
	key, exists, err := extkey.ReadKey(ctx, req.Storage, extkey.KeyPath(configName, keyName))
	switch {
	case err != nil:
		return handleError(err)
	case !exists:
		return nil, logical.CodedError(http.StatusNotFound, "key %q not found", keyName)
	}

	return &logical.Response{Data: key.Values}, nil
}

// PUT /sys/external-keys/configs/:config-name/keys/:key-name
func (b *SystemBackend) handleExternalKeysKeyWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("config").(string)

	unlock := b.Core.externalKeys.RLockStorage(ctx, name)
	defer unlock()

	// Ensure this key has a config.
	path := extkey.ConfigPath(d.Get("config").(string))
	config, exists, err := extkey.ReadConfig(ctx, req.Storage, path)
	switch {
	case err != nil:
		return handleError(err)
	case !exists:
		return nil, logical.CodedError(http.StatusNotFound, "config %q not found", name)
	case config.Inherits != "":
		return handleError(fmt.Errorf("cannot associate key with inherited config"))
	}

	// The key may already exist.
	path = extkey.KeyPath(name, d.Get("key").(string))
	key, exists, err := extkey.ReadKey(ctx, req.Storage, path)
	switch {
	case err != nil:
		return handleError(err)
	case !exists:
		// Initialize a new key.
		key = &extkey.Key{
			Grants: []string{}, // For consistency.
		}
	}

	// Get the associated provider.
	p, err := b.Core.externalKeys.GetProvider(config.Provider)
	if err != nil {
		return handleError(err)
	}

	data := &framework.FieldData{
		Raw: req.Data, Schema: p.KeySchema,
	}

	// Validate the data against the provider.
	key.Values, err = data.ToMap()
	if err != nil {
		return handleError(err)
	}

	// Write back to storage.
	if err := extkey.WriteKey(ctx, req.Storage, path, key); err != nil {
		return handleError(err)
	}

	return nil, nil
}

// PATCH /sys/external-keys/configs/:config-name/keys/:key-name
func (b *SystemBackend) handleExternalKeysKeyPatch(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	configName, keyName := d.Get("config").(string), d.Get("key").(string)

	unlock := b.Core.externalKeys.RLockStorage(ctx, configName)
	defer unlock()

	// Read the associated config.
	config, exists, err := extkey.ReadConfig(ctx, req.Storage, extkey.ConfigPath(configName))
	switch {
	case err != nil:
		return handleError(err)
	case !exists:
		return nil, logical.CodedError(http.StatusNotFound, "config %q not found", configName)
	}

	// The key must already exist.
	path := extkey.KeyPath(configName, keyName)
	key, exists, err := extkey.ReadKey(ctx, req.Storage, path)
	switch {
	case err != nil:
		return handleError(err)
	case !exists:
		return nil, logical.CodedError(http.StatusNotFound, "key %q not found", keyName)
	}

	// Get the associated provider.
	p, err := b.Core.externalKeys.GetProvider(config.Provider)
	if err != nil {
		return handleError(err)
	}

	input := &framework.FieldData{
		Raw: req.Data, Schema: p.KeySchema,
	}

	patched, err := framework.HandlePatchOperation(input, key.Values, nil)
	if err != nil {
		return handleError(err)
	}

	output := &framework.FieldData{Schema: input.Schema}
	if err := json.Unmarshal(patched, &output.Raw); err != nil {
		return handleError(err)
	}

	key.Values, err = output.ToMap()
	if err != nil {
		return handleError(err)
	}

	// Write back to storage.
	if err := extkey.WriteKey(ctx, req.Storage, path, key); err != nil {
		return handleError(err)
	}

	return nil, nil
}

// DELETE /sys/external-keys/configs/:config-name/keys/:key-name
func (b *SystemBackend) handleExternalKeysKeyDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	path := extkey.KeyPath(d.Get("config").(string), d.Get("key").(string))
	if err := req.Storage.Delete(ctx, path); err != nil {
		return handleError(err)
	}

	return nil, nil
}

// LIST /sys/external-keys/configs/:config-name/keys/:key-name/grants
func (b *SystemBackend) handleExternalKeysGrantList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	configName, keyName := d.Get("config").(string), d.Get("key").(string)
	key, exists, err := extkey.ReadKey(ctx, req.Storage, extkey.KeyPath(configName, keyName))
	switch {
	case err != nil:
		return handleError(err)
	case !exists:
		return nil, logical.CodedError(http.StatusNotFound, "key %q not found", keyName)
	}

	return logical.ListResponse(key.Grants), nil
}

// PUT /sys/external-keys/configs/:config-name/keys/:key-name/grants/:mount-path
func (b *SystemBackend) handleExternalKeysGrantAdd(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	configName, keyName := d.Get("config").(string), d.Get("key").(string)

	unlock := b.Core.externalKeys.RLockStorage(ctx, configName)
	defer unlock()

	// Canonicalize the mount path; both for comparison with other paths and to
	// get a consistent representation for display.
	mount := strings.Trim(d.Get("mount").(string), "/") + "/"

	path := extkey.KeyPath(configName, keyName)
	key, exists, err := extkey.ReadKey(ctx, req.Storage, path)
	switch {
	case err != nil:
		return handleError(err)
	case !exists:
		return nil, logical.CodedError(http.StatusNotFound, "key %q not found", keyName)
	}

	// Grant already exists.
	if slices.Contains(key.Grants, mount) {
		return nil, nil
	}

	// Add the grant and write back to storage.
	key.Grants = append(key.Grants, mount)
	if err := extkey.WriteKey(ctx, req.Storage, path, key); err != nil {
		return handleError(err)
	}

	return nil, nil
}

// DELETE /sys/external-keys/configs/:config-name/keys/:key-name/grants/:mount-path
func (b *SystemBackend) handleExternalKeysGrantRemove(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	configName, keyName := d.Get("config").(string), d.Get("key").(string)

	unlock := b.Core.externalKeys.RLockStorage(ctx, configName)
	defer unlock()

	// Canonicalize the mount path; both for comparison with other paths and to
	// get a consistent representation for display.
	mount := strings.Trim(d.Get("mount").(string), "/") + "/"

	path := extkey.KeyPath(configName, keyName)
	key, exists, err := extkey.ReadKey(ctx, req.Storage, path)
	switch {
	case err != nil:
		return handleError(err)
	case !exists:
		return nil, logical.CodedError(http.StatusNotFound, "key %q not found", keyName)
	}

	// Grant doesn't exist.
	if !slices.Contains(key.Grants, mount) {
		return nil, nil
	}

	// Remove the grant and write back to storage.
	key.Grants = slices.DeleteFunc(key.Grants, func(grant string) bool {
		return grant == mount
	})
	if err := extkey.WriteKey(ctx, req.Storage, path, key); err != nil {
		return handleError(err)
	}

	return nil, nil
}

// GET /sys/external-keys/configs/:config-name/keys/:key-name/test/sign
func (b *SystemBackend) handleExternalKeysTestSign(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	key, err := b.System().GetExternalSigningKey(ctx, d.Get("config").(string), d.Get("key").(string))
	if err != nil {
		return handleError(err)
	}

	defer func() {
		if err := key.Close(ctx); err != nil {
			b.logger.Error("failed to close external key", err)
		}
	}()

	signer, err := key.GetSigner(ctx)
	if err != nil {
		return handleError(err)
	}

	var opts crypto.SignerOpts = crypto.Hash(0)
	var verify func(msg, digest, sig []byte) error

	switch pub := signer.Public().(type) {
	case *ecdsa.PublicKey:
		switch pub.Curve {
		case elliptic.P256():
			opts = crypto.SHA256
		case elliptic.P384():
			opts = crypto.SHA384
		case elliptic.P521():
			opts = crypto.SHA512
		}
		verify = func(msg, digest, sig []byte) error {
			if ecdsa.VerifyASN1(pub, digest, sig) {
				return nil
			}
			return errors.New("failed to verify ecdsa signature")
		}

	case *rsa.PublicKey:
		pss := &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: rsa.PSSSaltLengthEqualsHash}
		opts = pss
		verify = func(msg, digest, sig []byte) error {
			return rsa.VerifyPSS(pub, pss.Hash, digest, sig, pss)
		}

	case ed25519.PublicKey:
		verify = func(msg, _, sig []byte) error {
			if ed25519.Verify(pub, msg, sig) {
				return nil
			}
			return errors.New("failed to verify ed25519 signature")
		}

	default:
		return handleError(fmt.Errorf("unsupported public key type: %T", pub))
	}

	// Generate a random message to sign. User input is not accepted by design,
	// this is a testing endpoint.
	msg := make([]byte, 512)
	if _, err := rand.Read(msg); err != nil {
		return handleError(err)
	}

	// "digest" remains the message itself if no hash function is defined
	// (e.g., for Ed25519).
	digest := msg
	if hash := opts.HashFunc(); hash != crypto.Hash(0) {
		h := hash.New()
		h.Write(msg) //nolint:errcheck
		digest = h.Sum(nil)
	}

	// Sign the message, using crypto.MessageSigner if available.
	sig, err := crypto.SignMessage(signer, rand.Reader, msg, opts)
	if err != nil {
		return handleError(err)
	}

	// Then verify the signature using the (exported) public key.
	if err := verify(msg, digest, sig); err != nil {
		return handleError(err)
	}

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

	PUT /configs/<config>/keys/<key>/grants/<mount>
		Create a grant.

	DELETE /configs/<config>/keys/<key>/grants/<mount>
		Remove a grant.
`,
	"test-sign": `
This path responds to the following HTTP methods.

	PUT /configs/<config>/keys/<key>/test/sign
		Test sign a random message and verify the result.
		`,
}
