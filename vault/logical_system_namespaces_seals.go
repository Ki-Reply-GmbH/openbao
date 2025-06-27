// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func (b *SystemBackend) namespaceSealPaths() []*framework.Path {
	namespaceFieldsSchema := map[string]*framework.FieldSchema{
		"name": {
			Type:        framework.TypeString,
			Required:    true,
			Description: "Name of the namespace.",
		},
		"key": {
			Type:        framework.TypeString,
			Description: "Specifies a single namespace unseal key share.",
		},
	}

	rekeyRequestFieldsSchema := map[string]*framework.FieldSchema{
		"name": namespaceFieldsSchema["name"],
		"secret_shares": {
			Type:        framework.TypeInt,
			Required:    true,
			Description: "Specifies the number of shares to split the root key into.",
		},
		"secret_threshold": {
			Type:        framework.TypeInt,
			Required:    true,
			Description: "Specifies the number of shares required to reconstruct the root key.",
		},
		"pgp_keys": {
			Type:        framework.TypeStringSlice,
			Description: "Specifies an array of PGP public keys used to encrypt the output unseal keys.",
		},
		"backup": {
			Type:        framework.TypeBool,
			Description: "Specifies if using PGP-encrypted keys, whether OpenBao should also store a plaintext backup of the said keys.",
		},
		"require_verification": {
			Type:        framework.TypeBool,
			Description: "Enables verification which after successful authorization with the current unseal keys, ensures the new unseal keys are returned but the root key is not actually rotated.",
		},
	}

	rekeyStatusSchema := map[string]*framework.FieldSchema{
		"nonce": {
			Type:     framework.TypeString,
			Required: true,
		},
		"started": {
			Type:     framework.TypeBool,
			Required: true,
		},
		"t": {
			Type:     framework.TypeInt,
			Required: true,
		},
		"n": {
			Type:     framework.TypeInt,
			Required: true,
		},
		"progress": {
			Type:     framework.TypeInt,
			Required: true,
		},
		"required": {
			Type:     framework.TypeInt,
			Required: true,
		},
		"pgp_fingerprints": {
			Type:     framework.TypeCommaStringSlice,
			Required: true,
		},
		"backup": {
			Type:     framework.TypeBool,
			Required: true,
		},
		"verification_required": {
			Type:     framework.TypeBool,
			Required: true,
		},
		"verification_nonce": {
			Type: framework.TypeString,
		},
	}

	sealStatusSchema := map[string]*framework.FieldSchema{
		"type": {
			Type:     framework.TypeString,
			Required: true,
		},
		"initialized": {
			Type:     framework.TypeBool,
			Required: true,
		},
		"sealed": {
			Type:     framework.TypeBool,
			Required: true,
		},
		"t": {
			Type:     framework.TypeInt,
			Required: true,
		},
		"n": {
			Type:     framework.TypeInt,
			Required: true,
		},
		"progress": {
			Type:     framework.TypeInt,
			Required: true,
		},
		"nonce": {
			Type:     framework.TypeString,
			Required: true,
		},
		"version": {
			Type:     framework.TypeString,
			Required: true,
		},
		"build_date": {
			Type:     framework.TypeString,
			Required: true,
		},
		"migration": {
			Type: framework.TypeBool,
		},
		"cluster_name": {
			Type: framework.TypeString,
		},
		"cluster_id": {
			Type: framework.TypeString,
		},
		"recovery_seal": {
			Type: framework.TypeBool,
		},
		"storage_type": {
			Type: framework.TypeString,
		},
	}

	return []*framework.Path{
		{
			Pattern: "namespaces/(?P<name>.+)/key-status",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "namespaces",
				OperationVerb:   "status",
				OperationSuffix: "encryption-key",
			},
			Fields: map[string]*framework.FieldSchema{
				"name": namespaceFieldsSchema["name"],
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Summary:  "Provides information about the namespace backend encryption key.",
					Callback: b.handleNamespaceKeyStatus(),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Fields: map[string]*framework.FieldSchema{
								"term": {
									Type:     framework.TypeInt,
									Required: true,
								},
								"install_time": {
									Type:     framework.TypeTime,
									Required: true,
								},
								"encryptions": {
									Type:     framework.TypeInt64,
									Required: true,
								},
							},
						}},
					},
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysHelp["namespaces-seal"][0]),
			HelpDescription: strings.TrimSpace(sysHelp["namespaces-seal"][1]),
		},
		{
			Pattern: "namespaces/(?P<name>.+)/rekey/init",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "namespaces",
				OperationVerb:   "rekey",
			},
			Fields: rekeyRequestFieldsSchema,

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Summary:  "Read status of a namespace key rekey attempt",
					Callback: b.handleNamespaceRekeyBarrierRead(),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: http.StatusText(http.StatusOK),
							Fields:      rekeyStatusSchema,
						}},
					},
				},
				logical.UpdateOperation: &framework.PathOperation{
					Summary:  "Initialize a new rekey attempt of the namespace key.",
					Callback: b.handleNamespaceRekeyBarrierInit(),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: http.StatusText(http.StatusOK),
							Fields:      rekeyStatusSchema,
						}},
					},
				},
			},

			// TODO: add
			HelpSynopsis:    strings.TrimSpace(sysHelp["namespaces-rekey"][0]),
			HelpDescription: strings.TrimSpace(sysHelp["namespaces-rekey"][1]),
		},
		{
			Pattern: "namespaces/(?P<name>.+)/seal-status",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "namespaces",
				OperationVerb:   "status",
				OperationSuffix: "seal",
			},
			Fields: map[string]*framework.FieldSchema{
				"name": namespaceFieldsSchema["name"],
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Summary:  "Check the seal status of an OpenBao namespace.",
					Callback: b.handleNamespaceSealStatus(),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: http.StatusText(http.StatusOK),
							Fields:      sealStatusSchema,
						}},
					},
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysHelp["namespaces-seal"][0]),
			HelpDescription: strings.TrimSpace(sysHelp["namespaces-seal"][1]),
		},

		{
			Pattern: "namespaces/(?P<name>.+)/seal",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "namespaces",
			},
			Fields: map[string]*framework.FieldSchema{
				"name": namespaceFieldsSchema["name"],
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Summary:  "Seal a namespace.",
					Callback: b.handleNamespacesSeal(),
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{Description: http.StatusText(http.StatusNoContent)}},
					},
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysHelp["namespaces-seal"][0]),
			HelpDescription: strings.TrimSpace(sysHelp["namespaces-seal"][1]),
		},
		{
			Pattern: "namespaces/(?P<name>.+)/unseal",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "namespaces",
			},
			Fields: namespaceFieldsSchema,

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Summary:  "Unseal a namespace.",
					Callback: b.handleNamespacesUnseal(),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: http.StatusText(http.StatusOK),
							Fields:      sealStatusSchema,
						}},
					},
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysHelp["namespaces-seal"][0]),
			HelpDescription: strings.TrimSpace(sysHelp["namespaces-seal"][1]),
		},
		{
			Pattern: "namespaces/(?P<name>.+)/rotate",

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "namespaces",
			},

			Fields: map[string]*framework.FieldSchema{
				"name": namespaceFieldsSchema["name"],
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Summary:  "Rotate the namespace key.",
					Callback: b.handleNamespacesRotate(),
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{Description: http.StatusText(http.StatusNoContent)}},
					},
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysHelp["namespaces-rotate"][0]),
			HelpDescription: strings.TrimSpace(sysHelp["namespaces-rotate"][1]),
		},
	}
}

// createNamespaceRekeyStatusResponse returns back a rekey status properties.
func createNamespaceRekeyStatusResponse(rekeyStatus *RekeyStatus) map[string]any {
	resp := map[string]any{
		"nonce":                 rekeyStatus.Nonce,
		"started":               rekeyStatus.Started,
		"t":                     rekeyStatus.T,
		"n":                     rekeyStatus.N,
		"progress":              rekeyStatus.Progress,
		"required":              rekeyStatus.Required,
		"pgp_fingerprints":      rekeyStatus.PGPFingerprints,
		"backup":                rekeyStatus.Backup,
		"verification_required": rekeyStatus.VerificationRequired,
	}

	if rekeyStatus.VerificationNonce != "" {
		resp["verification_nonce"] = rekeyStatus.VerificationNonce
	}

	return resp
}

// handleNamespaceKeyStatus handles the "/sys/namespaces/<name>/key-status" endpoint
// to return status information about the namespace-owned backend key.
func (b *SystemBackend) handleNamespaceKeyStatus() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		name := namespace.Canonicalize(data.Get("name").(string))
		if len(name) > 0 && strings.Contains(name[:len(name)-1], "/") {
			return nil, errors.New("name must not contain /")
		}

		ns, err := b.Core.namespaceStore.GetNamespaceByPath(ctx, name)
		if err != nil {
			return handleError(err)
		}

		if ns == nil {
			return nil, fmt.Errorf("namespace %q doesn't exist", name)
		}

		barrier := b.Core.sealManager.NamespaceBarrier(ns.Path)
		if barrier == nil {
			return nil, fmt.Errorf("namespace %q doesn't have a barrier setup", ns.Path)
		}

		info, err := barrier.ActiveKeyInfo()
		if err != nil {
			return handleError(err)
		}

		return &logical.Response{
			Data: map[string]interface{}{
				"term":         info.Term,
				"install_time": info.InstallTime.Format(time.RFC3339Nano),
				"encryptions":  info.Encryptions,
			},
		}, nil
	}
}

// handleNamespaceRekeyBarrierInit handles the POST "/sys/namespaces/<name>/rekey/init"
// endpoint to initialize a new namespace barrier rekey attempt.
func (b *SystemBackend) handleNamespaceRekeyBarrierInit() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		name := namespace.Canonicalize(data.Get("name").(string))
		if len(name) > 0 && strings.Contains(name[:len(name)-1], "/") {
			return nil, errors.New("name must not contain /")
		}

		ns, err := b.Core.namespaceStore.GetNamespaceByPath(ctx, name)
		if err != nil {
			return handleError(err)
		}

		if ns == nil {
			return nil, fmt.Errorf("namespace %q doesn't exist", name)
		}

		rekeyConfig := &SealConfig{}
		secretShares, ok := data.GetOk("secret_shares")
		if ok {
			rekeyConfig.SecretShares = secretShares.(int)
		}

		secretThreshold, ok := data.GetOk("secret_threshold")
		if ok {
			rekeyConfig.SecretThreshold = secretThreshold.(int)
		}

		pgpKeys, ok := data.GetOk("pgp_keys")
		if ok {
			rekeyConfig.PGPKeys = pgpKeys.([]string)
		}

		backup, ok := data.GetOk("backup")
		if ok {
			rekeyConfig.Backup = backup.(bool)
		}

		verificationReq, ok := data.GetOk("require_verification")
		if ok {
			rekeyConfig.VerificationRequired = verificationReq.(bool)
		}

		err = b.Core.sealManager.RekeyInit(ctx, rekeyConfig, ns, false)
		if err != nil {
			return handleError(err)
		}

		rekeyStatus, err := b.Core.sealManager.RekeyStatus(ctx, ns, false)
		if err != nil {
			return handleError(err)
		}

		return &logical.Response{
			Data: createNamespaceRekeyStatusResponse(rekeyStatus),
		}, nil
	}
}

// handleNamespaceRekeyBarrierRead handles the GET "/sys/namespaces/<name>/rekey/init"
// endpoint to read current namespace rekey attempt status.
func (b *SystemBackend) handleNamespaceRekeyBarrierRead() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		name := namespace.Canonicalize(data.Get("name").(string))
		if len(name) > 0 && strings.Contains(name[:len(name)-1], "/") {
			return nil, errors.New("name must not contain /")
		}

		ns, err := b.Core.namespaceStore.GetNamespaceByPath(ctx, name)
		if err != nil {
			return handleError(err)
		}

		if ns == nil {
			return nil, fmt.Errorf("namespace %q doesn't exist", name)
		}

		rekeyStatus, err := b.Core.sealManager.RekeyStatus(ctx, ns, false)
		if err != nil {
			return handleError(err)
		}

		return &logical.Response{
			Data: createNamespaceRekeyStatusResponse(rekeyStatus),
		}, nil
	}
}

// handleNamespaceSealStatus handles the "/sys/namespaces/<name>/seal-status" endpoint
// to retrieve a seal status of the namespace.
func (b *SystemBackend) handleNamespaceSealStatus() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		name := namespace.Canonicalize(data.Get("name").(string))
		if len(name) > 0 && strings.Contains(name[:len(name)-1], "/") {
			return nil, errors.New("name must not contain /")
		}

		ns, err := b.Core.namespaceStore.GetNamespaceByPath(ctx, name)
		if err != nil {
			return handleError(err)
		}

		if ns == nil {
			return nil, fmt.Errorf("namespace %q doesn't exist", name)
		}

		status, err := b.Core.sealManager.GetSealStatus(ctx, ns, false)
		if err != nil {
			return handleError(err)
		}

		if status == nil {
			return nil, nil
		}

		return &logical.Response{
			Data: map[string]interface{}{"seal_status": status},
		}, nil
	}
}

// handleNamespacesSeal handles the "/sys/namespaces/<name>/seal" endpoint to seal the namespace.
func (b *SystemBackend) handleNamespacesSeal() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		name := namespace.Canonicalize(data.Get("name").(string))

		if len(name) > 0 && strings.Contains(name[:len(name)-1], "/") {
			return nil, errors.New("name must not contain /")
		}

		err := b.Core.namespaceStore.SealNamespace(ctx, name)
		if err != nil {
			return handleError(err)
		}

		return nil, nil
	}
}

// handleNamespacesRotate handles the "/sys/namespaces/<name>/rotate" endpoint to rotate the namespace encryption key.
func (b *SystemBackend) handleNamespacesRotate() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		name := namespace.Canonicalize(data.Get("name").(string))

		if len(name) > 0 && strings.Contains(name[:len(name)-1], "/") {
			return nil, errors.New("name must not contain /")
		}

		ns, err := b.Core.namespaceStore.GetNamespaceByPath(ctx, name)
		if err != nil {
			return handleError(err)
		}

		if ns == nil {
			return nil, fmt.Errorf("namespace %q doesn't exist", name)
		}

		err = b.Core.sealManager.RotateNamespaceBarrierKey(ctx, ns)
		if err != nil {
			return nil, err
		}

		return nil, nil
	}
}

// handleNamespacesUnseal handles the "/sys/namespaces/<name>/unseal" endpoint to unseal the namespace.
func (b *SystemBackend) handleNamespacesUnseal() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		name := namespace.Canonicalize(data.Get("name").(string))
		key := data.Get("key").(string)

		if len(name) > 0 && strings.Contains(name[:len(name)-1], "/") {
			return nil, errors.New("name must not contain /")
		}

		if key == "" {
			return nil, errors.New("provided key is empty")
		}

		var decodedKey []byte
		decodedKey, err := hex.DecodeString(key)
		if err != nil {
			decodedKey, err = base64.StdEncoding.DecodeString(key)
			if err != nil {
				return handleError(err)
			}
		}

		ns, err := b.Core.namespaceStore.GetNamespaceByPath(ctx, name)
		if err != nil {
			return handleError(err)
		}

		if ns == nil {
			return nil, fmt.Errorf("namespace %q doesn't exist", name)
		}

		err = b.Core.sealManager.UnsealNamespace(ctx, ns, decodedKey)
		if err != nil {
			invalidKeyErr := &ErrInvalidKey{}
			switch {
			case errors.As(err, &invalidKeyErr):
			case errors.Is(err, ErrBarrierInvalidKey):
			case errors.Is(err, ErrBarrierNotInit):
			case errors.Is(err, ErrBarrierSealed):
			default:
				return logical.RespondWithStatusCode(logical.ErrorResponse(err.Error()), req, http.StatusInternalServerError)
			}
			return handleError(err)
		}

		status, err := b.Core.sealManager.GetSealStatus(ctx, ns, true)
		if err != nil {
			return nil, err
		}

		return &logical.Response{Data: map[string]interface{}{
			"seal_status": status,
		}}, nil
	}
}
