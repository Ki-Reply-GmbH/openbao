// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package extkey

import (
	"context"
	"errors"
	"fmt"
	"maps"

	"github.com/openbao/go-kms-wrapping/v2/kms"
	"github.com/openbao/openbao/command/server"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/framework"
)

// Provider is a KMS Provider for external keys, such as PKCS#11.
type Provider struct {
	// Factory is this provider's kms.NewKeyStore function.
	Factory kms.NewKeyStore

	KeySchema   map[string]*framework.FieldSchema
	KeyMappings map[string]*Mapping

	ConfigSchema   map[string]*framework.FieldSchema
	ConfigMappings map[string]*Mapping

	stanza *server.ExternalKeysConfig
}

type Mapping struct {
	// Target is the Target key store parameters or key attributes key of this
	// field.
	Target string

	// Password/Username is true when this field is part of kms.Credentials
	// and is not provide as key store parameters or key attributes. This only
	// applies to a provider's config schema.
	Password, Username bool

	// Server is true when this field can only be provided within the Server's
	// configuration file. It will be rejected if provided via an API request.
	// This only applies to a provider's config schema.
	Server bool
}

// providers is the global registry of external key KMS providers.
var providers = map[string]*Provider{}

func (r *Registry) GetProvider(name string) (*Provider, error) {
	stanza := r.core.GetStanza(name)
	if stanza != nil {
		name = stanza.Provider
	}

	p, ok := r.Providers[name]
	if !ok {
		return nil, fmt.Errorf("unknown provider: %q", name)
	}

	// No stanza means we can just return the original provider.
	if stanza == nil {
		return p, nil
	}

	// Create a shallow copy of the provider with the stanza attached.
	return &Provider{
		stanza:         stanza,
		Factory:        p.Factory,
		KeySchema:      p.KeySchema,
		KeyMappings:    p.KeyMappings,
		ConfigSchema:   p.ConfigSchema,
		ConfigMappings: p.ConfigMappings,
	}, nil
}

func (p *Provider) AllowsNamespace(ns *namespace.Namespace) bool {
	if p.stanza == nil {
		return true
	}

	for _, spec := range p.stanza.Namespaces {
		if ns.CompareSpecifier(spec.Kind, spec.Value) {
			return true
		}
	}

	return false
}

func (p *Provider) ParseConfigData(raw map[string]any, sanitize bool) (map[string]any, error) {
	// Validate that no server fields are set.
	for k, field := range p.ConfigMappings {
		if _, ok := raw[k]; !ok {
			continue
		}

		// Statically forbidden values, such as the PKCS#11 library path.
		if field.Server {
			return nil, fmt.Errorf("field %q: is only allowed in server configuration", k)
		}

		if p.stanza == nil {
			continue
		}

		// Dynamically forbidden values that were additionally provided in the
		// server config.
		if _, ok := p.stanza.Values[k]; ok {
			return nil, fmt.Errorf("field %q: is only allowed in server configuration", k)
		}
	}

	// Now merge with server fields.
	if p.stanza != nil {
		// Copy the original values so they're not mutated.
		raw = maps.Clone(raw)
		// Then copy the server config's values on top.
		maps.Copy(raw, p.stanza.Values)
	}

	data := framework.FieldData{
		Raw: raw, Schema: p.ConfigSchema,
	}

	ret, err := data.ToMap()
	if err != nil {
		return nil, err
	}

	if sanitize && p.stanza != nil {
		for k := range p.stanza.Values {
			delete(ret, k)
		}
	}

	return ret, nil
}

func (p *Provider) newKMS(ctx context.Context, config *Config) (kms.KeyStore, error) {
	values, err := p.ParseConfigData(config.Values, false)
	if err != nil {
		return nil, err
	}

	params := make(map[string]any)
	var credentials kms.Credentials

	for k, v := range values {
		field, ok := p.ConfigMappings[k]
		if !ok {
			return nil, fmt.Errorf("unknown config field %q", k)
		}

		switch {
		case field.Target != "":
			params[field.Target] = v

		case field.Username:
			s, ok := v.(string)
			if !ok {
				return nil, fmt.Errorf("field %q is configured as password but not a string", k)
			}
			credentials.Username = s

		case field.Password:
			s, ok := values[k].(string)
			if !ok {
				return nil, fmt.Errorf("field %q is configured as password but not a string", k)
			}
			credentials.Password = s
		}
	}

	store, err := p.Factory(params)
	if err != nil {
		return nil, fmt.Errorf("failed to create key store: %w", err)
	}

	if err := store.Login(ctx, &credentials); err != nil {
		return nil, errors.Join(fmt.Errorf("failed to log in key store: %w", err), store.Close(ctx))
	}

	return store, nil
}

func (p *Provider) getKMSKey(ctx context.Context, store kms.KeyStore, key *Key) (kms.Key, error) {
	data := &framework.FieldData{
		Raw: key.Values, Schema: p.KeySchema,
	}

	values, err := data.ToMap()
	if err != nil {
		return nil, err
	}

	params := make(map[string]any)

	for k, v := range values {
		field, ok := p.KeyMappings[k]
		if !ok {
			return nil, fmt.Errorf("unknown key field %q", k)
		}

		if field.Target == "" {
			return nil, fmt.Errorf("target of field %q is empty", k)
		}

		params[field.Target] = v
	}

	return store.GetKeyByAttrs(ctx, params)
}
