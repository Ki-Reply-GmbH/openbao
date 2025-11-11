// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

//go:build hsm && (linux || darwin)

package extkey

import (
	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2"
	"github.com/openbao/openbao/sdk/v2/framework"
)

var pkcs11Provider = &Provider{
	Factory: pkcs11.NewKeyStore,

	KeySchema: map[string]*framework.FieldSchema{
		"id":    {Type: framework.TypeString},
		"label": {Type: framework.TypeString},
	},

	KeyMappings: map[string]*Mapping{
		"id":    {Target: pkcs11.IdAttr},
		"label": {Target: pkcs11.LabelAttr},
	},

	ConfigSchema: map[string]*framework.FieldSchema{
		"library":     {Type: framework.TypeString, Required: true},
		"pin":         {Type: framework.TypeString},
		"slot":        {Type: framework.TypeString},
		"token_label": {Type: framework.TypeString},
	},

	ConfigMappings: map[string]*Mapping{
		"library":     {Target: pkcs11.KeyStoreParamLib, Server: true},
		"pin":         {Password: true},
		"slot":        {Target: pkcs11.KeyStoreParamSlot},
		"token_label": {Target: pkcs11.KeyStoreParamLabel},
	},
}

func init() {
	providers["pkcs11"] = pkcs11Provider
}
