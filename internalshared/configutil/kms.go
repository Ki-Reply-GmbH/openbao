// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package configutil

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	aeadwrapper "github.com/openbao/go-kms-wrapping/wrappers/aead/v2"
	"github.com/openbao/go-kms-wrapping/wrappers/alicloudkms/v2"
	"github.com/openbao/go-kms-wrapping/wrappers/awskms/v2"
	"github.com/openbao/go-kms-wrapping/wrappers/azurekeyvault/v2"
	"github.com/openbao/go-kms-wrapping/wrappers/gcpckms/v2"
	"github.com/openbao/go-kms-wrapping/wrappers/kmip/v2"
	"github.com/openbao/go-kms-wrapping/wrappers/ocikms/v2"
	statickms "github.com/openbao/go-kms-wrapping/wrappers/static/v2"
	"github.com/openbao/go-kms-wrapping/wrappers/transit/v2"
	"github.com/openbao/openbao/sdk/v2/logical"
)

var (
	ConfigureWrapper             = configureWrapper
	CreateSecureRandomReaderFunc = createSecureRandomReader
)

// Entropy contains Entropy configuration for the server
type EntropyMode int

const (
	EntropyUnknown EntropyMode = iota
	EntropyAugmentation
)

type Entropy struct {
	Mode EntropyMode
}

// KMS contains KMS configuration for the server
type KMS struct {
	UnusedKeys []string `hcl:",unusedKeys"`
	Type       string
	// Purpose can be used to allow a string-based specification of what this
	// KMS is designated for, in situations where we want to allow more than
	// one KMS to be specified
	Purpose []string `hcl:"-"`

	Disabled bool
	Config   map[string]string
}

func (k *KMS) GoString() string {
	return fmt.Sprintf("*%#v", *k)
}

func parseKMS(result *[]*KMS, list *ast.ObjectList, blockName string, maxKMS int) error {
	if len(list.Items) > maxKMS {
		return fmt.Errorf("only two or less %q blocks are permitted", blockName)
	}

	seals := make([]*KMS, 0, len(list.Items))
	for _, item := range list.Items {
		key := blockName
		if len(item.Keys) > 0 {
			key = item.Keys[0].Token.Value().(string)
		}

		// We first decode into a map[string]interface{} because purpose isn't
		// necessarily a string. Then we migrate everything else over to
		// map[string]string and error if it doesn't work.
		var m map[string]interface{}
		if err := hcl.DecodeObject(&m, item.Val); err != nil {
			return multierror.Prefix(err, fmt.Sprintf("%s.%s:", blockName, key))
		}

		var purpose []string
		var err error
		if v, ok := m["purpose"]; ok {
			if purpose, err = parseutil.ParseCommaStringSlice(v); err != nil {
				return multierror.Prefix(fmt.Errorf("unable to parse 'purpose' in kms type %q: %w", key, err), fmt.Sprintf("%s.%s:", blockName, key))
			}
			for i, p := range purpose {
				purpose[i] = strings.ToLower(p)
			}
			delete(m, "purpose")
		}

		var disabled bool
		if v, ok := m["disabled"]; ok {
			disabled, err = parseutil.ParseBool(v)
			if err != nil {
				return multierror.Prefix(err, fmt.Sprintf("%s.%s:", blockName, key))
			}
			delete(m, "disabled")
		}

		strMap := make(map[string]string, len(m))
		for k, v := range m {
			s, err := parseutil.ParseString(v)
			if err != nil {
				return multierror.Prefix(err, fmt.Sprintf("%s.%s:", blockName, key))
			}
			strMap[k] = s
		}

		seal := &KMS{
			Type:     strings.ToLower(key),
			Purpose:  purpose,
			Disabled: disabled,
		}
		if len(strMap) > 0 {
			seal.Config = strMap
		}
		seals = append(seals, seal)
	}

	*result = append(*result, seals...)

	return nil
}

func ParseKMSes(d string) ([]*KMS, error) {
	// Parse!
	obj, err := hcl.Parse(d)
	if err != nil {
		return nil, err
	}

	// Start building the result
	var result struct {
		Seals []*KMS `hcl:"-"`
	}

	if err := hcl.DecodeObject(&result, obj); err != nil {
		return nil, err
	}

	list, ok := obj.Node.(*ast.ObjectList)
	if !ok {
		return nil, errors.New("error parsing: file doesn't contain a root object")
	}

	if o := list.Filter("seal"); len(o.Items) > 0 {
		if err := parseKMS(&result.Seals, o, "seal", 3); err != nil {
			return nil, fmt.Errorf("error parsing 'seal': %w", err)
		}
	}

	if o := list.Filter("kms"); len(o.Items) > 0 {
		if err := parseKMS(&result.Seals, o, "kms", 3); err != nil {
			return nil, fmt.Errorf("error parsing 'kms': %w", err)
		}
	}

	return result.Seals, nil
}

func configureWrapper(configKMS *KMS, infoKeys *[]string, info *map[string]string, logger hclog.Logger, opts ...wrapping.Option) (wrapping.Wrapper, error) {
	var wrapper wrapping.Wrapper
	var kmsInfo map[string]string
	var err error

	switch wrapping.WrapperType(configKMS.Type) {
	case wrapping.WrapperTypeShamir:
		return nil, nil

	case wrapping.WrapperTypeAead:
		wrapper, kmsInfo, err = GetAEADKMSFunc(configKMS, opts...)

	case wrapping.WrapperTypeAliCloudKms:
		wrapper, kmsInfo, err = GetAliCloudKMSFunc(configKMS, opts...)

	case wrapping.WrapperTypeAwsKms:
		wrapper, kmsInfo, err = GetAWSKMSFunc(configKMS, opts...)

	case wrapping.WrapperTypeAzureKeyVault:
		wrapper, kmsInfo, err = GetAzureKeyVaultKMSFunc(configKMS, opts...)

	case wrapping.WrapperTypeGcpCkms:
		wrapper, kmsInfo, err = GetGCPCKMSKMSFunc(configKMS, opts...)

	case wrapping.WrapperTypeOciKms:
		if keyId, ok := configKMS.Config["key_id"]; ok {
			opts = append(opts, wrapping.WithKeyId(keyId))
		}
		wrapper, kmsInfo, err = GetOCIKMSKMSFunc(configKMS, opts...)

	case wrapping.WrapperTypeTransit:
		wrapper, kmsInfo, err = GetTransitKMSFunc(configKMS, opts...)

	case wrapping.WrapperTypePkcs11:
		wrapper, kmsInfo, err = GetPKCS11KMSFunc(configKMS, opts...)

	case wrapping.WrapperTypeKmip:
		wrapper, kmsInfo, err = GetKmipKMSFunc(configKMS, opts...)

	case wrapping.WrapperTypeStatic:
		wrapper, kmsInfo, err = GetStaticKMSFunc(configKMS, opts...)

	default:
		return nil, fmt.Errorf("Unknown KMS type %q", configKMS.Type)
	}

	if err != nil {
		return nil, err
	}

	if infoKeys != nil && info != nil {
		for k, v := range kmsInfo {
			*infoKeys = append(*infoKeys, k)
			(*info)[k] = v
		}
	}

	return wrapper, nil
}

func GetAEADKMSFunc(kms *KMS, opts ...wrapping.Option) (wrapping.Wrapper, map[string]string, error) {
	wrapper := aeadwrapper.NewWrapper()
	wrapperInfo, err := wrapper.SetConfig(context.Background(), append(opts, wrapping.WithConfigMap(kms.Config))...)
	if err != nil {
		return nil, nil, err
	}
	info := make(map[string]string)
	if wrapperInfo != nil {
		str := "AEAD Type"
		if len(kms.Purpose) > 0 {
			str = fmt.Sprintf("%v %s", kms.Purpose, str)
		}
		info[str] = wrapperInfo.Metadata["aead_type"]
	}
	return wrapper, info, nil
}

func GetAliCloudKMSFunc(kms *KMS, opts ...wrapping.Option) (wrapping.Wrapper, map[string]string, error) {
	wrapper := alicloudkms.NewWrapper()
	wrapperInfo, err := wrapper.SetConfig(context.Background(), append(opts, wrapping.WithConfigMap(kms.Config))...)
	if err != nil {
		// If the error is any other than logical.KeyNotFoundError, return the error
		if !errwrap.ContainsType(err, new(logical.KeyNotFoundError)) {
			return nil, nil, err
		}
	}
	info := make(map[string]string)
	if wrapperInfo != nil {
		info["AliCloud KMS Region"] = wrapperInfo.Metadata["region"]
		info["AliCloud KMS KeyID"] = wrapperInfo.Metadata["kms_key_id"]
		if domain, ok := wrapperInfo.Metadata["domain"]; ok {
			info["AliCloud KMS Domain"] = domain
		}
	}
	return wrapper, info, nil
}

var GetAWSKMSFunc = func(kms *KMS, opts ...wrapping.Option) (wrapping.Wrapper, map[string]string, error) {
	wrapper := awskms.NewWrapper()
	wrapperInfo, err := wrapper.SetConfig(context.Background(), append(opts, wrapping.WithConfigMap(kms.Config))...)
	if err != nil {
		// If the error is any other than logical.KeyNotFoundError, return the error
		if !errwrap.ContainsType(err, new(logical.KeyNotFoundError)) {
			return nil, nil, err
		}
	}
	info := make(map[string]string)
	if wrapperInfo != nil {
		info["AWS KMS Region"] = wrapperInfo.Metadata["region"]
		info["AWS KMS KeyID"] = wrapperInfo.Metadata["kms_key_id"]
		if endpoint, ok := wrapperInfo.Metadata["endpoint"]; ok {
			info["AWS KMS Endpoint"] = endpoint
		}
	}
	return wrapper, info, nil
}

func GetAzureKeyVaultKMSFunc(kms *KMS, opts ...wrapping.Option) (wrapping.Wrapper, map[string]string, error) {
	wrapper := azurekeyvault.NewWrapper()
	wrapperInfo, err := wrapper.SetConfig(context.Background(), append(opts, wrapping.WithConfigMap(kms.Config))...)
	if err != nil {
		// If the error is any other than logical.KeyNotFoundError, return the error
		if !errwrap.ContainsType(err, new(logical.KeyNotFoundError)) {
			return nil, nil, err
		}
	}
	info := make(map[string]string)
	if wrapperInfo != nil {
		info["Azure Environment"] = wrapperInfo.Metadata["environment"]
		info["Azure Vault Name"] = wrapperInfo.Metadata["vault_name"]
		info["Azure Key Name"] = wrapperInfo.Metadata["key_name"]
	}
	return wrapper, info, nil
}

func GetGCPCKMSKMSFunc(kms *KMS, opts ...wrapping.Option) (wrapping.Wrapper, map[string]string, error) {
	wrapper := gcpckms.NewWrapper()
	wrapperInfo, err := wrapper.SetConfig(context.Background(), append(opts, wrapping.WithConfigMap(kms.Config))...)
	if err != nil {
		// If the error is any other than logical.KeyNotFoundError, return the error
		if !errwrap.ContainsType(err, new(logical.KeyNotFoundError)) {
			return nil, nil, err
		}
	}
	info := make(map[string]string)
	if wrapperInfo != nil {
		info["GCP KMS Project"] = wrapperInfo.Metadata["project"]
		info["GCP KMS Region"] = wrapperInfo.Metadata["region"]
		info["GCP KMS Key Ring"] = wrapperInfo.Metadata["key_ring"]
		info["GCP KMS Crypto Key"] = wrapperInfo.Metadata["crypto_key"]
	}
	return wrapper, info, nil
}

func GetOCIKMSKMSFunc(kms *KMS, opts ...wrapping.Option) (wrapping.Wrapper, map[string]string, error) {
	wrapper := ocikms.NewWrapper()
	wrapperInfo, err := wrapper.SetConfig(context.Background(), append(opts, wrapping.WithConfigMap(kms.Config))...)
	if err != nil {
		return nil, nil, err
	}
	info := make(map[string]string)
	if wrapperInfo != nil {
		info["OCI KMS KeyID"] = wrapperInfo.Metadata[ocikms.KmsConfigKeyId]
		info["OCI KMS Crypto Endpoint"] = wrapperInfo.Metadata[ocikms.KmsConfigCryptoEndpoint]
		info["OCI KMS Management Endpoint"] = wrapperInfo.Metadata[ocikms.KmsConfigManagementEndpoint]
		info["OCI KMS Principal Type"] = wrapperInfo.Metadata["principal_type"]
	}
	return wrapper, info, nil
}

var GetTransitKMSFunc = func(kms *KMS, opts ...wrapping.Option) (wrapping.Wrapper, map[string]string, error) {
	wrapper := transit.NewWrapper()
	wrapperInfo, err := wrapper.SetConfig(context.Background(), append(opts, wrapping.WithConfigMap(kms.Config))...)
	if err != nil {
		// If the error is any other than logical.KeyNotFoundError, return the error
		if !errwrap.ContainsType(err, new(logical.KeyNotFoundError)) {
			return nil, nil, err
		}
	}
	info := make(map[string]string)
	if wrapperInfo != nil {
		info["Transit Address"] = wrapperInfo.Metadata["address"]
		info["Transit Mount Path"] = wrapperInfo.Metadata["mount_path"]
		info["Transit Key Name"] = wrapperInfo.Metadata["key_name"]
		if namespace, ok := wrapperInfo.Metadata["namespace"]; ok {
			info["Transit Namespace"] = namespace
		}
	}
	return wrapper, info, nil
}

func GetKmipKMSFunc(kms *KMS, opts ...wrapping.Option) (wrapping.Wrapper, map[string]string, error) {
	wrapper := kmip.NewWrapper()
	wrapperInfo, err := wrapper.SetConfig(context.Background(), append(opts, wrapping.WithConfigMap(kms.Config))...)
	if err != nil {
		return nil, nil, err
	}

	info := make(map[string]string)
	if wrapperInfo != nil {
		info["KMIP Key ID"] = wrapperInfo.Metadata["kms_key_id"]
		info["KMIP Endpoint"] = wrapperInfo.Metadata["endpoint"]
		info["KMIP Timeout"] = wrapperInfo.Metadata["timeout"]
		info["KMIP Encryption Algorithm"] = wrapperInfo.Metadata["encrypt_alg"]
		info["KMIP Protocol Version"] = wrapperInfo.Metadata["kmip_version"]

		if tlsCiphers := wrapperInfo.Metadata["kmip_tls12_ciphers"]; tlsCiphers != "" {
			info["KMIP TLS 1.2 Ciphers"] = tlsCiphers
		}
		if pubKeyId := wrapperInfo.Metadata["kms_public_key_id"]; pubKeyId != "" {
			info["KMIP Public Key ID"] = pubKeyId
		}
		if serverName := wrapperInfo.Metadata["server_name"]; serverName != "" {
			info["KMIP Server Name"] = serverName
		}
	}
	return wrapper, info, nil
}

func GetStaticKMSFunc(kms *KMS, opts ...wrapping.Option) (wrapping.Wrapper, map[string]string, error) {
	wrapper := statickms.NewWrapper()
	wrapperInfo, err := wrapper.SetConfig(context.Background(), append(opts, wrapping.WithConfigMap(kms.Config))...)
	if err != nil {
		// If the error is any other than logical.KeyNotFoundError, return the error
		if !errwrap.ContainsType(err, new(logical.KeyNotFoundError)) {
			return nil, nil, err
		}
	}
	info := make(map[string]string)
	if wrapperInfo != nil {
		if prev, ok := wrapperInfo.Metadata["previous_key_id"]; ok {
			info["Static KMS Previous Key ID"] = prev
		}
		info["Static KMS Key ID"] = wrapperInfo.Metadata["current_key_id"]
	}
	return wrapper, info, nil
}

func createSecureRandomReader(conf *SharedConfig, wrapper wrapping.Wrapper) (io.Reader, error) {
	return rand.Reader, nil
}
