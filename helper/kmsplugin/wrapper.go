// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package kmsplugin

import (
	"context"
	"errors"
	"fmt"

	"github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/go-kms-wrapping/wrappers/alicloudkms/v2"
	"github.com/openbao/go-kms-wrapping/wrappers/awskms/v2"
	"github.com/openbao/go-kms-wrapping/wrappers/azurekeyvault/v2"
	"github.com/openbao/go-kms-wrapping/wrappers/gcpckms/v2"
	"github.com/openbao/go-kms-wrapping/wrappers/kmip/v2"
	"github.com/openbao/go-kms-wrapping/wrappers/ocikms/v2"
	"github.com/openbao/go-kms-wrapping/wrappers/static/v2"
	"github.com/openbao/go-kms-wrapping/wrappers/transit/v2"
)

type wrapperFactory func() (wrapping.Wrapper, error)

var builtinWrappers = map[wrapping.WrapperType]wrapperFactory{
	// Standards-based or generic:
	wrapping.WrapperTypeKmip:    toWrapper(kmip.NewWrapper),
	wrapping.WrapperTypeStatic:  toWrapper(static.NewWrapper),
	wrapping.WrapperTypeTransit: toWrapper(transit.NewWrapper),

	// Cloud providers:
	wrapping.WrapperTypeAliCloudKms:   toWrapper(alicloudkms.NewWrapper),
	wrapping.WrapperTypeAwsKms:        toWrapper(awskms.NewWrapper),
	wrapping.WrapperTypeAzureKeyVault: toWrapper(azurekeyvault.NewWrapper),
	wrapping.WrapperTypeGcpCkms:       toWrapper(gcpckms.NewWrapper),
	wrapping.WrapperTypeOciKms:        toWrapper(ocikms.NewWrapper),

	wrapping.WrapperTypePkcs11: func() (wrapping.Wrapper, error) {
		// The real wrapper is conditionally enabled pkcs11.go.
		return nil, errors.New("this build of OpenBao has PKCS#11 disabled")
	},
}

// toWrapper is a hack to go from func() <concrete wrapper type> to func()
// (wrapping.Wrapper, error), as constructors in go-kms-wrapping tend to return
// the concrete type.
func toWrapper[T wrapping.Wrapper](f func() T) wrapperFactory {
	return func() (wrapping.Wrapper, error) { return f(), nil }
}

// ConfigureWrapper creates a new wrapper instance and calls SetConfig with
// the provided options. This may dispatch to either a builtin wrapper or an
// external pluginized wrapper.
func (c *Catalog) ConfigureWrapper(ctx context.Context, name string, opts ...wrapping.Option) (wrapping.Wrapper, *wrapping.WrapperConfig, error) {
	wrapper, err := c.getWrapper(name)
	if err != nil {
		return nil, nil, err
	}

	config, err := wrapper.SetConfig(ctx, opts...)
	if err != nil {
		return nil, nil, err
	}

	return wrapper, config, nil
}

func (c *Catalog) getWrapper(name string) (wrapping.Wrapper, error) {
	cl, ok, err := c.getClient(name)
	switch {
	case err != nil:
		return nil, err
	case !ok:
		// Try builtin wrappers.
		if factory, ok := builtinWrappers[wrapping.WrapperType(name)]; ok {
			return factory()
		}
		return nil, fmt.Errorf("unknown wrapper: %s", name)
	}

	raw, err := cl.clientproto.Dispense("wrapper")
	if err != nil {
		cl.close()
		return nil, err
	}

	return &wrapper{
		client:        cl,
		Wrapper:       raw.(wrapping.Wrapper),
		InitFinalizer: raw.(wrapping.InitFinalizer),
	}, nil
}

type wrapper struct {
	client *client

	// Wrappers provded by go-kms-wrapping/plugin always implement both
	// interfaces.
	wrapping.Wrapper
	wrapping.InitFinalizer
}

func (w *wrapper) Finalize(ctx context.Context, opts ...wrapping.Option) error {
	err := w.InitFinalizer.Finalize(ctx, opts...)
	w.client.close()
	return err
}
