// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package mldsa

import (
	"crypto"
	"errors"
	"io"
)

var err = errors.New("crypto/mldsa is unavailable in this build of OpenBao")

type Parameters struct{}

func MLDSA44() Parameters { return Parameters{} }
func MLDSA65() Parameters { return Parameters{} }
func MLDSA87() Parameters { return Parameters{} }

func (p Parameters) String() string { return "" }

type PublicKey struct{}

func (PublicKey) Bytes() []byte               { return nil }
func (PublicKey) Equal(crypto.PublicKey) bool { return false }
func (PublicKey) Parameters() Parameters      { return Parameters{} }

type PrivateKey struct{}

func (PrivateKey) Bytes() []byte                                             { return nil }
func (PrivateKey) PublicKey() *PublicKey                                     { return nil }
func (PrivateKey) Public() crypto.PublicKey                                  { return nil }
func (PrivateKey) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) { return nil, err }

func GenerateKey(Parameters) (*PrivateKey, error)           { return nil, err }
func NewPublicKey(Parameters, []byte) (*PublicKey, error)   { return nil, err }
func NewPrivateKey(Parameters, []byte) (*PrivateKey, error) { return nil, err }

func Verify(*PublicKey, []byte, []byte, any) error { return err }
