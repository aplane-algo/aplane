// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package v1

import (
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	"github.com/aplane-algo/aplane/lsig/ecdsak1/family"
)

// ComposedECDSA is the explicit family name for composed ecdsak1 providers.
type ComposedECDSA = composeddsa.ComposedDSA

// ComposedECDSAConfig configures an ecdsak1 composed provider.
type ComposedECDSAConfig struct {
	KeyType     string
	BaseKeyType string
	FamilyName  string
	Version     int
	DisplayName string
	Description string

	Base        family.DSABase
	TEALSuffix  string
	SaltStyle   lsigsalt.Style
	Params      []lsigprovider.ParameterDef
	RuntimeArgs []lsigprovider.RuntimeArgDef
}

// NewComposedECDSA returns an ecdsak1 composed provider powered by generic engine.
func NewComposedECDSA(cfg ComposedECDSAConfig) *ComposedECDSA {
	base := cfg.Base
	if base == nil {
		base = family.ECDSAK1Base
	}
	ops := NewECDSAK1Ops(base)

	return composeddsa.NewComposedDSA(composeddsa.Config{
		KeyType:     cfg.KeyType,
		BaseKeyType: cfg.BaseKeyType,
		FamilyName:  cfg.FamilyName,
		Version:     cfg.Version,
		DisplayName: cfg.DisplayName,
		Description: cfg.Description,
		Ops:         ops,
		TEALSuffix:  cfg.TEALSuffix,
		SaltStyle:   cfg.SaltStyle,
		Params:      cfg.Params,
		RuntimeArgs: cfg.RuntimeArgs,
	})
}
