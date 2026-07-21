// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package v1

import (
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/internal/tealtemplate"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
)

// ComposedFalcon is the explicit Falcon name for the same underlying type.
type ComposedFalcon = composeddsa.ComposedDSA

// ComposedFalconConfig configures a Falcon composed provider.
type ComposedFalconConfig struct {
	KeyType     string // e.g., "test.falcon1024-policy.v1"
	BaseKeyType string // e.g., "aplane.falcon1024.v1"
	FamilyName  string // e.g., "falcon1024"
	Version     int
	DisplayName string
	Description string

	Base         family.DSABase
	TEALSuffix   string
	SaltStyle    lsigsalt.Style
	TemplateMode string
	TemplateVars []tealtemplate.TemplateVariable
	Params       []lsigprovider.ParameterDef
	RuntimeArgs  []lsigprovider.RuntimeArgDef
}

// NewComposedFalcon returns a Falcon-composed provider powered by the generic
// ComposedDSA engine.
func NewComposedFalcon(cfg ComposedFalconConfig) *ComposedFalcon {
	base := cfg.Base
	if base == nil {
		base = family.FalconBase
	}
	ops := NewFalconOps(base)

	return composeddsa.NewComposedDSA(composeddsa.Config{
		KeyType:      cfg.KeyType,
		BaseKeyType:  cfg.BaseKeyType,
		FamilyName:   cfg.FamilyName,
		Version:      cfg.Version,
		DisplayName:  cfg.DisplayName,
		Description:  cfg.Description,
		Ops:          ops,
		TEALSuffix:   cfg.TEALSuffix,
		SaltStyle:    cfg.SaltStyle,
		TemplateMode: cfg.TemplateMode,
		TemplateVars: cfg.TemplateVars,
		Params:       cfg.Params,
		RuntimeArgs:  cfg.RuntimeArgs,
	})
}
