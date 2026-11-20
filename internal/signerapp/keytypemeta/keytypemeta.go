// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package keytypemeta projects the metadata a LogicSig provider declares for
// its key type, its creation parameters and runtime arguments (a bounded
// contract's runtime arguments among them), into the signer API's wire types.
// /keytypes, /keys and the admin template library all project through it, so
// each maps the same fields and gives each description as its author means it
// (lsigprovider.DescriptionText).
package keytypemeta

import (
	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// CreationParams projects creation parameters. None is an empty list, not
// nil, which /keytypes serves as [].
func CreationParams(params []lsigprovider.ParameterDef) []signerapi.CreationParamInfo {
	out := make([]signerapi.CreationParamInfo, len(params))
	for i, p := range params {
		out[i] = signerapi.CreationParamInfo{
			Name:        p.Name,
			Label:       p.Label,
			Description: lsigprovider.DescriptionText(p.Description),
			Type:        p.Type,
			Required:    p.Required,
			MaxLength:   p.MaxLength,
			InputModes:  inputModes(p.InputModes),
			Options:     append([]string(nil), p.Options...),
			MinItems:    p.MinItems,
			MaxItems:    p.MaxItems,
			Example:     p.Example,
			Placeholder: p.Placeholder,
			Min:         p.Min,
			Max:         p.Max,
			Default:     p.Default,
		}
	}
	return out
}

func inputModes(modes []lsigprovider.InputMode) []signerapi.InputModeInfo {
	if len(modes) == 0 {
		return nil
	}
	out := make([]signerapi.InputModeInfo, len(modes))
	for i, mode := range modes {
		out[i] = signerapi.InputModeInfo{
			Name:       mode.Name,
			Label:      mode.Label,
			Transform:  mode.Transform,
			ByteLength: mode.ByteLength,
			InputType:  mode.InputType,
		}
	}
	return out
}

// RuntimeArgs projects runtime arguments: a key type's, or the signing
// arguments an aplane key recorded when it was created. None is an empty
// list, not nil, which /keytypes serves as [].
func RuntimeArgs(args []lsigprovider.RuntimeArgDef) []signerapi.RuntimeArgInfo {
	out := make([]signerapi.RuntimeArgInfo, len(args))
	for i, a := range args {
		out[i] = runtimeArg(a)
	}
	return out
}

// BoundedRuntimeArgs projects a bounded contract's runtime arguments. None is
// an empty list, not nil, which the wire serves as [].
func BoundedRuntimeArgs(args []boundedmeta.RuntimeArg) []signerapi.RuntimeArgInfo {
	out := make([]signerapi.RuntimeArgInfo, len(args))
	for i, a := range args {
		out[i] = runtimeArg(lsigprovider.RuntimeArgDef(a))
	}
	return out
}

func runtimeArg(a lsigprovider.RuntimeArgDef) signerapi.RuntimeArgInfo {
	return signerapi.RuntimeArgInfo{
		Name:        a.Name,
		Label:       a.Label,
		Description: lsigprovider.DescriptionText(a.Description),
		Type:        a.Type,
		Required:    a.Required,
		ByteLength:  a.ByteLength,
		MaxSize:     a.MaxSize,
	}
}
