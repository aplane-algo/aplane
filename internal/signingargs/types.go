// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package signingargs owns the internal model for signing-time LogicSig
// argument metadata. Key files, signer cache records, and wire DTOs project
// from this model instead of maintaining parallel struct definitions.
package signingargs

import "github.com/aplane-algo/aplane/internal/lsigprovider"

// Info describes one signing-time LogicSig argument.
// Position is implicit: the index in a []Info corresponds to the TEAL arg index.
type Info struct {
	Name        string `json:"name"`
	Label       string `json:"label,omitempty"`
	Description string `json:"description,omitempty"`
	Type        string `json:"type"`
	Required    bool   `json:"required,omitempty"`
	ByteLength  int    `json:"byte_length,omitempty"`
}

// FromRuntimeDefs projects provider runtime-argument definitions into the
// durable/internal signing-argument model.
func FromRuntimeDefs(defs []lsigprovider.RuntimeArgDef) []Info {
	if len(defs) == 0 {
		return nil
	}
	out := make([]Info, len(defs))
	for i, def := range defs {
		out[i] = Info{
			Name:        def.Name,
			Label:       def.Label,
			Description: def.Description,
			Type:        def.Type,
			Required:    def.Required,
			ByteLength:  def.ByteLength,
		}
	}
	return out
}

// ToRuntimeDefs converts internal signing-argument metadata back to provider
// runtime-argument definitions for signing-time validation.
func ToRuntimeDefs(args []Info) []lsigprovider.RuntimeArgDef {
	if len(args) == 0 {
		return nil
	}
	out := make([]lsigprovider.RuntimeArgDef, len(args))
	for i, arg := range args {
		out[i] = lsigprovider.RuntimeArgDef{
			Name:        arg.Name,
			Label:       arg.Label,
			Description: arg.Description,
			Type:        arg.Type,
			Required:    arg.Required,
			ByteLength:  arg.ByteLength,
		}
	}
	return out
}
