// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/tealtemplate"
)

func TestSyntheticComposedDSACompatibilityFingerprint(t *testing.T) {
	min := uint64(1)
	max := uint64(999)
	dsa := NewComposedDSA(Config{
		KeyType:      "synthetic-dsa-v7",
		FamilyName:   "synthetic-dsa",
		Version:      7,
		DisplayName:  "Synthetic DSA",
		Description:  "Exercises every canonical fingerprint field",
		Ops:          testOps{},
		TemplateMode: "strict",
		TEALSuffix:   "$owner_const\nlen\nint 32\n==\nassert\nint 1\nreturn\n",
		TemplateVars: []tealtemplate.TemplateVariable{{
			Name:      "owner_const",
			Source:    tealtemplate.SourceParameter,
			Parameter: "owner",
			Type:      "address",
			Constant:  tealtemplate.ConstantByte,
		}},
		Params: []lsigprovider.ParameterDef{
			{Name: "owner", Type: "address", Required: true},
			{Name: "hash", Type: "bytes", Required: true, MaxLength: 64},
			{Name: "unlock_round", Type: "uint64", MaxLength: 20, Min: &min, Max: &max, Default: "100"},
			{Name: "recipients", Type: "address[]", MinItems: 1, MaxItems: 3},
		},
		RuntimeArgs: []lsigprovider.RuntimeArgDef{
			{Name: "preimage", Type: "bytes", Required: true, ByteLength: 32},
			{Name: "note", Type: "string"},
		},
	})

	got := dsa.CompatibilityFingerprint()
	const want = "1:093ba3ca5b1b555ede42b1c1e7d8e549750b3d2dcd234a7a37494f4b774c2a73"
	if got != want {
		t.Fatalf("CompatibilityFingerprint() = %q, want %q", got, want)
	}
}
