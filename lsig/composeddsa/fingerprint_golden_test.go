// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/internal/tealtemplate"
)

// syntheticFingerprintConfig sets every canonical fingerprint field, under the
// given salt style and ops.
func syntheticFingerprintConfig(saltStyle lsigsalt.Style, ops DSAOps) Config {
	min := uint64(1)
	max := uint64(999)
	return Config{
		KeyType:      "synthetic-dsa-v7",
		FamilyName:   "synthetic-dsa",
		Version:      7,
		DisplayName:  "Synthetic DSA",
		Description:  "Exercises every canonical fingerprint field",
		Ops:          ops,
		SaltStyle:    saltStyle,
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
		OpcodeProfile: lsigresource.DefaultOpcodeProfile(lsigresource.SingleTransactionOpcodeCeiling),
	}
}

// The goldens were computed on the code before counter salting was retired,
// for the two salt styles a template can still have.
func TestSyntheticComposedDSACompatibilityFingerprint(t *testing.T) {
	for _, test := range []struct {
		style lsigsalt.Style
		ops   DSAOps
		want  string
	}{
		{style: lsigsalt.StyleNone, ops: testOps{}, want: "1:7fcefee802ed3a478ba98bc4d4f0372d1eeae890a0ebae6cd2e128b685dc3c37"},
		{style: lsigsalt.StyleAlgodAutoSalt, ops: autoSaltTestOps{}, want: "1:d25542ef6f57768bd15b3df1105fc32c199ce19d4c64ca6753ed07102adc2c7a"},
	} {
		t.Run(string(test.style), func(t *testing.T) {
			got := NewComposedDSA(syntheticFingerprintConfig(test.style, test.ops)).CompatibilityFingerprint()
			if got != test.want {
				t.Fatalf("CompatibilityFingerprint() = %q, want %q", got, test.want)
			}
		})
	}
}
