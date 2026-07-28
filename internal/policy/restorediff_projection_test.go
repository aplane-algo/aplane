// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"reflect"
	"testing"
)

// TestRestoreDiffProjectionCoversPolicyFields walks every struct the restore
// policy projection renders and requires each exported field to be either
// projected or explicitly skipped with a reason. Adding a policy field
// without deciding its projection fate fails this test — a field the diff
// silently omits would let a restored policy differ from the source without
// the review surfacing it.
func TestRestoreDiffProjectionCoversPolicyFields(t *testing.T) {
	cases := []struct {
		typ       reflect.Type
		projected []string
		skipped   map[string]string
	}{
		{
			typ: reflect.TypeOf(Config{}),
			projected: []string{
				"RejectForeignRekey", "RejectRekey", "RejectCloseRemainder",
				"RejectAssetClose", "RejectClawback", "AlwaysReviewWarnings",
				"AutoApproveSelfNoOpTransfer", "MaxFeeMicroAlgos",
				"ReviewAlgoPayments", "MaxAlgoPayments", "ReviewASAAmounts",
				"MaxASAAmounts", "TransferPolicy", "RekeyPolicy",
			},
			skipped: map[string]string{
				"KeyOverrides":        "each selector is projected individually via ForKey",
				"Sentry":              "role domains produce their own projections",
				"GenesisHashResolver": "runtime plumbing, not policy data",
				"FormatASAAmount":     "runtime plumbing, not policy data",
			},
		},
		{
			typ: reflect.TypeOf(TransferPolicy{}),
			projected: []string{
				"Enabled", "OnNoRoute", "CloseOnNoRoute", "ClawbackOnNoRoute",
				"BlockedDestinations", "AddressSets", "AssetSets", "Routes",
			},
		},
		{
			typ: reflect.TypeOf(CompiledTransferRoute{}),
			projected: []string{
				"ID", "Enabled", "NetworkWildcard", "Networks", "Sources",
				"AssetSources", "Assets", "Destinations", "Limits",
				"LimitsByNetwork", "AllowClose", "AllowClawback",
			},
			skipped: map[string]string{
				"Description": "cosmetic label with no policy effect",
			},
		},
		{
			typ:       reflect.TypeOf(AmountLimits{}),
			projected: []string{"ReviewAbove", "RejectAbove"},
		},
		{
			typ:       reflect.TypeOf(compiledAddressSet{}),
			projected: []string{"Flat", "ByNetwork"},
		},
		{
			typ:       reflect.TypeOf(compiledAssetSet{}),
			projected: []string{"ByNetwork"},
		},
		{
			typ:       reflect.TypeOf(RekeyPolicy{}),
			projected: []string{"Allowed"},
		},
		{
			typ:       reflect.TypeOf(CompiledRekeyRule{}),
			projected: []string{"Sender", "Targets"},
		},
		{
			typ:       reflect.TypeOf(compiledAddressTerms{}),
			projected: []string{"Wildcard", "Self", "Direct", "Sets"},
		},
		{
			typ:       reflect.TypeOf(compiledAssetTerms{}),
			projected: []string{"Wildcard", "Algo", "ASAIDs", "Sets"},
		},
		{
			typ:       reflect.TypeOf(compiledRekeyAddressTerms{}),
			projected: []string{"Direct"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.typ.Name(), func(t *testing.T) {
			classified := make(map[string]bool, len(tc.projected)+len(tc.skipped))
			for _, name := range tc.projected {
				if classified[name] {
					t.Errorf("field %s listed twice", name)
				}
				classified[name] = true
			}
			for name := range tc.skipped {
				if classified[name] {
					t.Errorf("field %s is both projected and skipped", name)
				}
				classified[name] = true
			}

			exported := make(map[string]bool)
			for i := 0; i < tc.typ.NumField(); i++ {
				field := tc.typ.Field(i)
				if field.PkgPath != "" {
					continue // unexported fields cannot cross the package API
				}
				exported[field.Name] = true
				if !classified[field.Name] {
					t.Errorf(
						"exported field %s.%s is neither projected nor explicitly skipped; "+
							"extend the restore diff projection (restorediff.go) or record a skip reason here",
						tc.typ.Name(), field.Name,
					)
				}
			}
			for name := range classified {
				if !exported[name] {
					t.Errorf("listed field %s.%s no longer exists", tc.typ.Name(), name)
				}
			}
		})
	}
}
