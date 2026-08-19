// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policytui

import (
	"strings"

	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policyview"
	"github.com/aplane-algo/aplane/internal/signerapp/policyeditor"
)

// Test-only conveniences: production constructs the editor with
// NewWithTarget and marshals through target-aware helpers.

func New(store policyeditor.Store, stored *policy.StoredConfig, dataDir string) Model {
	return NewWithTarget(store, stored, dataDir, policyeditor.TargetSigner)
}

func transferGuardRows(routes []policy.StoredTransferRoute) []transferGuardRow {
	return policyview.TransferGuardRows(routes)
}

func routeToGuardRow(index int, route policy.StoredTransferRoute) transferGuardRow {
	return policyview.RouteToGuardRow(index, route)
}

func marshalStored(stored *policy.StoredConfig) ([]byte, error) {
	return marshalStoredForTarget(stored, policyeditor.TargetSigner)
}

func joinAssetTerms(terms []policy.StoredAssetTerm) string {
	if len(terms) == 0 {
		return "-"
	}
	raw := make([]string, 0, len(terms))
	for _, term := range terms {
		raw = append(raw, term.Raw)
	}
	return strings.Join(raw, ",")
}
