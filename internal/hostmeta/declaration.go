// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package hostmeta

import (
	"fmt"
	"slices"
)

// RekeySetting is how a bounded account answers a pure rekey.
type RekeySetting string

const (
	// RekeyRefused gives the account no rekey path.
	RekeyRefused RekeySetting = "refused"
	// RekeySpendingKey lets the spending key authorize a pure rekey: alone, or
	// with the cosigner on a cosigned account.
	RekeySpendingKey RekeySetting = "spending_key"
)

// CosignerOverlay is the cosigner a bounded account requires, and on which paths.
type CosignerOverlay struct {
	ComponentKeyType string
	RequiredOn       []string
}

// PathDeclaration is what a bounded account allows: the value it may spend, under
// which Layer 3 policy, how it may be rekeyed, and which cosigner it needs. The
// signer's classifier reads it, through txeffects.ClassifyFor. The renderer still
// works from the composer's profile, so the two are held together by test
// (internal/signerapp/signing/host_agreement_test.go), not by sharing this.
type PathDeclaration struct {
	Contract string
	// Bounds is the bounded host's spend effects, fee ceiling and Layer 3
	// policy; nil on a plain host, which has none of them.
	Bounds *Bounds
	Rekey  RekeySetting
	// RekeyList is set when the account has a rekey-to list. Under rekey:
	// refused that is "only these": a pure rekey may go to a listed address and
	// nowhere else. Under a spending-key rekey it is "plus cosigned": a listed
	// address takes the spending key alone, any other the cosigner too.
	RekeyList bool
	Cosigner  *CosignerOverlay
}

// Declaration projects stored bounded metadata onto its path declaration.
func (metadata *Metadata) Declaration() (PathDeclaration, error) {
	if metadata == nil {
		return PathDeclaration{}, fmt.Errorf("host metadata is nil")
	}
	declaration := PathDeclaration{
		Contract:  metadata.Contract,
		Bounds:    cloneBounds(metadata.Bounds),
		Rekey:     metadata.Rekey,
		RekeyList: metadata.RekeyList != nil,
	}
	if metadata.Cosigner != nil {
		declaration.Cosigner = &CosignerOverlay{
			ComponentKeyType: metadata.Cosigner.ComponentKeyType,
			RequiredOn:       slices.Clone(metadata.Cosigner.RequiredOn),
		}
	}
	return declaration, nil
}

// AllowsSpendEffect reports whether the declaration lets the account spend this way.
func (declaration PathDeclaration) AllowsSpendEffect(effect string) bool {
	return declaration.Bounds != nil && slices.Contains(declaration.Bounds.SpendEffects, effect)
}
