// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package boundedmeta

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
// (internal/signerapp/signing/bounded_agreement_test.go), not by sharing this.
type PathDeclaration struct {
	Contract     string
	SpendEffects []string
	// MaxFee is nil when the account has no fee ceiling: a bounded host has
	// one, a plain host doesn't.
	MaxFee       *uint64
	Layer3Policy string
	Rekey        RekeySetting
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
		return PathDeclaration{}, fmt.Errorf("bounded authorization metadata is nil")
	}
	declaration := PathDeclaration{
		Contract:     metadata.Contract,
		SpendEffects: slices.Clone(metadata.SpendEffects),
		Layer3Policy: metadata.Layer3Policy,
		Rekey:        metadata.Rekey,
		RekeyList:    metadata.RekeyList != nil,
	}
	declaration.MaxFee = CloneMaxFee(metadata.MaxFee)
	if err := ValidateRekeySetting(metadata.Rekey); err != nil {
		return PathDeclaration{}, err
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
	return slices.Contains(declaration.SpendEffects, effect)
}
