// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

// SignerRekeys is a signer's one rejection rule for a transaction that rekeys.
// It only rejects: a rekey it lets through goes on through the rest of policy
// as any transaction does, to the rekey warning, review rules, operator
// approval and user_auto_approve. The cosigner role has its own rekey rules
// (reject_rekey and rekey_policy) and never reads it.
type SignerRekeys string

const (
	// RekeysRejectAll rejects every rekey.
	RekeysRejectAll SignerRekeys = "reject_all_rekeys"
	// RekeysRejectForeign rejects a rekey unless this node holds the target.
	// It is the default.
	RekeysRejectForeign SignerRekeys = "reject_foreign_rekey"
	// RekeysAllow rejects nothing.
	RekeysAllow SignerRekeys = "allow_rekeys"
)

// Valid reports whether r is one of the three settings.
func (r SignerRekeys) Valid() bool {
	switch r {
	case RekeysRejectAll, RekeysRejectForeign, RekeysAllow:
		return true
	}
	return false
}

// rekeysStrictness orders the settings for diffs. A value that is not one of
// the three ranks as strictest, as the lint treats it.
func rekeysStrictness(r SignerRekeys) int {
	switch r {
	case RekeysAllow:
		return 0
	case RekeysRejectForeign:
		return 1
	default:
		return 2
	}
}
