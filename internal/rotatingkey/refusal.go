// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rotatingkey

// RekeyTargetRefusal is why an account can't be rekeyed to the rotating
// account at target. apshell refuses with it before building the rekey, and
// the signer refuses with it as a signer invariant, so both give the same
// reason.
func RekeyTargetRefusal(target string) string {
	return "cannot rekey to " + target + ": it is a rotating account, and its address is a one-time stage key; " +
		"an account rekeyed to it would be stuck on that stage, and every signature would reuse that key"
}

// StageRekeyTargetRefusal is why an account can't be rekeyed to target, a stage
// address of the rotating account at account.
func StageRekeyTargetRefusal(target, account string) string {
	return "cannot rekey to " + target + ": it is a stage key of the rotating account " + account + ", and a stage key is used once; " +
		"an account rekeyed to it would be stuck on that stage, and every signature would reuse that key"
}

// StageOwners names the accounts whose stage tables hold an address, as far as
// the signer knows. More than one can: a table is a cache, and a stale one can
// hold another account's stage.
type StageOwners func(address string) []string

// RefuseRekeyTarget is the one rule for whether a signer refuses a rekey to
// target because of the rotating accounts it holds. It returns the reason.
//
//   - target is a rotating account in keyTypes, the signer's key types by
//     address. Its address is its stage 0 key.
//   - target is a stage address of one, by stageOwners. A nil stageOwners knows
//     none. An owner that is not a held rotating account doesn't count; of
//     those that are, the lowest is named, so the reason is the same each time.
//
// The rule has no exception. A rotation rekeys a rotating account to its own
// next stage, which this rule would refuse: the caller that signs rotations
// leaves out the targets it issued and proved itself, and asks about the rest.
//
// The rule sees what the signer holds and knows. A rotating account held
// elsewhere passes, and so does a stage the signer hasn't derived yet.
func RefuseRekeyTarget(target string, keyTypes map[string]string, stageOwners StageOwners) (reason string, refused bool) {
	if IsRotatingKeyType(keyTypes[target]) {
		return RekeyTargetRefusal(target), true
	}
	if stageOwners == nil {
		return "", false
	}
	held := ""
	for _, account := range stageOwners(target) {
		if IsRotatingKeyType(keyTypes[account]) && (held == "" || account < held) {
			held = account
		}
	}
	if held == "" {
		return "", false
	}
	return StageRekeyTargetRefusal(target, held), true
}
