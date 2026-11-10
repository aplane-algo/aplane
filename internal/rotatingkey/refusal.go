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

// StageOwner names the rotating account that has an address as one of its stage
// addresses, when the signer knows of one.
type StageOwner func(address string) (account string, ok bool)

// RefuseRekeyTarget is the one rule for whether a signer refuses a rekey to
// target because of the rotating accounts it holds. It returns the reason.
//
//   - target is a rotating account in keyTypes, the signer's key types by
//     address. Its address is its stage 0 key.
//   - target is a stage address of one, by stageOwner. A nil stageOwner knows
//     none.
//
// sender is the account being rekeyed, or "" when there is none yet (a rekey-to
// list at account generation). A rotating account's rekey to one of its own
// stages is the rotation itself and is not refused: only the rotating flow
// signs for a rotating account, and it checks the stage.
//
// The rule sees what the signer holds and knows. A rotating account held
// elsewhere passes, and so does a stage the signer hasn't derived yet.
func RefuseRekeyTarget(sender, target string, keyTypes map[string]string, stageOwner StageOwner) (reason string, refused bool) {
	if IsRotatingKeyType(keyTypes[target]) {
		return RekeyTargetRefusal(target), true
	}
	if stageOwner == nil {
		return "", false
	}
	account, ok := stageOwner(target)
	if !ok || account == sender || !IsRotatingKeyType(keyTypes[account]) {
		return "", false
	}
	return StageRekeyTargetRefusal(target, account), true
}
