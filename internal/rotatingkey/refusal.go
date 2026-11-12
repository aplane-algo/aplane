// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rotatingkey

// RekeyTargetRefusal is why an account can't be rekeyed to the rotating
// account at target. apshell refuses with it before building the rekey, and
// so do key generation and the bounded rekey-to list. The signer refuses such
// a rekey as rekey_target_not_valid, since every rotating aplane key records
// that it is not a valid rekey target; its rotating invariant, a second line,
// gives this reason only if a rotating key's record ever said otherwise.
func RekeyTargetRefusal(target string) string {
	return "cannot rekey to " + target + ": " + RekeyTargetReason
}

// RekeyTargetReason is why a rotating account is no rekey target, as
// RekeyTargetRefusal and the signer's rekey_target_not_valid refusal of a
// rotating target give it.
const RekeyTargetReason = "it is a rotating account, and its address is a one-time stage key; " +
	"an account rekeyed to it would be stuck on that stage, and every signature would reuse that key"
