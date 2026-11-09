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
