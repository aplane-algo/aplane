// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"errors"
	"os"
	"testing"

	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/witness"
)

// damageTokenFile overwrites selector's token file in the selected
// generation with bytes that do not decrypt.
func damageTokenFile(t *testing.T, server *Signer, selector string) string {
	t.Helper()
	active, err := server.productRuntime().ActivePaths()
	if err != nil {
		t.Fatal(err)
	}
	path := active.SourceTokenPath(selector)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("%s has no token file to damage: %v", selector, err)
	}
	if err := os.WriteFile(path, []byte("not a source token file"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// unlockIntoRecovery locks the node and unlocks it again, through the real
// unlock and reload, and requires the unlock to enter recovery: the
// passphrase was right, so the operator repairs the store from there.
func unlockIntoRecovery(t *testing.T, server *Signer) {
	t.Helper()
	ir := server.productRuntime()
	ir.Lock()
	success, keyCount, errMsg, code := server.adminServices().UnlockIdentity(testPassphrase)
	if !success || keyCount != 0 || errMsg != "" || code != protocol.ResultCodeRecoveryBlocked {
		t.Fatalf("UnlockIdentity() = (%v, %d, %q, %q), want recovery", success, keyCount, errMsg, code)
	}
	if !ir.IsRecovery() || ir.IsUnlocked() {
		t.Fatalf("runtime state = recovery %v unlocked %v, want recovery with signing blocked", ir.IsRecovery(), ir.IsUnlocked())
	}
	requireServedToken(t, server, policy.DefaultKey, "")
}

// A key's token file that no longer decrypts puts the node in recovery at
// unlock, and a recovery-mode restore with replace_existing replaces it with
// the archived one; the node then unlocks cleanly and serves the token.
func TestADamagedKeyTokenFileEntersRecoveryAndRestoreRepairsIt(t *testing.T) {
	server, cleanup := setupTestNode(t, noderole.RoleCosigner, cosignerDefaultWithSources(t))
	defer cleanup()
	key := generateTestKey(t, server, witness.Falcon1024V1)
	setTokenForBackupTest(t, server, key, "tok-archived")
	archivePath := backupForTokenTest(t, server)

	damageTokenFile(t, server, key)
	unlockIntoRecovery(t, server)

	if refused := restoreForTokenTest(server, archivePath, "restore-refused", false); refused.Success ||
		refused.Code != protocol.ResultCodeRestoreConflict {
		t.Fatalf("recovery restore without replacement = %+v, want a conflict", refused)
	}
	if repaired := restoreForTokenTest(server, archivePath, "restore-repair", true); !repaired.Success ||
		len(repaired.SourceTokensRestored) != 1 || repaired.SourceTokensRestored[0] != key {
		t.Fatalf("recovery restore with replacement = %+v", repaired)
	}

	ir := server.productRuntime()
	ir.Lock()
	if success, _, errMsg, code := server.adminServices().UnlockIdentity(testPassphrase); !success || errMsg != "" || code != "" {
		t.Fatalf("UnlockIdentity(repaired) = (%v, %q, %q), want a clean unlock", success, errMsg, code)
	}
	if ir.IsRecovery() || !ir.IsUnlocked() {
		t.Fatalf("runtime state after repair = recovery %v unlocked %v", ir.IsRecovery(), ir.IsUnlocked())
	}
	requireServedToken(t, server, key, "tok-archived")
}

// The node default's token file is not backed up, so nothing restores it;
// damaged, it puts the node in recovery, and once it is discarded (what
// apstore source token discard does, with the daemon stopped) the node
// unlocks and its sources have no token.
func TestADamagedDefaultTokenFileEntersRecoveryUntilDiscarded(t *testing.T) {
	server, cleanup := setupTestNode(t, noderole.RoleCosigner, cosignerDefaultWithSources(t))
	defer cleanup()
	setTokenForBackupTest(t, server, policy.DefaultKey, "tok-default")

	path := damageTokenFile(t, server, policy.DefaultKey)
	unlockIntoRecovery(t, server)

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	ir := server.productRuntime()
	ir.Lock()
	if success, _, errMsg, code := server.adminServices().UnlockIdentity(testPassphrase); !success || errMsg != "" || code != "" {
		t.Fatalf("UnlockIdentity(discarded) = (%v, %q, %q), want a clean unlock", success, errMsg, code)
	}
	if ir.IsRecovery() || !ir.IsUnlocked() {
		t.Fatalf("runtime state after the discard = recovery %v unlocked %v", ir.IsRecovery(), ir.IsUnlocked())
	}
	requireServedToken(t, server, policy.DefaultKey, "")
}

// A token file on a signer node is a node role conflict, not damage a
// restore repairs: the unlock fails and the node fails closed, as it does
// for a key its role forbids.
func TestATokenFileOnASignerNodeFailsTheNodeClosed(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ir := server.productRuntime()
	active, err := ir.ActivePaths()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(active.SourceTokenPath(storepaths.SourceTokensDefaultSelector), []byte("any"), 0o600); err != nil {
		t.Fatal(err)
	}
	ir.Lock()
	success, _, errMsg, code := server.adminServices().UnlockIdentity(testPassphrase)
	if success || code == protocol.ResultCodeRecoveryBlocked || errMsg == "" {
		t.Fatalf("UnlockIdentity() = (%v, %q, %q), want a failed unlock", success, errMsg, code)
	}
	if ir.IsRecovery() || ir.IsUnlocked() {
		t.Fatalf("runtime state = recovery %v unlocked %v, want locked", ir.IsRecovery(), ir.IsUnlocked())
	}
	if err := server.nodeFailState.Err(); !errors.Is(err, productruntime.ErrNodeFailClosed) {
		t.Fatalf("node failure = %v, want the node failed closed", err)
	}
}
