// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/templaterepair"
	"github.com/aplane-algo/aplane/internal/templatestore"
)

// A store that unlock puts into recovery for its template records unlocks
// normally once the offline template repair has repaired it with the signer
// stopped: an externally edited record re-pinned, an orphaned one dropped.
func TestOfflineTemplateRepairLetsTheSignerUnlock(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	suffix := time.Now().UnixNano()
	edited := testTemplateKeyType(fmt.Sprintf("offline-repair-edited-%d", suffix))
	orphaned := testTemplateKeyType(fmt.Sprintf("offline-repair-orphan-%d", suffix))
	templates := server.adminServices().templateApp()
	for _, keyType := range []string{edited, orphaned} {
		t.Cleanup(func() { lsigprovider.Unregister(keyType) })
		family := strings.TrimSuffix(strings.TrimPrefix(keyType, "test."), ".v1")
		yaml := renderGenericTemplateYAML(family, 1, "Offline Repair", "offline repair")
		if result := templates.ImportInstalledTemplate(adminproto.ImportInstalledTemplateRequest{TemplateYAML: yaml}); !result.Success {
			t.Fatalf("ImportInstalledTemplate(%s) = %+v", keyType, result)
		}
	}
	paths := mustActiveKeyPaths(t, server)
	rec, ok, err := keytypestate.Get(paths, edited)
	if err != nil || !ok {
		t.Fatalf("Get(%s) = %v, %v", edited, ok, err)
	}
	installed := rec.Fingerprint
	rec.Fingerprint = "1:" + strings.Repeat("b", 64)
	if err := keytypestate.Put(paths, rec); err != nil {
		t.Fatal(err)
	}
	orphanPath, err := templatestore.GetTemplateFilePathForPaths(paths, orphaned)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(orphanPath); err != nil {
		t.Fatal(err)
	}

	unlockFresh := func() (bool, string) {
		t.Helper()
		server.runtime.Lock()
		// A fresh process has registered no template.
		lsigprovider.Unregister(edited)
		lsigprovider.Unregister(orphaned)
		success, _, errMsg, code := server.adminServices().UnlockIdentity(testPassphrase)
		if !success {
			t.Fatalf("UnlockIdentity() failed: %s", errMsg)
		}
		return server.runtime.IsUnlocked(), code
	}
	if unlocked, code := unlockFresh(); unlocked || code != protocol.ResultCodeRecoveryBlocked || !server.runtime.IsRecovery() {
		t.Fatalf("unlock of the damaged store = unlocked %v, code %q, recovery %v; want recovery_blocked",
			unlocked, code, server.runtime.IsRecovery())
	}

	// apsigner stopped: nothing holds the store, and apstore opens it as
	// any offline command does.
	server.runtime.Lock()
	damaged, kr, err := genstore.ResolveStoreRoot(server.keyPaths, testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	result, err := templaterepair.Repair(templaterepair.Options{
		Paths: server.keyPaths, Current: damaged, Keyring: kr,
		Role: noderole.RoleSigner, DataDir: server.dataDir, Config: server.config,
	}, map[string]templaterepair.Action{edited: templaterepair.ActionRepin, orphaned: templaterepair.ActionDrop})
	kr.Zero()
	if err != nil {
		t.Fatalf("Repair() error = %v", err)
	}

	if unlocked, code := unlockFresh(); !unlocked || code != "" || server.runtime.IsRecovery() {
		t.Fatalf("unlock of the repaired store = unlocked %v, code %q, recovery %v; want a normal unlock",
			unlocked, code, server.runtime.IsRecovery())
	}
	active, err := server.productRuntime().ActiveKeyPaths()
	if err != nil {
		t.Fatal(err)
	}
	serving, err := genstore.Resolve(active)
	if err != nil || serving.GenerationID() != result.GenerationID {
		t.Fatalf("unlocked signer serves generation %s (%v), want the repair's %s", serving.GenerationID(), err, result.GenerationID)
	}
	if rec, ok, err := keytypestate.Get(active, edited); err != nil || !ok || rec.Fingerprint != installed {
		t.Fatalf("re-pinned record = %+v, %v, %v; want fingerprint %s", rec, ok, err, installed)
	}
	if lsigprovider.Get(edited) == nil {
		t.Fatalf("the re-pinned template %s is not registered after unlock", edited)
	}
	if _, ok, err := keytypestate.Get(active, orphaned); ok || err != nil {
		t.Fatalf("dropped record after unlock = %v, %v; want gone", ok, err)
	}
}
