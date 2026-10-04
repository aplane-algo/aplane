// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/storepaths"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// Archive maintenance runs in recovery, where a failed reload can leave the
// runtime's cached generation behind the store root. Listing and pruning must
// act on the generation the root selects, never mutate the superseded one.
func TestDeletedArchiveMaintenanceFollowsTheStoreRoot(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ir := server.productRuntime()
	cached, err := ir.ActivePaths()
	if err != nil {
		t.Fatal(err)
	}

	archived := filepath.ToSlash(filepath.Join("deleted", "keys", types.Address{7}.String()+".key"))
	_, kr, err := genstore.ResolveStoreRoot(ir.KeyPaths(), testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	next, err := genstore.NewGenerationID(time.Now().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := genstore.Mint(ir.KeyPaths(), genstore.MintRequest{
		GenerationID: next, Parent: cached.GenerationID(), Operation: "test", OperationID: "test-" + next,
		CreatedAt: time.Now(), Integrity: kr,
		Apply: func(staged storepaths.GenPaths) error {
			return os.WriteFile(filepath.Join(staged.Dir(), filepath.FromSlash(archived)), []byte("archived"), 0o600)
		},
	}); err != nil {
		kr.Zero()
		t.Fatal(err)
	}
	kr.Zero()
	if stale, _ := ir.ActivePaths(); stale.GenerationID() != cached.GenerationID() {
		t.Fatalf("setup: runtime followed the root to %s; want it still bound to %s", stale.GenerationID(), cached.GenerationID())
	}

	svc := server.adminServices()
	listed := svc.ListDeletedArchive()
	if listed.Error != "" || len(listed.Entries) != 1 || listed.Entries[0].Path != archived {
		t.Fatalf("ListDeletedArchive() = %+v, want the root-selected generation's entry %s", listed, archived)
	}
	pruned := svc.PruneDeletedArchive(adminproto.PruneDeletedArchiveRequest{Entries: []string{archived}})
	if !pruned.Success || len(pruned.Pruned) != 1 || pruned.Pruned[0].AlreadyAbsent {
		t.Fatalf("PruneDeletedArchive() = %+v, want the entry removed", pruned)
	}
	if _, err := os.Stat(filepath.Join(ir.KeyPaths().GenerationPaths(next).Dir(), filepath.FromSlash(archived))); !os.IsNotExist(err) {
		t.Fatalf("archived entry still in the selected generation: %v", err)
	}
}
