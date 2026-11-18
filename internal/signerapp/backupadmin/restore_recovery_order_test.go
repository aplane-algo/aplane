// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backupadmin

import (
	"errors"
	"sync/atomic"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// recoveryAtReleaseDeps reports whether the runtime was already in recovery
// when the store mutation lock was released.
type recoveryAtReleaseDeps struct {
	Deps
	ir                *productruntime.Runtime
	recoveryAtRelease bool
}

func (d *recoveryAtReleaseDeps) WithStoreMutation(fn func() error) error {
	return d.Deps.WithStoreMutation(func() error {
		err := fn()
		d.recoveryAtRelease = d.ir.IsRecovery()
		return err
	})
}

// A restore that leaves the runtime behind the store root must enter recovery
// before the mutation lock is released: until then the runtime may still
// serve the superseded generation, and a key write taking the lock would
// land in it.
func TestRestoreEntersRecoveryBeforeReleasingTheLock(t *testing.T) {
	tests := []struct {
		name    string
		arrange func(t *testing.T, paths storepaths.Paths, ir *productruntime.Runtime)
	}{
		{"a commit whose durability is unknown", func(t *testing.T, paths storepaths.Paths, ir *productruntime.Runtime) {
			identityDir := paths.ProductDir()
			fsutil.TestHook = func(op fsutil.HookOp, path string) error {
				if op == fsutil.OpDirSync && path == identityDir {
					return errors.New("simulated identity-directory sync failure")
				}
				return nil
			}
			t.Cleanup(func() { fsutil.TestHook = nil })
		}},
		{"a reload that fails after the commit", func(t *testing.T, paths storepaths.Paths, ir *productruntime.Runtime) {
			ir.SetReloadFunc(func([]byte, *keystore.KeySession) (*signertemplates.ReloadReport, error) {
				return nil, errors.New("reload failed")
			})
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paths := storepaths.NewPaths(t.TempDir())
			var reloads atomic.Int64
			ir := testUnlockedBackupIdentityRuntime(t, paths, &reloads)
			archivePath, _ := writeCredentialOnlyManagedArchive(t, paths)
			service := directRestoreTestService(paths, ir)
			deps := &recoveryAtReleaseDeps{Deps: service.Deps, ir: ir}
			service.Deps = deps
			tt.arrange(t, paths, ir)

			result := service.RestoreBackup(adminproto.RestoreBackupRequest{
				OperationID:      "restore-recovery-order",
				ArchivePath:      archivePath,
				ExportPassphrase: []byte("export-passphrase"),
			})
			fsutil.TestHook = nil

			if result.Success || result.Code != protocol.ResultCodeRestoreRollbackFailed || result.GenerationID == "" {
				t.Fatalf("RestoreBackup() = %+v, want a committed restore that failed afterwards", result)
			}
			if !deps.recoveryAtRelease {
				t.Fatal("runtime entered recovery only after the store mutation lock was released")
			}
			if !ir.IsRecovery() {
				t.Fatal("runtime is not in recovery after the restore")
			}
		})
	}
}
