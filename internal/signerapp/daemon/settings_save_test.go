// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/protocol"
	signeraudit "github.com/aplane-algo/aplane/internal/signerapp/audit"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
)

// heldSave is an update running in the background with its durable write
// held at one step.
type heldSave struct {
	reached    chan struct{}
	released   chan struct{}
	releaseErr error
	result     chan error
	once       sync.Once
	err        error
}

// holdSave runs update with the durable write held at op on path until
// finish. Every exit path, a failed assertion included, releases the hold and
// waits for update before it clears the hook: a test that stopped while the
// hook was blocked once left the update parked inside the durable write,
// holding the store mutation lock, and cleared the hook while that goroutine
// could still read it.
func holdSave(t *testing.T, op fsutil.HookOp, path string, update func() error) *heldSave {
	t.Helper()
	h := &heldSave{reached: make(chan struct{}), released: make(chan struct{}), result: make(chan error, 1)}
	var reachOnce sync.Once
	fsutil.TestHook = func(got fsutil.HookOp, gotPath string) error {
		if got == op && gotPath == path {
			reachOnce.Do(func() { close(h.reached) })
			<-h.released
			return h.releaseErr
		}
		return nil
	}
	go func() { h.result <- update() }()
	t.Cleanup(func() {
		_ = h.finish(nil)
		fsutil.TestHook = nil
	})
	select {
	case <-h.reached:
	case <-time.After(10 * time.Second):
		t.Fatal("the save never reached the held step")
	}
	return h
}

// finish lets the held step return err (nil lets it go on) and returns the
// update's result. Later calls return the same result.
func (h *heldSave) finish(err error) error {
	h.once.Do(func() {
		h.releaseErr = err
		close(h.released)
		h.err = <-h.result
	})
	return h.err
}

// A signing request reads user_auto_approve once, when its approval service
// is built, and takes no lock the settings update holds. Turning auto-approve
// on is permissive: the update once published it before saving it, so a
// request built during the save kept a value that was then reset, or never
// saved at all. Turning it off is restrictive: it is in effect from before
// the save, however long the save takes, and stays in effect if the save
// fails before its rename (a restart then loads the old value). The save
// here is held at the step where it fails.
func TestSigningSeesAutoApproveByTheChangesDirection(t *testing.T) {
	for _, change := range []struct {
		name     string
		from, to bool
		// restrictive: the new value is in effect before the save returns.
		restrictive bool
	}{
		{"enable", false, true, false},
		{"disable", true, false, true},
	} {
		for _, failure := range []struct {
			name string
			op   fsutil.HookOp
			// replaced: the new file is in place when the save fails.
			replaced bool
		}{
			{"failure before the rename", fsutil.OpRename, false},
			{"failure after the rename", fsutil.OpDirSync, true},
		} {
			t.Run(change.name+"/"+failure.name, func(t *testing.T) {
				server, cleanup := setupTestSigner(t)
				t.Cleanup(cleanup)
				if err := os.WriteFile(filepath.Join(server.dataDir, "config.yaml"), []byte("theme: auto\n"), 0o640); err != nil {
					t.Fatal(err)
				}
				ir := server.productRuntime()
				app := server.adminServices().adminApp()
				signingSees := func() bool {
					return *server.newApprovalServiceWithAudit(ir, nil, nil).UserAutoApprove
				}
				update := func(v bool) error {
					return app.UpdateAdminSetting(adminproto.UpdateAdminSettingRequest{
						Key: adminproto.AdminSettingUserAutoApprove, Value: strconv.FormatBool(v),
					})
				}
				if err := update(change.from); err != nil {
					t.Fatalf("setting the starting value: %v", err)
				}

				configPath := productruntime.ConfigPath(server.dataDir)
				hookPath := configPath
				if failure.op == fsutil.OpDirSync {
					hookPath = filepath.Dir(configPath)
				}
				held := holdSave(t, failure.op, hookPath, func() error { return update(change.to) })
				during := change.from
				if change.restrictive {
					during = change.to
				}
				if got := signingSees(); got != during {
					t.Fatalf("a request built during the save got auto-approve %v, want %v", got, during)
				}
				err := held.finish(errors.New("injected " + string(failure.op) + " failure"))

				live, saved := change.from, change.from
				if failure.replaced || change.restrictive {
					live = change.to
				}
				if failure.replaced {
					saved = change.to
				}
				if err == nil || errors.Is(err, fsutil.ErrPublishedNotDurable) != failure.replaced {
					t.Fatalf("UpdateAdminSetting error = %v, want a failure that reports whether the file was replaced (%v)", err, failure.replaced)
				}
				if got := signingSees(); got != live {
					t.Fatalf("a request built after the save got auto-approve %v, want %v", got, live)
				}
				stored, loadErr := productruntime.LoadStoredConfig(server.dataDir)
				if loadErr != nil {
					t.Fatal(loadErr)
				}
				if stored.UserAutoApprove == nil || *stored.UserAutoApprove != saved {
					t.Fatalf("saved auto-approve = %v, want %v", stored.UserAutoApprove, saved)
				}
			})
		}
	}
}

// What an admin client receives when a setting is in effect but its save did
// not complete, and what the audit log records of it: a failed result coded
// applied_not_durable (file replaced, directory sync failed) or
// applied_not_saved (a restrictive change whose save failed before the
// rename), an error that says the setting is in effect, settings that then
// report the new value, which the TUI re-reads after any result, and one
// SETTING_NOT_DURABLE entry, since nothing else durable records the change.
// A save that fails before the rename of a permissive change writes none: the
// setting is unchanged.
func TestSettingInEffectWithoutACompletedSaveReachesTheAdminClientAndTheAuditLog(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		op          fsutil.HookOp
		code        string
		errText     []string
	}{
		{"unsynced", "true", fsutil.OpDirSync, protocol.ResultCodeAppliedNotDurable, []string{"in effect", "durability is not confirmed"}},
		{"unsaved restrictive", "false", fsutil.OpRename, protocol.ResultCodeAppliedNotSaved, []string{"in effect now", "not saved", "a restart loads the old value"}},
		{"unsaved permissive", "true", fsutil.OpRename, "", []string{"unchanged"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, cleanup := setupTestSigner(t)
			t.Cleanup(cleanup)
			if err := os.WriteFile(filepath.Join(server.dataDir, "config.yaml"), []byte("theme: auto\n"), 0o640); err != nil {
				t.Fatal(err)
			}
			ir := server.productRuntime()
			// Start from the opposite value, saved, so the change is real.
			start := strconv.FormatBool(tc.value != "true")
			if err := server.adminServices().adminApp().UpdateAdminSetting(adminproto.UpdateAdminSettingRequest{
				Key: adminproto.AdminSettingUserAutoApprove, Value: start,
			}); err != nil {
				t.Fatal(err)
			}
			configPath := productruntime.ConfigPath(server.dataDir)
			hookPath := configPath
			if tc.op == fsutil.OpDirSync {
				hookPath = filepath.Dir(configPath)
			}
			fsutil.TestHook = func(op fsutil.HookOp, path string) error {
				if op == tc.op && path == hookPath {
					return errors.New("injected " + string(op) + " failure")
				}
				return nil
			}
			t.Cleanup(func() { fsutil.TestHook = nil })

			recorder := &ipcJSONRecorderConn{}
			session := newBoundTestSession(&IPCServer{signer: server}, recorder, ir)
			session.HandleUpdateAdminSetting(&protocol.UpdateAdminSettingMessage{
				BaseMessage: protocol.BaseMessage{ID: "req-1"},
				Key:         adminproto.AdminSettingUserAutoApprove,
				Value:       tc.value,
			})
			fsutil.TestHook = nil
			session.HandleGetAdminSettings("req-2")

			msgs := recorder.messages(t)
			if len(msgs) != 2 {
				t.Fatalf("message count = %d, want 2", len(msgs))
			}
			want := map[string]any{
				"type": protocol.MsgTypeUpdateAdminSettingResult, "id": "req-1", "success": false,
				"key": adminproto.AdminSettingUserAutoApprove, "value": tc.value,
			}
			if tc.code != "" {
				want["code"] = tc.code
			}
			if !reflectJSONSubset(msgs[0], want) {
				t.Fatalf("update_admin_setting_result = %#v", msgs[0])
			}
			errText, _ := msgs[0]["error"].(string)
			for _, part := range tc.errText {
				if !strings.Contains(errText, part) {
					t.Fatalf("update_admin_setting_result error = %q, want it to say %q", errText, part)
				}
			}
			live := tc.value
			if tc.code == "" {
				live = start
			}
			if !reflectJSONSubset(msgs[1], map[string]any{"type": protocol.MsgTypeAdminSettings, "id": "req-2", "user_auto_approve": live == "true"}) {
				t.Fatalf("admin_settings after the save = %#v, want user_auto_approve %s", msgs[1], live)
			}

			auditPath := filepath.Join(server.dataDir, "audit.log")
			if tc.code == "" {
				if data, err := os.ReadFile(auditPath); err != nil || strings.Contains(string(data), string(signeraudit.AuditSettingNotDurable)) {
					t.Fatalf("audit log for an unchanged setting = %q (%v), want no %s entry", data, err, signeraudit.AuditSettingNotDurable)
				}
				return
			}
			entries := auditEntries(t, auditPath, string(signeraudit.AuditSettingNotDurable))
			if len(entries) != 1 {
				t.Fatalf("SETTING_NOT_DURABLE entries = %#v, want one", entries)
			}
			reason, _ := entries[0]["reason"].(string)
			sessionID, _ := entries[0]["admin_session_id"].(string)
			if entries[0]["result_code"] != tc.code || entries[0]["outcome"] != "applied" || entries[0]["transport"] != "ipc" ||
				sessionID == "" || reason != "setting="+adminproto.AdminSettingUserAutoApprove+": "+errText {
				t.Fatalf("SETTING_NOT_DURABLE entry = %#v", entries[0])
			}
		})
	}
}
