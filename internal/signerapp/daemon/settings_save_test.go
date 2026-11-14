// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/fsutil/fsutiltest"
	"github.com/aplane-algo/aplane/internal/protocol"
	signeraudit "github.com/aplane-algo/aplane/internal/signerapp/audit"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
)

// A signing request reads user_auto_approve once, when its approval service
// is built, and takes no lock the settings update holds. Turning auto-approve
// on is permissive: the update once published it before saving it, so a
// request built during the save kept a value that was then reset, or never
// saved at all. Turning it off is restrictive: it is in effect from before
// the save, however long the save takes, and stays in effect if the save
// fails before its rename (a restart then loads the old value). A failed
// directory flush after the rename is a success: the new file is in place.
// The save here is held at the step where it fails.
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
				held := fsutiltest.Hold(t, failure.op, hookPath, func() error { return update(change.to) })
				during := change.from
				if change.restrictive {
					during = change.to
				}
				if got := signingSees(); got != during {
					t.Fatalf("a request built during the save got auto-approve %v, want %v", got, during)
				}
				err := held.Finish(errors.New("injected " + string(failure.op) + " failure"))

				live, saved := change.from, change.from
				if failure.replaced || change.restrictive {
					live = change.to
				}
				if failure.replaced {
					saved = change.to
				}
				if (err == nil) != failure.replaced {
					t.Fatalf("UpdateAdminSetting error = %v, want success exactly when the file was replaced (%v)", err, failure.replaced)
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

// What an admin client receives for each save outcome, and what the audit
// log and the signer's log record of it. A failed directory flush after the
// rename is a success with one warning in the signer's log, and no audit
// entry: the new file is in place. A save that fails before the rename writes
// one SETTING_SAVE_ERROR entry with the setting, the value, the cause and
// whether the value is in effect: a restrictive change is (applied_not_saved,
// reported unsaved), a permissive one is not (a plain failure). A request
// refused before any save writes none. The settings re-read shows what is in
// effect.
func TestSettingSaveOutcomesReachTheAdminClientAndTheLogs(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		op          fsutil.HookOp
		success     bool
		code        string
		errText     string
		// inEffect is the audit entry's, for a failed save.
		audited, inEffect bool
		live              string
	}{
		{name: "unsynced", value: "true", op: fsutil.OpDirSync, success: true, live: "true"},
		{name: "unsaved restrictive", value: "false", op: fsutil.OpRename, code: protocol.ResultCodeAppliedNotSaved,
			errText: "in effect now, but it was not saved, so a restart loads the old value", audited: true, inEffect: true, live: "false"},
		{name: "unsaved permissive", value: "true", op: fsutil.OpRename, errText: "unchanged", audited: true, live: "false"},
		{name: "refused before the save", value: "maybe", op: fsutil.OpRename, code: protocol.ErrCodeInvalidRequest, errText: "must be true or false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, cleanup := setupTestSigner(t)
			t.Cleanup(cleanup)
			if err := os.WriteFile(filepath.Join(server.dataDir, "config.yaml"), []byte("theme: auto\n"), 0o640); err != nil {
				t.Fatal(err)
			}
			logs := &syncBuffer{}
			appLogger.SetOutput(logs)
			t.Cleanup(func() { appLogger.SetOutput(os.Stderr) })
			ir := server.productRuntime()
			// Start from the opposite of a true value, saved, so a change is
			// real either way.
			start := "true"
			if tc.value == "true" {
				start = "false"
			}
			if err := server.adminServices().adminApp().UpdateAdminSetting(adminproto.UpdateAdminSettingRequest{
				Key: adminproto.AdminSettingUserAutoApprove, Value: start,
			}); err != nil {
				t.Fatal(err)
			}
			if tc.live == "" {
				tc.live = start
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
				"type": protocol.MsgTypeUpdateAdminSettingResult, "id": "req-1", "success": tc.success,
				"key": adminproto.AdminSettingUserAutoApprove, "value": tc.value,
			}
			if tc.code != "" {
				want["code"] = tc.code
			}
			if !reflectJSONSubset(msgs[0], want) {
				t.Fatalf("update_admin_setting_result = %#v", msgs[0])
			}
			if errText, _ := msgs[0]["error"].(string); !strings.Contains(errText, tc.errText) {
				t.Fatalf("update_admin_setting_result error = %q, want it to say %q", errText, tc.errText)
			}
			if !reflectJSONSubset(msgs[1], map[string]any{"type": protocol.MsgTypeAdminSettings, "id": "req-2", "user_auto_approve": tc.live == "true"}) {
				t.Fatalf("admin_settings after the update = %#v, want user_auto_approve %s", msgs[1], tc.live)
			}
			unsaved, reported := msgs[1]["unsaved_settings"]
			if wantUnsaved := tc.code == protocol.ResultCodeAppliedNotSaved; reported != wantUnsaved ||
				(wantUnsaved && !reflect.DeepEqual(unsaved, []any{adminproto.AdminSettingUserAutoApprove})) {
				t.Fatalf("admin_settings unsaved_settings = %v (reported %v), want it only for %s", unsaved, reported, protocol.ResultCodeAppliedNotSaved)
			}
			if flushed := strings.Contains(logs.String(), "setting user_auto_approve saved, but its directory flush failed"); flushed != (tc.op == fsutil.OpDirSync) {
				t.Fatalf("signer log = %q, want the flush warning only for the unsynced save", logs.String())
			}

			auditPath := filepath.Join(server.dataDir, "audit.log")
			data, err := os.ReadFile(auditPath)
			if err != nil {
				t.Fatal(err)
			}
			if !tc.audited {
				if strings.Contains(string(data), string(signeraudit.AuditSettingSaveError)) {
					t.Fatalf("audit log = %q, want no %s entry", data, signeraudit.AuditSettingSaveError)
				}
				return
			}
			entries := auditEntries(t, auditPath, string(signeraudit.AuditSettingSaveError))
			if len(entries) != 1 {
				t.Fatalf("SETTING_SAVE_ERROR entries = %#v, want one", entries)
			}
			outcome := map[bool]string{true: "applied", false: "failed"}[tc.inEffect]
			reason, _ := entries[0]["reason"].(string)
			sessionID, _ := entries[0]["admin_session_id"].(string)
			wantReason := fmt.Sprintf("setting=%s value=%s in_effect=%t: ", adminproto.AdminSettingUserAutoApprove, tc.value, tc.inEffect)
			if entries[0]["outcome"] != outcome || entries[0]["transport"] != "ipc" || sessionID == "" ||
				!strings.HasPrefix(reason, wantReason) || !strings.Contains(reason, "injected rename failure") {
				t.Fatalf("SETTING_SAVE_ERROR entry = %#v, want outcome %s and reason %q plus the cause", entries[0], outcome, wantReason)
			}
		})
	}
}
