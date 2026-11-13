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
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
)

// A signing request reads user_auto_approve once, when its approval service
// is built, and takes no lock the settings update holds. The update once
// published the new value before saving it, so a request built during the
// save kept a value that was then reset, or never saved at all. The save
// here is held at the step where it fails; a request built meanwhile must
// get the saved value, and one built afterward the value the file holds.
func TestSigningNeverSeesAnUnsavedAutoApprove(t *testing.T) {
	for _, change := range []struct {
		name     string
		from, to bool
	}{
		{"enable", false, true},
		{"disable", true, false},
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
				defer cleanup()
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
				reached := make(chan struct{})
				release := make(chan struct{})
				var once sync.Once
				fsutil.TestHook = func(op fsutil.HookOp, path string) error {
					if op == failure.op && path == hookPath {
						once.Do(func() { close(reached) })
						<-release
						return errors.New("injected " + string(op) + " failure")
					}
					return nil
				}
				defer func() { fsutil.TestHook = nil }()

				result := make(chan error, 1)
				go func() { result <- update(change.to) }()
				select {
				case <-reached:
				case <-time.After(10 * time.Second):
					close(release)
					t.Fatal("the save never reached the injected failure")
				}
				if got := signingSees(); got != change.from {
					t.Fatalf("a request built during the save got auto-approve %v; the saved value is %v", got, change.from)
				}
				close(release)
				err := <-result
				fsutil.TestHook = nil

				want := change.from
				if failure.replaced {
					want = change.to
				}
				if err == nil || errors.Is(err, fsutil.ErrPublishedNotDurable) != failure.replaced {
					t.Fatalf("UpdateAdminSetting error = %v, want a failure that reports whether the file was replaced (%v)", err, failure.replaced)
				}
				if got := signingSees(); got != want {
					t.Fatalf("a request built after the save got auto-approve %v, want %v", got, want)
				}
				stored, loadErr := productruntime.LoadStoredConfig(server.dataDir)
				if loadErr != nil {
					t.Fatal(loadErr)
				}
				if stored.UserAutoApprove == nil || *stored.UserAutoApprove != want {
					t.Fatalf("saved auto-approve = %v, want %v, the value signing uses", stored.UserAutoApprove, want)
				}
			})
		}
	}
}

// What an admin client receives when the save is in place but its directory
// sync failed: a failed result coded applied_not_durable whose error says the
// setting is in effect, and settings that then report the new value, which
// the TUI re-reads after any result.
func TestUnsyncedSettingSaveReachesTheAdminClientAsInEffect(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	if err := os.WriteFile(filepath.Join(server.dataDir, "config.yaml"), []byte("theme: auto\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	identityDir := filepath.Dir(productruntime.ConfigPath(server.dataDir))
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if op == fsutil.OpDirSync && path == identityDir {
			return errors.New("injected dir-sync failure")
		}
		return nil
	}
	defer func() { fsutil.TestHook = nil }()

	recorder := &ipcJSONRecorderConn{}
	ir := server.productRuntime()
	session := newBoundTestSession(&IPCServer{signer: server}, recorder, ir)
	session.HandleUpdateAdminSetting(&protocol.UpdateAdminSettingMessage{
		BaseMessage: protocol.BaseMessage{ID: "req-1"},
		Key:         adminproto.AdminSettingUserAutoApprove,
		Value:       "true",
	})
	fsutil.TestHook = nil
	session.HandleGetAdminSettings("req-2")

	msgs := recorder.messages(t)
	if len(msgs) != 2 {
		t.Fatalf("message count = %d, want 2", len(msgs))
	}
	if !reflectJSONSubset(msgs[0], map[string]any{
		"type": protocol.MsgTypeUpdateAdminSettingResult, "id": "req-1", "success": false,
		"key": adminproto.AdminSettingUserAutoApprove, "value": "true",
		"code": protocol.ResultCodeAppliedNotDurable,
	}) {
		t.Fatalf("update_admin_setting_result = %#v", msgs[0])
	}
	if errText, _ := msgs[0]["error"].(string); !strings.Contains(errText, "in effect") || !strings.Contains(errText, "durability is not confirmed") {
		t.Fatalf("update_admin_setting_result error = %q, want in effect with durability unconfirmed", errText)
	}
	if !reflectJSONSubset(msgs[1], map[string]any{"type": protocol.MsgTypeAdminSettings, "id": "req-2", "user_auto_approve": true}) {
		t.Fatalf("admin_settings after the unsynced save = %#v, want user_auto_approve true", msgs[1])
	}
}
