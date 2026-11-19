// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	signerstartup "github.com/aplane-algo/aplane/internal/signerapp/startup"
	"github.com/aplane-algo/aplane/internal/signerapp/unlockconfig"
	utilkeys "github.com/aplane-algo/aplane/internal/storepaths"
)

// startupRuntime builds the product runtime as apsigner's startup does, on a
// default config.yaml (user_auto_approve false, lock_on_disconnect true,
// passphrase_timeout 15m) with stored saved to identities/default/config.yaml.
func startupRuntime(t *testing.T, unlockMethod string, stored map[string]any) *productruntime.Runtime {
	t.Helper()
	root := t.TempDir()
	writeTestNodeRole(t, root, noderole.RoleSigner)
	for key, value := range stored {
		if err := productruntime.SaveStoredSetting(root, key, value); err != nil {
			t.Fatal(err)
		}
	}
	cfg := serverconfig.DefaultServerConfig()
	ir, err := signerstartup.BuildProductRuntime(signerstartup.ProductBuildOptions{
		DataDir:               root,
		KeyPaths:              utilkeys.NewPaths(root),
		Config:                &cfg,
		DefaultSessionTimeout: 15 * time.Minute,
		UnlockMethod:          unlockMethod,
	}, signerstartup.ProductBuildHooks{})
	if err != nil {
		t.Fatal(err)
	}
	return ir
}

func containsWarning(warnings []string, text string) bool {
	return slices.ContainsFunc(warnings, func(w string) bool { return strings.Contains(w, text) })
}

// The startup warnings read the settings in effect, which overlay
// identities/default/config.yaml, where apadmin saves a change, on
// config.yaml. They once read config.yaml alone, so user auto-approve turned
// on in apadmin got no warning at startup.
func TestStartupWarningsReadTheSettingsInEffect(t *testing.T) {
	t.Run("interactive, set in apadmin", func(t *testing.T) {
		ir := startupRuntime(t, unlockconfig.MethodNone, map[string]any{
			"user_auto_approve":  true,
			"lock_on_disconnect": false,
			"passphrase_timeout": "0",
		})
		warnings, headless := modeWarnings(ir)
		if headless {
			t.Fatal("a prompt-mode runtime reported headless")
		}
		for _, want := range []string{"user_auto_approve:true", "lock_on_disconnect:false", "passphrase_timeout:0"} {
			if !containsWarning(warnings, want) {
				t.Errorf("warnings = %q, want one for %s", warnings, want)
			}
		}

		logs := &syncBuffer{}
		appLogger.SetOutput(logs)
		t.Cleanup(func() { appLogger.SetOutput(os.Stderr) })
		printModeWarnings(ir)
		if out := logs.String(); !strings.Contains(out, "interactive mode warnings:") || !strings.Contains(out, "user_auto_approve:true") {
			t.Fatalf("startup log = %q, want the interactive warnings", out)
		}
	})

	t.Run("interactive, defaults", func(t *testing.T) {
		if warnings, _ := modeWarnings(startupRuntime(t, unlockconfig.MethodNone, nil)); len(warnings) != 0 {
			t.Fatalf("warnings = %q, want none for the default settings", warnings)
		}
	})

	t.Run("headless, auto-approve set in apadmin", func(t *testing.T) {
		warnings, headless := modeWarnings(startupRuntime(t, unlockconfig.MethodPassfile, map[string]any{"user_auto_approve": true}))
		if !headless {
			t.Fatal("a passphrase-helper runtime did not report headless")
		}
		if !containsWarning(warnings, "turns off lock_on_disconnect and passphrase_timeout") {
			t.Fatalf("warnings = %q, want the headless overrides named", warnings)
		}
		if containsWarning(warnings, "manual approval") {
			t.Fatalf("warnings = %q, want no manual-approval warning with auto-approve on", warnings)
		}
	})

	t.Run("headless, defaults", func(t *testing.T) {
		if warnings, _ := modeWarnings(startupRuntime(t, unlockconfig.MethodPassfile, nil)); !containsWarning(warnings, "manual approval") {
			t.Fatalf("warnings = %q, want the manual-approval warning", warnings)
		}
	})
}
