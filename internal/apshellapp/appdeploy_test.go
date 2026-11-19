// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/appresult"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
)

func TestAppDeployResolvesSender(t *testing.T) {
	eng := engine.NewEngine("testnet")
	eng.AliasCache.Aliases = map[string]string{
		"alice": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
	}
	app := New(eng, config.DefaultConfig(), t.TempDir())

	_, err := app.AppDeploy(context.Background(), AppDeployRequest{
		From:         "alice",
		ApprovalPath: "approval.teal",
		ClearPath:    "clear.teal",
		Wait:         true,
	})
	if err == nil || err.Error() != "algod client not configured" {
		t.Fatalf("AppDeploy() error = %v", err)
	}
}

func TestAppDeployResultCarriesRenderLines(t *testing.T) {
	result := &AppDeployResult{
		FromAddress:    "ADDR",
		SigningKeyType: "ed25519",
		PreSubmitLines: []string{"Deploying app from {from} using ed25519..."},
		ConfirmedLines: []string{"Created app 88 at APPADDR"},
		Structured: appresult.AppDeploy{
			AppID:      88,
			AppAddress: "APPADDR",
			Confirmed:  true,
		},
	}

	if got := result.PreSubmitLines[0]; got != "Deploying app from {from} using ed25519..." {
		t.Fatalf("pre-submit line = %q", got)
	}
	if got := result.ConfirmedLines[0]; got != "Created app 88 at APPADDR" {
		t.Fatalf("confirmed line = %q", got)
	}
}

// A deploy that confirmed is not failed when the app it created cannot be
// looked up: the result keeps its transaction ID, says why the app's ID is
// missing, and warns, so nothing invites a second deploy.
func TestAppDeployConfirmedWithoutTheCreatedApp(t *testing.T) {
	f := newArgsFixture(t)
	f.signsFor = map[string]bool{argsNative: true}
	f.confirms = true // and reports no app created
	dir := t.TempDir()
	program := filepath.Join(dir, "program.bin")
	if err := os.WriteFile(program, []byte{0x06, 0x81, 0x01}, 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := f.app.AppDeploy(context.Background(), AppDeployRequest{
		From: "nat", ApprovalPath: program, ApprovalCompiled: true, ClearPath: program, ClearCompiled: true, Wait: true,
	})
	if err != nil {
		t.Fatalf("AppDeploy() error = %v, want the confirmed deploy's result", err)
	}
	if f.submitted.Load() != 1 {
		t.Fatalf("node accepted %d transaction(s), want the deploy", f.submitted.Load())
	}
	deployed := result.Structured
	if deployed.TxID == "" || !deployed.Confirmed || deployed.AppID != 0 ||
		!strings.Contains(deployed.AppLookupError, "transaction did not create an application") {
		t.Fatalf("structured result = %+v, want the confirmed deploy and why its app is missing", deployed)
	}
	if len(result.Warnings) != 1 || result.Warnings[0].Code != "created_app_lookup_failed" ||
		!strings.Contains(result.Warnings[0].Message, deployed.TxID) {
		t.Fatalf("warnings = %+v, want the lookup failure naming %s", result.Warnings, deployed.TxID)
	}
	if !strings.Contains(result.Output, deployed.TxID) {
		t.Fatalf("output %q does not name the deploy", result.Output)
	}
}
