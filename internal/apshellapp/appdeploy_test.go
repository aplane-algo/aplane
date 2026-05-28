// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"testing"

	"github.com/aplane-algo/aplane/internal/appresult"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
)

func TestAppDeployResolvesSender(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	eng.AliasCache.Aliases = map[string]string{
		"alice": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
	}
	app := New(eng, config.DefaultConfig(), t.TempDir())

	_, err = app.AppDeploy(context.Background(), AppDeployRequest{
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
