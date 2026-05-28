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

func TestAppCallRawResolvesSender(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	eng.AliasCache.Aliases = map[string]string{
		"alice": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
	}
	app := New(eng, config.DefaultConfig(), t.TempDir())

	_, err = app.AppCallRaw(context.Background(), AppCallRawRequest{
		AppID: 123,
		From:  "alice",
		Wait:  true,
	})
	if err == nil || err.Error() != "algod client not configured" {
		t.Fatalf("AppCallRaw() error = %v", err)
	}
}

func TestDecorateAppCallRawResult(t *testing.T) {
	result := &AppCallRawResult{
		FromAddress:    "ADDR",
		SigningKeyType: "ed25519",
		AppArgsCount:   2,
		AccountsCount:  1,
		AppsCount:      2,
		AssetsCount:    3,
		BoxesCount:     4,
		Note:           "memo",
		PayAmount:      1000,
		Structured: appresult.AppCall{
			AppID:     77,
			Grouped:   true,
			Confirmed: true,
		},
	}

	decorateAppCallRawResult(result)

	if len(result.PreSubmitLines) == 0 {
		t.Fatal("PreSubmitLines should not be empty")
	}
	if got := result.PreSubmitLines[0]; got != "Calling app 77 raw from {from} with companion payment of 1000 microAlgos using ed25519..." {
		t.Fatalf("first pre-submit line = %q", got)
	}
	if got := result.ConfirmedLines[0]; got != "Confirmed grouped raw app call on app 77" {
		t.Fatalf("confirmed line = %q", got)
	}
}
