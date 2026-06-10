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

func TestAppCallMethodResolvesSender(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	eng.AliasCache.Aliases = map[string]string{
		"alice": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
	}
	app := New(eng, config.DefaultConfig(), t.TempDir())

	_, err = app.AppCallMethod(context.Background(), AppCallMethodRequest{
		AppID:   123,
		Method:  "foo()void",
		ABIPath: "abi.json",
		From:    "alice",
		Wait:    true,
	})
	if err == nil || err.Error() != "failed to read ABI file: open abi.json: no such file or directory" {
		t.Fatalf("AppCallMethod() error = %v", err)
	}
}

func TestDecorateAppCallMethodResult(t *testing.T) {
	result := &AppCallMethodResult{
		Method:         "foo(uint64)void",
		SigningKeyType: "ed25519",
		ArgsCount:      1,
		AccountsCount:  1,
		AppsCount:      2,
		AssetsCount:    3,
		BoxesCount:     4,
		Note:           "memo",
		Structured: appresult.AppCall{
			AppID:   55,
			Grouped: false,
		},
	}

	// Mirror production order: decorate runs pre-submit (Confirmed unset),
	// confirmed lines are appended only after submission sets Confirmed.
	decorateAppCallMethodResult(result)

	if len(result.PreSubmitLines) == 0 {
		t.Fatal("PreSubmitLines should not be empty")
	}
	if got := result.PreSubmitLines[0]; got != "Calling app 55 method foo(uint64)void from {from} using ed25519..." {
		t.Fatalf("first pre-submit line = %q", got)
	}
	if len(result.ConfirmedLines) != 0 {
		t.Fatalf("decorate must not emit confirmed lines pre-submit, got %v", result.ConfirmedLines)
	}

	result.Structured.Confirmed = true
	appendAppCallMethodConfirmedLines(result)

	if len(result.ConfirmedLines) != 1 {
		t.Fatalf("ConfirmedLines = %v, want exactly one entry", result.ConfirmedLines)
	}
	if got := result.ConfirmedLines[0]; got != "Confirmed app call foo(uint64)void on app 55" {
		t.Fatalf("confirmed line = %q", got)
	}
}

func TestAppendAppCallMethodConfirmedLinesSkipsUnconfirmed(t *testing.T) {
	result := &AppCallMethodResult{
		Method:     "foo(uint64)void",
		Structured: appresult.AppCall{AppID: 55},
	}

	appendAppCallMethodConfirmedLines(result)

	if len(result.ConfirmedLines) != 0 {
		t.Fatalf("unconfirmed call must not produce confirmed lines, got %v", result.ConfirmedLines)
	}
}
