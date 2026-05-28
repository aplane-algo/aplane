// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/asa"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
)

func TestPrepareSendRejectsManyToMany(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	eng.SetCache.Sets = map[string][]string{
		"senders": {"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ", "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"},
		"rcvrs":   {"CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ", "DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"},
	}

	app := New(eng, config.DefaultConfig(), t.TempDir())
	_, err = app.PrepareSend(context.Background(), SendRequest{
		AmountText: "1",
		AssetRef:   "algo",
		FromRaw:    []string{"@senders"},
		ToRaw:      []string{"@rcvrs"},
	})
	if err == nil {
		t.Fatal("PrepareSend() error = nil, want many-to-many rejection")
	}
}

func TestPrepareSendSelectsAtomicToMultipleMode(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	eng.AliasCache.Aliases = map[string]string{}
	eng.AliasCache.Aliases["alice"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
	eng.SetCache.Sets = map[string][]string{
		"friends": {
			"BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
			"CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
		},
	}

	app := New(eng, config.DefaultConfig(), t.TempDir())
	plan, err := app.PrepareSend(context.Background(), SendRequest{
		AmountText: "1.5",
		AssetRef:   "algo",
		FromRaw:    []string{"alice"},
		ToRaw:      []string{"@friends"},
		Atomic:     true,
	})
	if err != nil {
		t.Fatalf("PrepareSend() error = %v", err)
	}
	if plan.Mode != SendModeAtomicToMultiple {
		t.Fatalf("Mode = %q, want %q", plan.Mode, SendModeAtomicToMultiple)
	}
	if len(plan.FromAddresses) != 1 || len(plan.ToAddresses) != 2 {
		t.Fatalf("plan addresses = %#v", plan)
	}
	if plan.Amount.Raw != 1500000 {
		t.Fatalf("Amount.Raw = %d, want 1500000", plan.Amount.Raw)
	}
}

func TestExecuteSendUsesNonAtomicPath(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	eng.AliasCache.Aliases = map[string]string{
		"alice": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
		"bob":   "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
	}

	app := New(eng, config.DefaultConfig(), t.TempDir())
	_, err = app.ExecuteSend(context.Background(), SendRequest{
		AmountText: "1",
		AssetRef:   "algo",
		FromRaw:    []string{"alice"},
		ToRaw:      []string{"bob"},
	})
	if !errors.Is(err, engine.ErrNoAlgodClient) {
		t.Fatalf("ExecuteSend() error = %v, want %v", err, engine.ErrNoAlgodClient)
	}
}

func TestExecuteSendUsesAtomicPath(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	eng.AliasCache.Aliases = map[string]string{
		"alice": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
	}
	eng.SetCache.Sets = map[string][]string{
		"friends": {
			"BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
			"CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
		},
	}

	app := New(eng, config.DefaultConfig(), t.TempDir())
	_, err = app.ExecuteSend(context.Background(), SendRequest{
		AmountText: "1",
		AssetRef:   "algo",
		FromRaw:    []string{"alice"},
		ToRaw:      []string{"@friends"},
		Atomic:     true,
	})
	if !errors.Is(err, engine.ErrNoAlgodClient) {
		t.Fatalf("ExecuteSend() error = %v, want %v", err, engine.ErrNoAlgodClient)
	}
}

func TestAtomicValidationNotesRejectsTotalOverflow(t *testing.T) {
	const maxUint64 = ^uint64(0)

	plan := &AtomicSendPlan{
		Mode:   SendModeAtomicToMultiple,
		Amount: asa.Amount{Raw: maxUint64/2 + 1},
		To:     []string{"bob", "carol"},
		Checks: []BalanceCheckDetails{{SufficientFunds: false}},
	}

	_, err := atomicValidationNotes(plan)
	if err == nil {
		t.Fatal("atomicValidationNotes() error = nil, want overflow rejection")
	}
	if !strings.Contains(err.Error(), "overflows uint64") {
		t.Fatalf("atomicValidationNotes() error = %v, want overflow rejection", err)
	}
}

func TestCheckedSendTotal(t *testing.T) {
	const maxUint64 = ^uint64(0)

	tests := []struct {
		name   string
		amount uint64
		count  int
		want   uint64
		ok     bool
	}{
		{name: "zero count", amount: 10, count: 0, want: 0, ok: true},
		{name: "normal", amount: 10, count: 3, want: 30, ok: true},
		{name: "overflow", amount: maxUint64/2 + 1, count: 2, ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := checkedSendTotal(tt.amount, tt.count)
			if ok != tt.ok {
				t.Fatalf("checkedSendTotal() ok = %v, want %v", ok, tt.ok)
			}
			if ok && got != tt.want {
				t.Fatalf("checkedSendTotal() = %d, want %d", got, tt.want)
			}
		})
	}
}
