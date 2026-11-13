// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
)

var (
	repeatAlice = types.Address{61}.String()
	repeatBob   = types.Address{62}.String()
	repeatCarol = types.Address{63}.String()
	repeatDan   = types.Address{64}.String()
)

// newRepeatTestApp has no algod client, so a send that gets past the repeat
// check fails preparing its first transaction with engine.ErrNoAlgodClient.
func newRepeatTestApp(t *testing.T) *App {
	t.Helper()
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	eng.AliasCache.Aliases = map[string]string{
		"alice": repeatAlice,
		"bob":   repeatBob,
	}
	eng.SetCache.Sets = map[string][]string{
		"team":    {repeatCarol, repeatBob},
		"doubled": {repeatCarol, repeatCarol},
	}
	return New(eng, config.DefaultConfig(), t.TempDir())
}

func TestSendRefusesAnAccountListedTwice(t *testing.T) {
	tests := []struct {
		name    string
		from    []string
		to      []string
		wantErr string
	}{
		{
			name:    "recipient address twice",
			from:    []string{"alice"},
			to:      []string{repeatCarol, repeatCarol},
			wantErr: "recipient " + repeatCarol + " is listed more than once",
		},
		{
			name:    "recipient alias and its address",
			from:    []string{"alice"},
			to:      []string{"bob", strings.ToLower(repeatBob)},
			wantErr: "recipient bob (" + repeatBob + ") is listed more than once",
		},
		{
			name:    "recipient in a set and listed again",
			from:    []string{"alice"},
			to:      []string{"@team", "bob"},
			wantErr: "recipient bob (" + repeatBob + ") is listed more than once",
		},
		{
			name:    "recipient twice inside one stored set",
			from:    []string{"alice"},
			to:      []string{"@doubled"},
			wantErr: "recipient " + repeatCarol + " is listed more than once",
		},
		{
			name:    "sender alias twice",
			from:    []string{"alice", "alice"},
			to:      []string{"bob"},
			wantErr: "sender alice (" + repeatAlice + ") is listed more than once",
		},
		{
			name:    "sender in a set and listed again",
			from:    []string{"@team", repeatCarol},
			to:      []string{"alice"},
			wantErr: "sender " + repeatCarol + " is listed more than once",
		},
	}
	for _, tt := range tests {
		for _, atomic := range []bool{false, true} {
			name := tt.name + " plain"
			if atomic {
				name = tt.name + " atomic"
			}
			t.Run(name, func(t *testing.T) {
				app := newRepeatTestApp(t)
				req := SendRequest{
					AmountText: "1",
					AssetRef:   "algo",
					FromRaw:    tt.from,
					ToRaw:      tt.to,
					Atomic:     atomic,
				}

				plan, err := app.PrepareSend(context.Background(), req)
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("PrepareSend() error = %v, want it to contain %q", err, tt.wantErr)
				}
				if plan != nil {
					t.Fatalf("PrepareSend() plan = %#v, want none", plan)
				}

				// Preparing any transaction would fail with ErrNoAlgodClient:
				// the refusal comes first, so nothing was prepared.
				result, err := app.ExecuteSend(context.Background(), req)
				if errors.Is(err, engine.ErrNoAlgodClient) {
					t.Fatalf("ExecuteSend() reached transaction preparation: %v", err)
				}
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("ExecuteSend() error = %v, want it to contain %q", err, tt.wantErr)
				}
				if result != nil {
					t.Fatalf("ExecuteSend() result = %#v, want none", result)
				}
			})
		}
	}
}

func TestSendWithoutRepeatsIsNotRefused(t *testing.T) {
	tests := []struct {
		name string
		from []string
		to   []string
	}{
		{name: "recipient set", from: []string{"alice"}, to: []string{"@team", repeatDan}},
		{name: "sender set", from: []string{"@team", "alice"}, to: []string{repeatDan}},
		// The sender may also be a recipient: each side is checked on its own.
		{name: "sender among recipients", from: []string{"alice"}, to: []string{"alice", "bob", repeatDan}},
	}
	for _, tt := range tests {
		for _, atomic := range []bool{false, true} {
			name := tt.name + " plain"
			if atomic {
				name = tt.name + " atomic"
			}
			t.Run(name, func(t *testing.T) {
				app := newRepeatTestApp(t)
				req := SendRequest{
					AmountText: "1",
					AssetRef:   "algo",
					FromRaw:    tt.from,
					ToRaw:      tt.to,
					Atomic:     atomic,
				}

				plan, err := app.PrepareSend(context.Background(), req)
				if err != nil {
					t.Fatalf("PrepareSend() error = %v", err)
				}
				if got := len(plan.FromAddresses) + len(plan.ToAddresses); got != 4 {
					t.Fatalf("plan has %d addresses, want 4: %#v", got, plan)
				}

				_, err = app.ExecuteSend(context.Background(), req)
				if !errors.Is(err, engine.ErrNoAlgodClient) {
					t.Fatalf("ExecuteSend() error = %v, want %v", err, engine.ErrNoAlgodClient)
				}
			})
		}
	}
}
