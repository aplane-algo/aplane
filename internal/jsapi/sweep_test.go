// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package jsapi

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type stubSweeper struct {
	got    *SweepRequest
	result *SweepResult
	err    error
}

func (s *stubSweeper) Sweep(_ context.Context, req SweepRequest) (*SweepResult, error) {
	s.got = &req
	return s.result, s.err
}

// sweep() is the shell's sweep: it hands the request to the host and never
// builds a closing transaction itself.
func TestSweepPassesTheRequestToTheHost(t *testing.T) {
	cases := []struct {
		name string
		code string
		want SweepRequest
	}{
		{
			name: "one account, defaults",
			code: `sweep("a", "dest")`,
			want: SweepRequest{From: []string{"a"}, To: "dest", Wait: true},
		},
		{
			name: "a list of accounts with every option",
			code: `sweep(["a", "b"], "dest", {asset: 31566704, leaving: 1000000, fee: 2000, wait: false})`,
			want: SweepRequest{From: []string{"a", "b"}, To: "dest", AssetID: 31566704,
				Leaving: 1000000, LeavingSet: true, Fee: 2000, UseFlatFee: true, Wait: false},
		},
		{
			name: "leaving nothing, said outright",
			code: `sweep("a", "dest", {leaving: 0})`,
			want: SweepRequest{From: []string{"a"}, To: "dest", LeavingSet: true, Wait: true},
		},
		{
			name: "LogicSig arguments",
			code: `sweep("a", "dest", {lsigArgs: {preimage: "text:secret"}})`,
			want: SweepRequest{From: []string{"a"}, To: "dest", Wait: true,
				LsigArgs: map[string][]byte{"preimage": []byte("secret")}},
		},
		{
			name: "a large amount as text",
			code: `sweep("a", "dest", {leaving: "9007199254740993"})`,
			want: SweepRequest{From: []string{"a"}, To: "dest", Leaving: 9007199254740993, LeavingSet: true, Wait: true},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, vm, api := newTestAPI(t)
			sweeper := &stubSweeper{result: &SweepResult{}}
			api.SetSweeper(sweeper)
			if _, err := vm.RunString(tc.code); err != nil {
				t.Fatalf("%s: %v", tc.code, err)
			}
			if sweeper.got == nil || !reflect.DeepEqual(*sweeper.got, tc.want) {
				t.Fatalf("request = %+v, want %+v", sweeper.got, tc.want)
			}
		})
	}
}

func TestSweepRefusesWhatItCannotRead(t *testing.T) {
	cases := []struct{ name, code, want string }{
		{"one argument", `sweep("a")`, "requires from and to"},
		{"an empty list", `sweep([], "dest")`, "list of accounts is empty"},
		{"a list entry that is not text", `sweep(["a", 7], "dest")`, "entry 2"},
		{"an unknown option", `sweep("a", "dest", {leave: 5})`, "leave"},
		{"note, which a sweep does not carry", `sweep("a", "dest", {note: "x"})`, "note"},
		{"a leaving amount that is not a whole number", `sweep("a", "dest", {leaving: 1.5})`, "invalid leaving"},
		{"wait that is not a boolean", `sweep("a", "dest", {wait: "false"})`, "wait"},
		{"options in the destination's place", `sweep("a", {wait: true})`, ""},
		{"an asset that is undefined", `sweep("a", "dest", {asset: undefined})`, "invalid asset"},
		{"a leaving amount that is null", `sweep("a", "dest", {leaving: null})`, "invalid leaving"},
		{"a fee that is null", `sweep("a", "dest", {fee: null})`, "invalid fee"},
		{"an empty account in the list", `sweep(["a", ""], "dest")`, "account 2 is empty"},
		{"an empty account", `sweep("", "dest")`, "account 1 is empty"},
		{"an empty destination", `sweep("a", "")`, "destination is empty"},
		{"lsigArgs that is not an object", `sweep("a", "dest", {lsigArgs: "x"})`, "invalid lsigArgs"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, vm, api := newTestAPI(t)
			sweeper := &stubSweeper{result: &SweepResult{}}
			api.SetSweeper(sweeper)
			_, err := vm.RunString(tc.code)
			if err == nil {
				t.Fatalf("%s was accepted (request %+v)", tc.code, sweeper.got)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to mention %q", err, tc.want)
			}
			if sweeper.got != nil {
				t.Fatalf("the host was called with %+v", sweeper.got)
			}
		})
	}
}

func TestSweepReturnsEachAccountsOutcome(t *testing.T) {
	_, vm, api := newTestAPI(t)
	api.SetSweeper(&stubSweeper{result: &SweepResult{
		AssetID: 0, To: "DEST", Succeeded: 1, Failed: 1,
		Items: []SweepItem{
			{From: "A", Amount: 5, TxID: "TX", Confirmed: true},
			{From: "B", Skipped: "balance too low"},
			{From: "C", Error: "refused"},
		},
	}})
	v, err := vm.RunString(`const r = sweep(["A","B","C"], "DEST");
		[r.to, r.simulated, r.succeeded, r.failed, r.items.length, r.items[0].txid, r.items[0].amount,
		 r.items[0].confirmed, r.items[1].skipped, r.items[2].error].join("|")`)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := v.String(), "DEST|false|1|1|3|TX|5|true|balance too low|refused"; got != want {
		t.Fatalf("result = %q, want %q", got, want)
	}
}

func TestSweepRaisesTheHostsError(t *testing.T) {
	_, vm, api := newTestAPI(t)
	api.SetSweeper(&stubSweeper{err: errors.New("all 1 transaction(s) failed (A: refused)")})
	if _, err := vm.RunString(`sweep("A", "DEST")`); err == nil || !strings.Contains(err.Error(), "A: refused") {
		t.Fatalf("error = %v, want the host's error", err)
	}
}

func TestSweepWithoutAHostIsAnError(t *testing.T) {
	_, vm, _ := newTestAPI(t)
	if _, err := vm.RunString(`sweep("A", "DEST")`); err == nil || !strings.Contains(err.Error(), "not available") {
		t.Fatalf("error = %v, want 'not available'", err)
	}
}
