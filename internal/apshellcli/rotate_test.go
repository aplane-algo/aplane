// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/pkg/signerapi"
)

func TestCmdRotateRejectsBadUsage(t *testing.T) {
	r := &REPLState{}
	for _, args := range [][]string{
		{},
		{"vault", "later"},
		{"vault", "nowait", "extra"},
		{"status", "vault", "extra"},
		{"exit", "vault", "to", "bob"},
		{"recover"},
		{"recover", "vault", "--stage"},
		{"recover", "vault", "--depth", "3"},
		{"recover", "vault", "cancel", "now"},
	} {
		if _, err := r.cmdRotate(args, nil); err == nil || !strings.Contains(err.Error(), "usage:") {
			t.Fatalf("args %v: err = %v, want usage error", args, err)
		}
	}
	if _, err := r.cmdRotate([]string{"recover", "vault", "--stage", "ten"}, nil); err == nil || !strings.Contains(err.Error(), "not a non-negative integer") {
		t.Fatalf("bad number: %v", err)
	}
	if _, err := r.cmdRotate([]string{"recover", "vault", "--window", "3"}, nil); err == nil || !strings.Contains(err.Error(), "--window needs --stage") {
		t.Fatalf("window without stage: %v", err)
	}
}

func TestParseRotateRecover(t *testing.T) {
	req, err := parseRotateRecover([]string{"vault", "--stage", "10000", "--window", "8", "--max-stages", "500", "--timeout", "90"})
	if err != nil {
		t.Fatal(err)
	}
	if req.Account != "vault" || req.Cancel || req.Stage == nil || *req.Stage != 10000 || req.Window != 8 || req.MaxStages != 500 || req.TimeoutSeconds != 90 {
		t.Fatalf("parsed = %+v", req)
	}
	req, err = parseRotateRecover([]string{"vault", "cancel"})
	if err != nil || !req.Cancel || req.Account != "vault" {
		t.Fatalf("cancel parsed = %+v, %v", req, err)
	}
	req, err = parseRotateRecover([]string{"vault"})
	if err != nil || req.Cancel || req.Stage != nil || req.MaxStages != 0 {
		t.Fatalf("bare recover parsed = %+v, %v", req, err)
	}
}

func TestStageLookupLineWordsEachOutcomeActiveAndStopped(t *testing.T) {
	stage := uint64(418)
	const txid = "TXIDTXIDTXIDTXIDTXIDTXIDTXIDTXIDTXIDTXIDTXIDTXIDTXID"
	candidate := func(probe string) *signerapi.RotatingStageLookupStatus {
		return &signerapi.RotatingStageLookupStatus{Outcome: signerapi.RotatingLookupCandidate, Stage: &stage, Probe: probe, TxID: txid, Round: 9000}
	}
	other := func(outcome string) *signerapi.RotatingStageLookupStatus {
		return &signerapi.RotatingStageLookupStatus{Outcome: outcome}
	}
	for _, tc := range []struct {
		lookup          *signerapi.RotatingStageLookupStatus
		active, stopped string
	}{
		{candidate(signerapi.RotatingLookupProbeMatched),
			"stage 418 was read from the last spend (" + txid + ", round 9000) and confirmed",
			"stage 418 was read from the last spend (" + txid + ", round 9000) and confirmed"},
		{candidate(signerapi.RotatingLookupProbeMissed),
			"stage 418 read from the last spend (" + txid + ") did not match; searching",
			"stage 418 read from the last spend (" + txid + ") did not match"},
		{candidate(signerapi.RotatingLookupProbeAlreadyCached),
			"stage 418 read from the last spend (" + txid + ") is not the authorizer's; searching",
			"stage 418 read from the last spend (" + txid + ") was not the authorizer's"},
		{other(signerapi.RotatingLookupUnavailable),
			"the Indexer could not be read; searching without it",
			"the Indexer could not be read"},
		{other(signerapi.RotatingLookupNoOutgoingRekey),
			"the Indexer shows no rekey sent by this account; searching",
			"the Indexer showed no rekey sent by this account"},
		{other(signerapi.RotatingLookupNotCurrent),
			"the Indexer's newest rekey for this account is not the current one; searching",
			"the Indexer's newest rekey for this account was not the current one"},
		{other(signerapi.RotatingLookupNotAStageProgram),
			"the account's last rekey was not signed by a stage program; searching",
			"the account's last rekey was not signed by a stage program"},
		{other(signerapi.RotatingLookupWrongNetwork),
			"the Indexer answered for another network; searching without it",
			"the Indexer answered for another network"},
	} {
		name := tc.lookup.Outcome + "/" + tc.lookup.Probe
		if got := stageLookupLine(tc.lookup, true); got != tc.active {
			t.Errorf("%s active:\n got %q\nwant %q", name, got, tc.active)
		}
		if got := stageLookupLine(tc.lookup, false); got != tc.stopped {
			t.Errorf("%s stopped:\n got %q\nwant %q", name, got, tc.stopped)
		}
		if strings.Contains(stageLookupLine(tc.lookup, false), "searching") {
			t.Errorf("%s: the stopped wording says searching", name)
		}
	}
}

// The transaction ID comes from the signer's Indexer: control characters
// in it are shown, not acted on.
func TestStageLookupLineEscapesTheTransactionID(t *testing.T) {
	stage := uint64(3)
	l := &signerapi.RotatingStageLookupStatus{Outcome: signerapi.RotatingLookupCandidate, Stage: &stage, Probe: signerapi.RotatingLookupProbeMissed, TxID: "BAD\x1b[2J\u202eID"}
	got := stageLookupLine(l, false)
	if strings.ContainsAny(got, "\x1b\u202e") || !strings.Contains(got, `BAD\x1b[2J\u202eID`) {
		t.Fatalf("line = %q, want the ID escaped", got)
	}
}

func TestRecoveryStatusPrintsTheLookupBesideTheStopLine(t *testing.T) {
	var out strings.Builder
	r := &REPLState{Out: &out}
	stage := uint64(418)
	renderRecoveryStatus(r, "  ", &signerapi.RotatingRecoveryStatus{
		Stopped: "found", StoppedKind: "automatic", StoppedGrantID: 2, StoppedStage: &stage,
		AllowanceSpent: 1, AllowanceMax: 1024,
		Lookup: &signerapi.RotatingStageLookupStatus{Outcome: signerapi.RotatingLookupCandidate, Stage: &stage, Probe: signerapi.RotatingLookupProbeMatched, Round: 77},
	})
	want := "  recovery: last automatic grant 2 stopped: found (stage 418)\n" +
		"  lookup: stage 418 was read from the last spend (round 77) and confirmed\n" +
		"  automatic allowance: 1 of 1024 stages used this unlock\n"
	if out.String() != want {
		t.Fatalf("output:\n%s\nwant:\n%s", out.String(), want)
	}
	// No lookup ran: no line.
	out.Reset()
	renderRecoveryStatus(r, "  ", &signerapi.RotatingRecoveryStatus{Active: true, Kind: "automatic", GrantID: 3, MaxStages: 10, AllowanceMax: 10})
	if strings.Contains(out.String(), "lookup") {
		t.Fatalf("output without a lookup:\n%s", out.String())
	}
}
