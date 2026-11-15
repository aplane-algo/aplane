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

// The authorizer line is read by apshell now and the signer's lines are from
// its last finished pass. When the signer saw another authorizer the line
// names what it saw and when, does not call that stage live, leaves out its
// readiness, and says the alerts and notes below come from the same read. It
// claims no direction: apshell's node may be the one that is behind.
func TestSignerViewSaysWhenItSeesAnotherAuthorizer(t *testing.T) {
	stage := uint64(6)
	view := &signerapi.RotatingAccountStatus{
		Account: "ACCT", Authorizer: "STAGE6ADDR", Round: 66970977,
		Classification: signerapi.RotatingClassStage, Stage: &stage, Preparation: "ready", CachedEntries: 4103,
	}
	render := func(s *signerapi.RotatingAccountStatus, differs bool) string {
		var out strings.Builder
		renderSignerRotatingView(&REPLState{Out: &out}, "  ", s, differs)
		return out.String()
	}
	const after = "    this view, and any alert or note below, is from that read; the signer reads again on its next pass\n" +
		"    if the two still differ after that, apshell and the signer are reading different nodes or networks\n"

	if got, want := render(view, false), "  signer: live stage 6, ready, 4103 cached entries\n"; got != want {
		t.Errorf("current view:\n%s\nwant:\n%s", got, want)
	}
	got := render(view, true)
	if want := "  signer: sees another authorizer; at round 66970977 it saw STAGE6ADDR, stage 6, 4103 cached entries\n" + after; got != want {
		t.Errorf("differing view:\n%s\nwant:\n%s", got, want)
	}
	for _, word := range []string{"live stage", "ready", "behind", "moved"} {
		if strings.Contains(got, word) {
			t.Errorf("a differing view says %q:\n%s", word, got)
		}
	}

	// Without a round the line still names what the signer saw.
	noRound := *view
	noRound.Round = 0
	if got, want := render(&noRound, true), "  signer: sees another authorizer; it saw STAGE6ADDR, stage 6, 4103 cached entries\n"+after; got != want {
		t.Errorf("differing view without a round:\n%s\nwant:\n%s", got, want)
	}

	// The other readings say the same.
	for class, words := range map[string]string{
		signerapi.RotatingClassUnknown: "it saw STAGE6ADDR, authorizer not placed, 4103 cached entries\n" + after,
		signerapi.RotatingClassHeldKey: "it saw STAGE6ADDR, rekeyed to a key this signer holds, 4103 cached entries\n" + after,
	} {
		other := *view
		other.Classification, other.Stage = class, nil
		if got := render(&other, true); !strings.HasSuffix(got, words) || !strings.Contains(got, "sees another authorizer") {
			t.Errorf("%s with another authorizer:\n%s\nwant it to end: %s", class, got, words)
		}
	}

	// A stage reading with no number still gets its signer line, so the
	// lines after it are never left under the authorizer line alone.
	unnumbered := *view
	unnumbered.Stage = nil
	if got, want := render(&unnumbered, true), "  signer: sees another authorizer; at round 66970977 it saw STAGE6ADDR, a stage it did not number, 4103 cached entries\n"+after; got != want {
		t.Errorf("unnumbered stage, differing:\n%s\nwant:\n%s", got, want)
	}
	if got, want := render(&unnumbered, false), "  signer: a stage it did not number, ready, 4103 cached entries\n"; got != want {
		t.Errorf("unnumbered stage:\n%s\nwant:\n%s", got, want)
	}

	// The authorizer and the readiness are the signer's text: escaped.
	hostile := *view
	hostile.Authorizer = "BAD\x1b[2JADDR"
	if got := render(&hostile, true); strings.Contains(got, "\x1b") {
		t.Errorf("authorizer not escaped: %q", got)
	}
	hostile = *view
	hostile.Preparation = "rea\x1b[2Jdy"
	if got := render(&hostile, false); strings.Contains(got, "\x1b") {
		t.Errorf("readiness not escaped: %q", got)
	}
}

// With no entry for the account in the signer's status, the output says so,
// not nothing at all. The signer reports the keys it holds after a pass that
// read them, and nothing while locked.
func TestSignerViewSaysWhenThereIsNone(t *testing.T) {
	var out strings.Builder
	renderSignerRotatingView(&REPLState{Out: &out}, "  ", nil, false)
	want := "  signer: no view of this account in its status; it reports the keys it holds after a background pass, while unlocked\n"
	if out.String() != want {
		t.Fatalf("output:\n%s\nwant:\n%s", out.String(), want)
	}
}
