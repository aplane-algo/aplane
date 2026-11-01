// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apadminapp

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/protocol"
)

func TestASACommandGrammar(t *testing.T) {
	for _, ok := range [][]string{
		{"list"},
		{"add", "private-dev", "9"},
		{"add", "private-dev", "9", "--yes"},
		{"remove", "private-dev", "9"},
		{"remove", "--genesis", "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=", "9"},
	} {
		mode, err := CatalogAuthMode("asa", ok)
		if err != nil || mode != AuthUnlock {
			t.Errorf("CatalogAuthMode(asa %v) = %v, %v; want unlock", ok, mode, err)
		}
	}
	for _, bad := range [][]string{
		{}, {"list", "x"}, {"add", "private-dev"}, {"add", "private-dev", "0"}, {"add", "private-dev", "x"},
		{"remove", "--genesis", "9"}, {"forget", "private-dev", "9"}, {"add", "private-dev", "9", "--force"},
	} {
		if _, err := CatalogAuthMode("asa", bad); err == nil {
			t.Errorf("CatalogAuthMode(asa %v) accepted a malformed command", bad)
		}
	}
}

func lookupReply(message, result any) error {
	switch m := message.(type) {
	case protocol.LookupASAMessage:
		out := result.(*protocol.LookupASAResultMessage)
		out.Success = true
		out.Asset = protocol.ASAObservation{Network: m.Network, GenesisHash: "AQEB", AssetID: m.AssetID, UnitName: "XYZ\x1b[2J", Decimals: 2, Creator: "C", Clawback: "C", Manager: "M"}
	case protocol.AddASAMessage:
		out := result.(*protocol.AddASAResultMessage)
		out.Success, out.GenerationID = true, "gen-1"
	default:
		return fmt.Errorf("unexpected request %T", message)
	}
	return nil
}

func TestASAAddShowsTheAssetAndAsksFirst(t *testing.T) {
	requester := &fakeRequester{handle: lookupReply}
	var stdout, stderr bytes.Buffer
	var asked string
	err := (Catalog{Client: requester, Streams: Streams{Stdout: &stdout, Stderr: &stderr},
		Confirm: func(prompt string) bool { asked = prompt; return true }}).Run("asa", []string{"add", "private-dev", "9"})
	if err != nil {
		t.Fatal(err)
	}
	out := stdout.String()
	for _, want := range []string{"clawback address can take this asset", "decimals              2", "manager can change"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b") || strings.Contains(asked, "\x1b") {
		t.Fatal("an issuer-chosen name reached the terminal with a control character")
	}
	if len(requester.requests) != 2 {
		t.Fatalf("requests = %d, want a lookup then an add", len(requester.requests))
	}
	if add := requester.requests[1].(protocol.AddASAMessage); add.Confirmed.Decimals != 2 || add.Confirmed.AssetID != 9 {
		t.Fatalf("add carried %+v, want the observation shown", add.Confirmed)
	}
}

func TestASAAddDeclinedAddsNothing(t *testing.T) {
	requester := &fakeRequester{handle: lookupReply}
	var stdout, stderr bytes.Buffer
	if err := (Catalog{Client: requester, Streams: Streams{Stdout: &stdout, Stderr: &stderr}}).Run("asa", []string{"add", "private-dev", "9"}); err != nil {
		t.Fatal(err)
	}
	if len(requester.requests) != 1 {
		t.Fatalf("requests = %d, want the lookup only", len(requester.requests))
	}
}

func TestASARemoveReportsBlockingReferences(t *testing.T) {
	requester := &fakeRequester{handle: func(message, result any) error {
		out := result.(*protocol.RemoveASAResultMessage)
		out.Code, out.Error = "asa_referenced", "named by 1 policy reference(s)"
		out.Blocking = []protocol.ASAReference{{Document: "default", Pointer: "/limits/private-dev/asa:9"}}
		return nil
	}}
	var stdout, stderr bytes.Buffer
	err := (Catalog{Client: requester, Streams: Streams{Stdout: &stdout, Stderr: &stderr}}).Run("asa", []string{"remove", "private-dev", "9"})
	if err == nil || !strings.Contains(stderr.String(), "referenced by default at /limits/private-dev/asa:9") {
		t.Fatalf("remove: err %v, stderr %q", err, stderr.String())
	}
}
