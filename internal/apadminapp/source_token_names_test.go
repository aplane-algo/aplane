// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apadminapp

import (
	"fmt"
	"testing"

	"github.com/aplane-algo/aplane/internal/protocol"
)

func listingPage(omitted int, selectors ...protocol.SourceTokenSelector) protocol.SourceTokenListResultMessage {
	return protocol.SourceTokenListResultMessage{Success: true, Selectors: selectors, Omitted: omitted}
}

func listed(selector string, rows ...protocol.SourceTokenInfo) protocol.SourceTokenSelector {
	return protocol.SourceTokenSelector{Selector: selector, Tokens: rows}
}

// The names are the tokens set, in use or not, of every page; a needed token
// is not set. Each page names where the next starts, until one leaves none
// out.
func TestSourceTokenNamesGathersEveryPage(t *testing.T) {
	var c SourceTokenNames
	after, done, err := c.Add(listingPage(1,
		listed("default", protocol.SourceTokenInfo{Source: "ops", State: protocol.SourceTokenUnused}),
		listed("KEY1", protocol.SourceTokenInfo{Source: "risk", State: protocol.SourceTokenNeeded}, protocol.SourceTokenInfo{Source: "screening", State: protocol.SourceTokenInUse}),
	))
	if err != nil || done || after != "KEY1" {
		t.Fatalf("first page: after %q, done %v, %v", after, done, err)
	}
	if _, done, err = c.Add(listingPage(0, listed("KEY2", protocol.SourceTokenInfo{Source: "risk", State: protocol.SourceTokenNeeded}))); err != nil || !done {
		t.Fatalf("last page: done %v, %v", done, err)
	}
	if got := fmt.Sprint(c.Names()); got != fmt.Sprint(map[string][]string{"default": {"ops"}, "KEY1": {"screening"}}) {
		t.Fatalf("Names() = %s", got)
	}
}

// A failed reply, and a listing that does not move on, are errors.
func TestSourceTokenNamesRefusesAListingThatDoesNotEnd(t *testing.T) {
	if _, _, err := (&SourceTokenNames{}).Add(protocol.SourceTokenListResultMessage{Code: "identity_locked", Error: "locked"}); err == nil ||
		protocol.CodeForError(err) != "identity_locked" {
		t.Fatalf("a failed reply: %v", err)
	}
	if _, _, err := (&SourceTokenNames{}).Add(listingPage(3)); err == nil {
		t.Fatal("an empty page with selectors left out was accepted")
	}
	var c SourceTokenNames
	if _, _, err := c.Add(listingPage(1, listed("KEY1"))); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Add(listingPage(1, listed("KEY1"))); err == nil {
		t.Fatal("a page that ends where the last one did was accepted")
	}
	if names := (&SourceTokenNames{}).Names(); names == nil || len(names) != 0 {
		t.Fatalf("Names() before any page = %v, want an empty map", names)
	}
}
