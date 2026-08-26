// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package crypto

import (
	"bytes"
	"slices"
	"strings"
	"testing"
)

func TestKeyringSealOpenBindsContext(t *testing.T) {
	kr, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	defer kr.Zero()
	plaintext := []byte("secret")
	ctx := AccountKeyContext("ACCOUNT")
	sealed, err := kr.Seal(plaintext, ctx)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := kr.Open(sealed, ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer ZeroBytes(opened)
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("opened = %q", opened)
	}
	if _, err := kr.Open(sealed, AccountKeyContext("OTHER")); err == nil {
		t.Fatal("Open accepted the wrong logical context")
	}
}

func TestSuccessorRetiresOrdinaryAuthorityButKeepsHistoricalAccess(t *testing.T) {
	current, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	defer current.Zero()
	ctx := AccountKeyContext("ACCOUNT")
	oldEnvelope, err := current.Seal([]byte("old"), ctx)
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := NewHistoricalGenerationAnchor("gen-1787000000-cafef00d", []byte("sealed generation"))
	if err != nil {
		t.Fatal(err)
	}
	successor, err := NewSuccessorKeyring(current, []HistoricalGenerationAnchor{anchor})
	if err != nil {
		t.Fatal(err)
	}
	defer successor.Zero()
	if successor.CurrentTerm() != current.CurrentTerm()+1 {
		t.Fatalf("successor term = %d", successor.CurrentTerm())
	}
	if _, err := successor.Open(oldEnvelope, ctx); err == nil {
		t.Fatal("successor granted retired term ordinary authority")
	}
	opened, err := successor.OpenHistoricalGenerationEnvelope(oldEnvelope, ctx, current.CurrentTerm())
	if err != nil {
		t.Fatal(err)
	}
	defer ZeroBytes(opened)
	if string(opened) != "old" {
		t.Fatalf("historical plaintext = %q", opened)
	}
	if got, ok := successor.HistoricalGenerationAnchor(anchor.GenerationID); !ok || got != anchor {
		t.Fatalf("historical anchor = %+v, %v", got, ok)
	}
}

func TestSuccessorPreservesExistingAnchors(t *testing.T) {
	current, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	defer current.Zero()
	first, _ := NewHistoricalGenerationAnchor("gen-1787000000-cafef00d", []byte("first"))
	current.historicalAnchors = []HistoricalGenerationAnchor{first}
	if _, err := NewSuccessorKeyring(current, []HistoricalGenerationAnchor{}); err == nil {
		t.Fatal("NewSuccessorKeyring dropped an existing anchor")
	}
	second, _ := NewHistoricalGenerationAnchor("gen-1787000001-deadbeef", []byte("second"))
	successor, err := NewSuccessorKeyring(current, []HistoricalGenerationAnchor{first, second})
	if err != nil {
		t.Fatal(err)
	}
	defer successor.Zero()
	if !slices.Equal(successor.HistoricalGenerationAnchors(), []HistoricalGenerationAnchor{first, second}) {
		t.Fatalf("anchors = %+v", successor.HistoricalGenerationAnchors())
	}
}

func TestHistoricalAnchorPinsExactSeal(t *testing.T) {
	anchor, err := NewHistoricalGenerationAnchor("gen-1787000000-cafef00d", []byte("seal"))
	if err != nil {
		t.Fatal(err)
	}
	if err := anchor.VerifyExact(anchor.GenerationID, []byte("seal")); err != nil {
		t.Fatal(err)
	}
	if err := anchor.VerifyExact(anchor.GenerationID, []byte("edit")); err == nil {
		t.Fatal("anchor accepted edited seal")
	}
	invalid := anchor
	invalid.SealSHA256 = strings.Repeat("A", 64)
	if err := invalid.Validate(); err == nil {
		t.Fatal("anchor accepted non-canonical digest")
	}
}
