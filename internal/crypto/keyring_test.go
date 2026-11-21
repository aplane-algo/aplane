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

// A source token file opens only as the source tokens of its own selector:
// not as another selector's, and not as another class with the same
// selector.
func TestSourceTokensContextBindsClassAndSelector(t *testing.T) {
	kr, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	defer kr.Zero()
	const selector = "MYJZE3UF7G4JXR5STMQK5TSL5FNE7PE224BSKLZ2H4AJWJIPBEBQ"
	sealed, err := kr.Seal([]byte("tokens"), SourceTokensContext(selector))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := kr.Open(sealed, SourceTokensContext(selector))
	if err != nil {
		t.Fatalf("Open(own context) error = %v", err)
	}
	ZeroBytes(opened)
	for name, ctx := range map[string]ObjectContext{
		"another selector":           SourceTokensContext("default"),
		"a cosigner credential":      CosignerCredentialContext(selector),
		"an account key":             AccountKeyContext(selector),
		"a template":                 KeyTypeTemplateContext(selector),
		"no selector":                {Class: ClassSourceTokens},
		"an unknown class":           {Class: "source-token", Selector: selector},
		"a selector with a NUL byte": SourceTokensContext(selector + "\x00"),
	} {
		if _, err := kr.Open(sealed, ctx); err == nil {
			t.Fatalf("Open(%s) accepted a source token file", name)
		}
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

// A successor carries an existing anchor unchanged or, for a generation
// pruned since, not at all; it never re-anchors a generation to another seal.
func TestSuccessorKeepsOrDropsButNeverChangesAnAnchor(t *testing.T) {
	current, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	defer current.Zero()
	first, _ := NewHistoricalGenerationAnchor("gen-1787000000-cafef00d", []byte("first"))
	current.historicalAnchors = []HistoricalGenerationAnchor{first}
	changed, _ := NewHistoricalGenerationAnchor(first.GenerationID, []byte("other seal"))
	_, err = NewSuccessorKeyring(current, []HistoricalGenerationAnchor{changed})
	if want := "historical anchor for generation gen-1787000000-cafef00d would be changed"; err == nil || err.Error() != want {
		t.Fatalf("NewSuccessorKeyring(changed anchor) error = %v, want %q", err, want)
	}
	second, _ := NewHistoricalGenerationAnchor("gen-1787000001-deadbeef", []byte("second"))
	for _, anchors := range [][]HistoricalGenerationAnchor{{first, second}, {second}} {
		successor, err := NewSuccessorKeyring(current, anchors)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(successor.historicalAnchors, anchors) {
			t.Fatalf("anchors = %+v, want %+v", successor.historicalAnchors, anchors)
		}
		successor.Zero()
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

// Generation inventories record InspectTermEnvelope's term as is, relying on
// it to be 0 for plaintext members and rejected envelopes.
func TestInspectTermEnvelopeTermIsZeroUnlessPresentAndValid(t *testing.T) {
	kr, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	defer kr.Zero()
	sealed, err := kr.Seal([]byte("secret"), AccountKeyContext("ACCOUNT"))
	if err != nil {
		t.Fatal(err)
	}
	term, present, err := InspectTermEnvelope(sealed)
	if err != nil || !present || term <= 0 {
		t.Fatalf("sealed envelope = (%d, %v, %v)", term, present, err)
	}
	for _, data := range [][]byte{
		[]byte("not json"),
		[]byte(`{"plaintext":true}`),
		[]byte(`{"envelope_version":"x"}`),
		[]byte(`{"envelope_version":2}`),
		[]byte(`{"envelope_version":99,"term":5}`),
		bytes.Replace(sealed, []byte(`"term":`), []byte(`"term":-`), 1),
	} {
		term, present, err := InspectTermEnvelope(data)
		if (!present || err != nil) && term != 0 {
			t.Fatalf("InspectTermEnvelope(%s) = (%d, %v, %v), want term 0", data, term, present, err)
		}
		if present && err == nil {
			t.Fatalf("InspectTermEnvelope(%s) accepted a malformed envelope", data)
		}
	}
}
