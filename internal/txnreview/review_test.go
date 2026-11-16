// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package txnreview

import (
	"strings"
	"testing"
)

// The text prints the accounts only once the chain is read: each balance and
// whether the signer can sign for the account; and where nothing was read,
// why.
func TestAccountsTextFollowsTheChainRead(t *testing.T) {
	balance := func(v uint64) *uint64 { return &v }
	review := Review{
		Items: []Item{{Details: Details{Title: "Payment"}}},
		Parties: []Party{
			{Address: "OWN", Held: true, Signs: true, KeyType: "ed25519", MicroAlgos: balance(1_234_567_890), Signable: true},
			{Address: "OTHER", MicroAlgos: balance(100_000)},
			{Address: "HELD", Held: true, Signable: true},
		},
	}
	if text := review.Text(); strings.Contains(text, "Accounts") || review.AccountsText() != "" {
		t.Fatalf("the accounts are printed before the chain is read:\n%s", text)
	}

	review.Chain = &ChainRead{Round: 77}
	want := `--- Accounts at round 77 ---
OWN
  1234.567890 ALGO · signable
OTHER
  0.100000 ALGO · not signable
HELD
  balance unavailable · signable
`
	if got := review.AccountsText(); got != want {
		t.Fatalf("accounts:\n%s\nwant:\n%s", got, want)
	}
	if !strings.HasSuffix(review.Text(), want) {
		t.Fatalf("the text does not end with the accounts:\n%s", review.Text())
	}

	review.Chain = &ChainRead{Unavailable: "no algod is configured for network testnet"}
	if got := review.AccountsText(); got != "Balances unavailable: no algod is configured for network testnet\n" {
		t.Fatalf("unavailable: %q", got)
	}
}

// Why the node was not read is escaped with the rest of the review, so an
// error from it can't drive the operator's terminal, and the copy shares no
// balance with the review it was made from.
func TestSafeEscapesWhatTheNodeSaid(t *testing.T) {
	hostile := "evil\x1b[2J"
	balance := uint64(5)
	review := Review{Parties: []Party{{Address: "A", MicroAlgos: &balance}}, Chain: &ChainRead{Unavailable: hostile}}
	safe := review.Safe()
	if strings.Contains(safe.Chain.Unavailable, "\x1b") {
		t.Errorf("not escaped: %q", safe.Chain.Unavailable)
	}
	if review.Chain.Unavailable != hostile {
		t.Error("Safe changed the review it was given")
	}
	if safe.Parties[0].MicroAlgos == review.Parties[0].MicroAlgos || *safe.Parties[0].MicroAlgos != 5 {
		t.Errorf("safe balance = %v", safe.Parties[0].MicroAlgos)
	}
}

// Until the chain is read, an account is signable where this signer holds an
// aplane key for it or this request signs one of its transactions.
func TestSetPartiesCallsAnAccountSignableByWhatTheSignerKnows(t *testing.T) {
	review := Review{Items: []Item{
		{Position: PositionSign, Details: Details{Sender: "REKEYED", Effects: []Effect{{Kind: EffectTransfer, From: "REKEYED", To: "PAYEE"}}}},
		{Position: PositionForeign, Details: Details{Sender: "OTHER", Effects: []Effect{{Kind: EffectTransfer, From: "OTHER", To: "HELD"}}}},
	}}
	review.SetParties(func(address string) bool { return address == "HELD" }, nil)
	want := map[string]bool{"REKEYED": true, "PAYEE": false, "OTHER": false, "HELD": true}
	for _, p := range review.Parties {
		if p.Signable != want[p.Address] {
			t.Errorf("%s: signable = %t, want %t", p.Address, p.Signable, want[p.Address])
		}
	}
}
