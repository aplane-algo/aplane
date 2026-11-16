// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package txnreview

import (
	"strings"
	"testing"
)

// The text prints the accounts only once the chain is read: each balance and
// how the signer stands to the account, a rekey, and a key the chain doesn't
// name; and where nothing was read, why.
func TestAccountsTextFollowsTheChainRead(t *testing.T) {
	review := Review{
		Items: []Item{{Details: Details{Title: "Payment"}}},
		Parties: []Party{
			{Address: "OWN", Held: true, Signs: true, KeyType: "ed25519",
				Chain: &PartyChain{MicroAlgos: 1_234_567_890, Authorizer: "STAGE", AuthorizerHeld: true, OtherSigner: "OWN"}},
			{Address: "OTHER", Chain: &PartyChain{MicroAlgos: 100_000}},
			{Address: "HELD", Held: true},
		},
	}
	if text := review.Text(); strings.Contains(text, "Accounts") || review.AccountsText() != "" {
		t.Fatalf("the accounts are printed before the chain is read:\n%s", text)
	}

	review.Chain = &ChainRead{Round: 77}
	want := `--- Accounts at round 77 ---
OWN
  1234.567890 ALGO · signed here with its ed25519 aplane key
  rekeyed to STAGE, an address this signer holds an aplane key for
  this request signs with OWN, a key the chain does not name for it
OTHER
  0.100000 ALGO
HELD
  balance unavailable · this signer holds its aplane key, not signed here
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

// What the node said is escaped with the rest of the review: an error from it
// and an address it names can't drive the operator's terminal.
func TestSafeEscapesWhatTheNodeSaid(t *testing.T) {
	hostile := "evil\x1b[2J"
	review := Review{
		Parties: []Party{{Address: "A", Chain: &PartyChain{Authorizer: hostile, OtherSigner: hostile}}},
		Chain:   &ChainRead{Unavailable: hostile},
	}
	safe := review.Safe()
	for _, got := range []string{safe.Chain.Unavailable, safe.Parties[0].Chain.Authorizer, safe.Parties[0].Chain.OtherSigner} {
		if strings.Contains(got, "\x1b") {
			t.Errorf("not escaped: %q", got)
		}
	}
	if review.Parties[0].Chain.Authorizer != hostile || review.Chain.Unavailable != hostile {
		t.Error("Safe changed the review it was given")
	}
}
