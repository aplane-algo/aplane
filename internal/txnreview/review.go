// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package txnreview

import (
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/termsafe"
)

// Review is what a reviewer is shown of one request to sign, as data: how the
// request is made up, what planning did to it, and each requested
// transaction in order. Text prints it, so a screen that draws the data and a
// prompt that prints the text show the same request.
type Review struct {
	// Group is set when the request has more than one transaction.
	Group bool
	// Banners say how a group is made up: how many of its transactions this
	// request signs, and how many it does not.
	Banners []string
	Changes Changes
	Items   []Item
	// Parties are the accounts the request's effects move value or control
	// between, in order of first appearance. The text does not print them:
	// they say which of the addresses in the fields are this signer's own.
	Parties []Party
	// Findings are what a reviewer must not miss about the request as a
	// whole, beyond each transaction's own.
	Findings []Finding
}

// Party is one account a request touches.
type Party struct {
	Address string
	// Held is set when this signer holds an aplane key for the address.
	Held bool
	// Signs is set when this request signs a transaction the account sends.
	Signs bool
	// KeyType is the key type of the aplane key that signs for the account
	// in this request. It is empty when none does.
	KeyType string
	// Lookalike is set when another account in the request looks like this
	// one: the request has a finding that names both.
	Lookalike bool
}

// Position is how a request treats one of its transactions.
type Position string

const (
	// PositionSign is a transaction this request signs.
	PositionSign Position = "sign"
	// PositionPassthrough is a transaction that arrived already signed.
	PositionPassthrough Position = "passthrough"
	// PositionHeld is a transaction this request does not sign, of an account
	// or authorizer this signer holds an aplane key for.
	PositionHeld Position = "held"
	// PositionForeign is a transaction this request does not sign and this
	// signer holds no aplane key for.
	PositionForeign Position = "foreign"
)

// Item is one requested transaction.
type Item struct {
	Position Position
	// Label is the heading's word for a transaction this request does not
	// sign. It is empty for one it signs.
	Label string
	// Notes are the lines under the heading: the key that signs, or who
	// authorizes a transaction this request does not sign.
	Notes []Field
	// Claims are the client's own words about the transaction, which the
	// signer does not verify. They are shown under the title.
	Claims  []string
	Details Details
	// Findings are what a reviewer must not miss in the transaction. The
	// prompt lists them beside the text.
	Findings []Finding
}

// Text prints the transaction: its title, the client's claims, then its
// fields.
func (it Item) Text() string {
	var b strings.Builder
	b.WriteString(it.Details.Title)
	for _, claim := range it.Claims {
		b.WriteString("\n" + claim)
	}
	for _, f := range it.Details.Fields {
		b.WriteString("\n" + f.Line())
	}
	return b.String()
}

// Changes is what planning did to a request: the dummy transactions it added
// and the fee it raised, or, for a request checked as sent, what its fees
// already pay.
type Changes struct {
	// Heading names the kind of change. It is empty when there is none.
	Heading string
	Lines   []string
	// Frozen is set for a request checked as sent, which planning changed
	// nothing of.
	Frozen bool
	// Dummies is the number of dummy transactions the group carries for
	// LogicSig arguments and opcode budget.
	Dummies int
	// FeeAdded is the fee, in microAlgos, added for the signer's
	// authorization charge.
	FeeAdded uint64
}

// Text prints the changes, every line ending in a newline. With nothing to
// say it is empty.
func (c Changes) Text() string {
	if c.Heading == "" && len(c.Lines) == 0 {
		return ""
	}
	var b strings.Builder
	if c.Heading != "" {
		b.WriteString(c.Heading + "\n")
	}
	for _, line := range c.Lines {
		b.WriteString("  • " + line + "\n")
	}
	return b.String()
}

// Text prints the whole request: a heading, what planning changed, then each
// transaction under its own heading.
func (r Review) Text() string {
	var b strings.Builder
	if r.Group {
		fmt.Fprintf(&b, "=== TRANSACTION GROUP (%d transactions) ===\n", len(r.Items))
		for _, banner := range r.Banners {
			b.WriteString(banner + "\n")
		}
		b.WriteString(r.Changes.Text())
		b.WriteString("\n")
	} else {
		b.WriteString("=== SINGLE TRANSACTION ===\n\n")
		if changes := r.Changes.Text(); changes != "" {
			b.WriteString(changes + "\n")
		}
	}
	for i, item := range r.Items {
		if r.Group {
			if item.Label != "" {
				fmt.Fprintf(&b, "--- Transaction %d of %d [%s] ---\n", i+1, len(r.Items), item.Label)
			} else {
				fmt.Fprintf(&b, "--- Transaction %d of %d ---\n", i+1, len(r.Items))
			}
			for _, note := range item.Notes {
				b.WriteString(note.Line() + "\n")
			}
		}
		b.WriteString(item.Text())
		b.WriteString("\n")
	}
	return b.String()
}

// SetParties lists the accounts the items' effects name, in order of first
// appearance. held reports whether this signer holds an aplane key for an
// address, and signer names the key type that signs for a sender this request
// signs for, by item.
func (r *Review) SetParties(held func(address string) bool, signerKeyType func(item int) string) {
	r.Parties = nil
	index := map[string]int{}
	party := func(address string) *Party {
		if i, ok := index[address]; ok {
			return &r.Parties[i]
		}
		index[address] = len(r.Parties)
		r.Parties = append(r.Parties, Party{Address: address, Held: held != nil && held(address)})
		return &r.Parties[len(r.Parties)-1]
	}
	for i, item := range r.Items {
		for _, effect := range item.Details.Effects {
			for _, address := range []string{effect.From, effect.To, effect.Authority} {
				if address != "" {
					party(address)
				}
			}
		}
		if item.Details.Sender == "" {
			continue
		}
		p := party(item.Details.Sender)
		if item.Position != PositionSign {
			continue
		}
		p.Signs = true
		if signerKeyType != nil && p.KeyType == "" {
			p.KeyType = signerKeyType(i)
		}
	}
}

// Safe is the review with every string escaped for a terminal. Much of a
// review comes from the client or the chain: an asset's name, a method label,
// an auth address.
func (r Review) Safe() Review {
	line := termsafe.Line
	lines := func(in []string) []string {
		if in == nil {
			return nil
		}
		out := make([]string, len(in))
		for i, s := range in {
			out[i] = line(s)
		}
		return out
	}
	fields := func(in []Field) []Field {
		if in == nil {
			return nil
		}
		out := make([]Field, len(in))
		for i, f := range in {
			f.Label, f.Value, f.Party = line(f.Label), line(f.Value), line(f.Party)
			out[i] = f
		}
		return out
	}
	safe := Review{Group: r.Group, Banners: lines(r.Banners), Changes: r.Changes}
	safe.Changes.Heading, safe.Changes.Lines = line(r.Changes.Heading), lines(r.Changes.Lines)
	for _, item := range r.Items {
		item.Label, item.Notes, item.Claims = line(item.Label), fields(item.Notes), lines(item.Claims)
		// A title may run over several lines only where a caller put them.
		item.Details.Title, item.Details.Fields = termsafe.Lines(item.Details.Title), fields(item.Details.Fields)
		item.Details.Sender = line(item.Details.Sender)
		effects := make([]Effect, len(item.Details.Effects))
		for i, e := range item.Details.Effects {
			e.From, e.To, e.Authority, e.Text = line(e.From), line(e.To), line(e.Authority), line(e.Text)
			effects[i] = e
		}
		item.Details.Effects = effects
		findings := make([]Finding, len(item.Findings))
		for i, f := range item.Findings {
			f.Field, f.Value, f.Message = line(f.Field), line(f.Value), termsafe.Lines(f.Message)
			findings[i] = f
		}
		item.Findings = findings
		safe.Items = append(safe.Items, item)
	}
	for _, p := range r.Parties {
		p.Address, p.KeyType = line(p.Address), line(p.KeyType)
		safe.Parties = append(safe.Parties, p)
	}
	for _, f := range r.Findings {
		f.Field, f.Value, f.Message = line(f.Field), line(f.Value), termsafe.Lines(f.Message)
		safe.Findings = append(safe.Findings, f)
	}
	return safe
}
