// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package txnreview

import (
	"fmt"
	"strings"
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
