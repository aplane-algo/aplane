// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package protocol

// ReviewVersion names the format of a sign request's review.
const ReviewVersion = "aplane.review.v1"

// Review is a signing request as data, for a client that draws it instead of
// printing the description. It says nothing the description does not: the
// signer prints the description from it.
type Review struct {
	Version string `json:"version"`
	// Group is set when the request has more than one transaction.
	Group bool `json:"group"`
	// Banners say how a group is made up.
	Banners []string      `json:"banners,omitempty"`
	Changes ReviewChanges `json:"changes"`
	Items   []ReviewItem  `json:"items"`
	// Parties are the accounts the request touches, in order of first
	// appearance.
	Parties []ReviewParty `json:"parties,omitempty"`
	// Findings are warnings about the request as a whole, such as two
	// accounts that look alike. The message's violations carry them too.
	Findings []PolicyViolation `json:"findings,omitempty"`
}

// ReviewChanges is what planning did to the request.
type ReviewChanges struct {
	Heading string   `json:"heading,omitempty"`
	Lines   []string `json:"lines,omitempty"`
	// Frozen is set for a request checked as sent.
	Frozen   bool   `json:"frozen,omitempty"`
	Dummies  int    `json:"dummies,omitempty"`
	FeeAdded uint64 `json:"fee_added,omitempty"`
}

// Review item positions.
const (
	ReviewPositionSign        = "sign"
	ReviewPositionPassthrough = "passthrough"
	ReviewPositionHeld        = "held"
	ReviewPositionForeign     = "foreign"
)

// ReviewNoteSigningKey labels the note that names the key a transaction
// signed here is signed with. A client may leave it out where it repeats the
// sender.
const ReviewNoteSigningKey = "Signing key"

// ReviewItem is one requested transaction.
type ReviewItem struct {
	// Position is how the request treats the transaction: sign, passthrough,
	// held or foreign.
	Position string `json:"position"`
	// Label is the heading's word for a transaction the request does not sign.
	Label string `json:"label,omitempty"`
	// Notes are the lines under the heading, such as the signing key.
	Notes []ReviewField `json:"notes,omitempty"`
	// Claims are the client's own words about the transaction, not verified.
	Claims []string `json:"claims,omitempty"`
	Title  string   `json:"title"`
	// Sender is the address the transaction is sent from.
	Sender   string            `json:"sender,omitempty"`
	Fields   []ReviewField     `json:"fields,omitempty"`
	Effects  []ReviewEffect    `json:"effects,omitempty"`
	Findings []PolicyViolation `json:"findings,omitempty"`
}

// ReviewField is one line of a transaction's review.
type ReviewField struct {
	// Label is empty for a remark, a line that is only its Value.
	Label string `json:"label,omitempty"`
	Value string `json:"value"`
	// Party is the address Value names, when it names one account.
	Party string `json:"party,omitempty"`
	// Alert marks a line the review warns of.
	Alert bool `json:"alert,omitempty"`
	// Depth is 1 for an entry of the list the field above it opens.
	Depth int `json:"depth,omitempty"`
}

// Review effect severities.
const (
	ReviewSeverityCaution = "caution"
	ReviewSeverityDanger  = "danger"
)

// ReviewEffect is one thing a transaction does between parties, for a
// picture of the request.
type ReviewEffect struct {
	Kind string `json:"kind"`
	From string `json:"from"`
	// To is empty for an effect on From alone, and for an app call.
	To string `json:"to,omitempty"`
	// Authority is the account that acts when it is neither end.
	Authority string `json:"authority,omitempty"`
	App       uint64 `json:"app,omitempty"`
	NewApp    bool   `json:"new_app,omitempty"`
	Text      string `json:"text"`
	// Severity is empty, caution or danger.
	Severity string `json:"severity,omitempty"`
}

// ReviewParty is one account a request touches.
type ReviewParty struct {
	Address string `json:"address"`
	// Held is set when the signer holds an aplane key for the address.
	Held bool `json:"held,omitempty"`
	// Signs is set when the request signs a transaction the account sends.
	Signs bool `json:"signs,omitempty"`
	// KeyType is the key type that signs for the account in this request.
	KeyType string `json:"key_type,omitempty"`
	// Lookalike is set when another account in the request looks like this
	// one; the review's findings name both.
	Lookalike bool `json:"lookalike,omitempty"`
}
