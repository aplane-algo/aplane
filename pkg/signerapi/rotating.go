// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerapi

import "fmt"

// MaxRotatingUserSlots bounds the user slots of a rotating request: the
// atomic group limit, before any resource dummies are added.
const MaxRotatingUserSlots = 16

// RotatingPrepareRequest asks the signer to prepare a spend from a rotating
// account (POST /sign/rotating/prepare). The signer finds the account's live
// stage on chain, sets RekeyTo on the rotating account's transaction to the
// next stage's address, adds the resource dummies, sets fees and the group
// ID, and returns the exact unsigned group. It stores nothing.
//
// Exactly one of TxnBytesHex and Requests is set. TxnBytesHex is the
// single-transaction form: one ungrouped transaction from the rotating
// account. Requests is the group form, in the ordinary /sign slot grammar:
// exactly one slot whose sender is the rotating account, carrying no
// auth_address and no lsig_args, and any number of slots signed by
// non-rotating keys this signer holds. On these endpoints an omitted
// auth_address on such a slot means the sender's own key. Every slot is
// ungrouped and sets no rekey_to, and every slot's validity window equals
// the rotating slot's, which spans at most 100 rounds. Passthrough and
// foreign slots are not accepted.
type RotatingPrepareRequest struct {
	RequestID   string        `json:"request_id,omitempty"`
	Account     string        `json:"account"`
	TxnBytesHex string        `json:"txn_bytes_hex,omitempty"`
	Requests    []SignRequest `json:"requests,omitempty"`
}

// RotationSlot describes the rotating account's transaction in a group.
// Index is its position in the group. Stage is the account's live stage, the
// one that signs; Target is the stage the spend hands the account to, always
// Stage + 1. A prepare response carries RekeyTo, the target stage's address;
// a sign response carries TxID, the rotating transaction's ID.
type RotationSlot struct {
	Index   int    `json:"index"`
	Stage   uint64 `json:"stage"`
	Target  uint64 `json:"target"`
	RekeyTo string `json:"rekey_to,omitempty"`
	TxID    string `json:"txid,omitempty"`
}

// RotatingPrepareResponse is the exact unsigned group the signer will sign.
// The user slots come first, in request order, followed by the canonical
// resource dummies. Clients validate and simulate these bytes and send the
// user slots back unchanged.
//
// Rotations is authoritative. Stage, Target and RekeyTo repeat its single
// entry for clients that predate the group form, and will be removed once
// every first-party consumer reads Rotations.
type RotatingPrepareResponse struct {
	Account string `json:"account"`
	// Stage is Rotations[0].Stage.
	Stage uint64 `json:"stage"`
	// Target is Rotations[0].Target.
	Target uint64 `json:"target"`
	// RekeyTo is Rotations[0].RekeyTo.
	RekeyTo string `json:"rekey_to"`
	// Transactions is the final unsigned group, TX-prefixed hex.
	Transactions []string        `json:"transactions"`
	Mutations    *MutationReport `json:"mutations,omitempty"`
	// Rotations lists the rotating slots of the group; one entry today.
	Rotations []RotationSlot `json:"rotations,omitempty"`
	// OwnedIndexes lists, ascending, the positions the signer signs with
	// ordinary keys. Every other position below the user slot count is a
	// rotation; every position at or above it is a resource dummy.
	OwnedIndexes []int `json:"owned_indexes,omitempty"`
}

// RotatingSignRequest asks the signer to sign a prepared rotating group
// (POST /sign/rotating/sign). The rotating slot's RekeyTo names the stage
// after the one that signs, so the request carries no stage of its own.
//
// Exactly one of Transactions and Requests is set. Transactions is the
// single-transaction form: the complete prepared group, dummies included.
// Requests is the group form: the prepared user slots in group order, each
// txn_bytes_hex holding the prepared bytes, with the same auth_address and
// lsig_args sent to prepare. The dummies are not resent; the signer rebuilds
// them, and the group ID every user slot carries binds them.
type RotatingSignRequest struct {
	RequestID    string        `json:"request_id,omitempty"`
	Account      string        `json:"account"`
	Transactions []string      `json:"transactions,omitempty"`
	Requests     []SignRequest `json:"requests,omitempty"`
}

// RotatingSignResponse carries the signed group, aligned with the prepared
// group and with every position filled.
//
// Rotations is authoritative. Stage, Target and TxID repeat its single
// entry for clients that predate the group form.
type RotatingSignResponse struct {
	Signed []string `json:"signed"`
	// Stage is Rotations[0].Stage: the stage whose program the signature
	// revealed.
	Stage uint64 `json:"stage"`
	// Target is Rotations[0].Target: the stage that controls the account
	// once the transaction lands.
	Target uint64 `json:"target"`
	// TxID is Rotations[0].TxID.
	TxID      string         `json:"txid"`
	GroupID   string         `json:"group_id"`
	Rotations []RotationSlot `json:"rotations,omitempty"`
}

// Validate checks the request shape. The signer applies every protocol rule.
func (r RotatingPrepareRequest) Validate() error {
	if err := validateSignRequestID(r.RequestID); err != nil {
		return err
	}
	if r.Account == "" {
		return fmt.Errorf("account is required")
	}
	return validateRotatingForms(r.TxnBytesHex != "", "txn_bytes_hex", r.Requests)
}

// Validate checks the request shape.
func (r RotatingSignRequest) Validate() error {
	if err := validateSignRequestID(r.RequestID); err != nil {
		return err
	}
	if r.Account == "" {
		return fmt.Errorf("account is required")
	}
	return validateRotatingForms(len(r.Transactions) > 0, "transactions", r.Requests)
}

// validateRotatingForms requires exactly one of a request's two forms.
func validateRotatingForms(hasSingle bool, singleField string, requests []SignRequest) error {
	hasGroup := requests != nil
	switch {
	case hasSingle && hasGroup:
		return fmt.Errorf("set exactly one of %s and requests", singleField)
	case !hasSingle && !hasGroup:
		return fmt.Errorf("one of %s and requests is required", singleField)
	case hasGroup && len(requests) == 0:
		return fmt.Errorf("requests must not be empty")
	case hasGroup && len(requests) > MaxRotatingUserSlots:
		return fmt.Errorf("requests has %d slots, maximum is %d", len(requests), MaxRotatingUserSlots)
	}
	return nil
}
