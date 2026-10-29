// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerapi

import "fmt"

// RotatingPrepareRequest asks the signer to prepare one spend from a
// rotating account (POST /sign/rotating/prepare). The transaction must be
// ungrouped, set no RekeyTo and no close-out, and span at most 100 rounds.
// The signer finds the account's live stage on chain, sets RekeyTo to the
// next stage's address, adds the resource dummies, sets fees and the group
// ID, and returns the exact unsigned group. It stores nothing.
type RotatingPrepareRequest struct {
	RequestID   string `json:"request_id,omitempty"`
	Account     string `json:"account"`
	TxnBytesHex string `json:"txn_bytes_hex"`
}

// RotatingPrepareResponse is the exact unsigned group the signer will sign.
// Clients validate and simulate these bytes and send them back unchanged.
type RotatingPrepareResponse struct {
	Account string `json:"account"`
	// Stage is the account's live stage, the one that will sign.
	Stage uint64 `json:"stage"`
	// Target is the stage the spend hands the account to: always Stage + 1.
	Target uint64 `json:"target"`
	// RekeyTo is the target stage's address, which the signer set on the spend.
	RekeyTo string `json:"rekey_to"`
	// Transactions is the final unsigned group, TX-prefixed hex.
	Transactions []string        `json:"transactions"`
	Mutations    *MutationReport `json:"mutations,omitempty"`
}

// RotatingSignRequest asks the signer to sign a prepared rotating group
// (POST /sign/rotating/sign). The group's RekeyTo names the stage after the
// one that signs, so the request carries no stage of its own.
//
// AppCallInfo is optional app-call metadata for the approval prompt, as on
// /sign. It describes the spend and is checked against its bytes when
// rendered; it is not signed.
type RotatingSignRequest struct {
	RequestID    string       `json:"request_id,omitempty"`
	Account      string       `json:"account"`
	Transactions []string     `json:"transactions"`
	AppCallInfo  *AppCallInfo `json:"app_call_info,omitempty"`
}

// RotatingSignResponse carries the signed group. Stage is the stage whose
// program the signature revealed; Target is the stage that controls the
// account once the transaction lands.
type RotatingSignResponse struct {
	Signed  []string `json:"signed"`
	Stage   uint64   `json:"stage"`
	Target  uint64   `json:"target"`
	TxID    string   `json:"txid"`
	GroupID string   `json:"group_id"`
}

// Validate checks the request shape. The signer applies every protocol rule.
func (r RotatingPrepareRequest) Validate() error {
	if err := validateSignRequestID(r.RequestID); err != nil {
		return err
	}
	if r.Account == "" {
		return fmt.Errorf("account is required")
	}
	if r.TxnBytesHex == "" {
		return fmt.Errorf("txn_bytes_hex is required")
	}
	return nil
}

// Validate checks the request shape.
func (r RotatingSignRequest) Validate() error {
	if err := validateSignRequestID(r.RequestID); err != nil {
		return err
	}
	if r.Account == "" {
		return fmt.Errorf("account is required")
	}
	if len(r.Transactions) == 0 {
		return fmt.Errorf("transactions are required")
	}
	return nil
}
