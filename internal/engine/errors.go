// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package engine

import (
	"errors"

	"github.com/aplane-algo/aplane/internal/signing"
)

var (
	// ErrNotConnected indicates no connection to Signer
	ErrNotConnected = errors.New("not connected to Signer")

	// ErrInvalidAddress indicates an invalid address or alias
	ErrInvalidAddress = errors.New("invalid address or alias")

	// ErrInvalidAmount indicates an invalid amount
	ErrInvalidAmount = errors.New("invalid amount")

	// ErrInvalidAssetID indicates an invalid asset ID
	ErrInvalidAssetID = errors.New("invalid asset ID")

	// ErrNoSigningKey indicates no signing key is available for an address
	ErrNoSigningKey = errors.New("no signing key available for address")

	// ErrTransactionFailed indicates a transaction submission failure
	ErrTransactionFailed = errors.New("transaction failed")

	// ErrScriptError indicates an error during script execution
	ErrScriptError = errors.New("script execution error")

	// ErrAlreadyConnected indicates an attempt to connect when already connected
	ErrAlreadyConnected = errors.New("already connected")

	// ErrConnectionFailed indicates a connection attempt failure
	ErrConnectionFailed = errors.New("connection failed")

	// ErrInvalidNetwork indicates an invalid network name
	ErrInvalidNetwork = errors.New("invalid network")

	// ErrSimulationFailed indicates the simulate endpoint reported a transaction failure.
	// Details are already printed to the console by SimulateTransactions.
	ErrSimulationFailed = signing.ErrSimulationFailed

	// ErrSignerLocked indicates the signer is locked and must be unlocked via apadmin
	ErrSignerLocked = errors.New("signer is locked — unlock via apadmin before signing")

	// ErrNoAlgodClient indicates the algod client is not configured
	ErrNoAlgodClient = errors.New("algod client not configured")

	// ErrAliasNotFound indicates the specified alias does not exist
	ErrAliasNotFound = errors.New("alias not found")

	// ErrSetNotFound indicates the specified set does not exist
	ErrSetNotFound = errors.New("set not found")
)
