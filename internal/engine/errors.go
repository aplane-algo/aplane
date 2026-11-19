// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"errors"

	"github.com/aplane-algo/aplane/internal/engine/connect"
	"github.com/aplane-algo/aplane/internal/signing"
)

var (
	// ErrNotConnected indicates no connection to Signer. It is the error a
	// signer request returns with no signer client, so errors.Is finds it in a
	// request's wrapped error too.
	ErrNotConnected = connect.ErrNotConnected

	// ErrInvalidAddress indicates an invalid address or alias
	ErrInvalidAddress = errors.New("invalid address or alias")

	// ErrInvalidAssetID indicates an invalid asset ID
	ErrInvalidAssetID = errors.New("invalid asset ID")

	// ErrNoSigningKey indicates no signing key is available for an address
	ErrNoSigningKey = errors.New("no signing key available for address")

	// ErrAlreadyConnected indicates an attempt to connect when already connected
	ErrAlreadyConnected = errors.New("already connected")

	// ErrInvalidNetwork indicates an invalid network name
	ErrInvalidNetwork = errors.New("invalid network")

	// ErrSimulationFailed indicates the simulate endpoint reported a transaction failure.
	// Details are already printed to the console by SimulateTransactions.
	ErrSimulationFailed = signing.ErrSimulationFailed

	// ErrSignerLocked indicates the signer is locked and must be unlocked via apadmin
	ErrSignerLocked = errors.New("signer is locked — unlock via apadmin before signing")

	// ErrSignerLockedForGeneration answers a key type the signer does not
	// list while it is locked: a locked signer lists only its built-in key
	// types, and generates none.
	ErrSignerLockedForGeneration = errors.New("the signer is locked; unlock it in apadmin to generate keys (a locked signer lists only its built-in key types)")

	// ErrNoAlgodClient indicates the algod client is not configured
	ErrNoAlgodClient = errors.New("algod client not configured")

	// ErrAliasNotFound indicates the specified alias does not exist
	ErrAliasNotFound = errors.New("alias not found")

	// ErrSetNotFound indicates the specified set does not exist
	ErrSetNotFound = errors.New("set not found")
)
