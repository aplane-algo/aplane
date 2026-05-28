// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package genericlsig provides the Template interface for generic LogicSig templates.
// Generic LogicSigs authorize transactions through TEAL program evaluation only,
// without requiring cryptographic signatures (unlike DSA-based LogicSigs like Falcon-1024).
//
// To add a new generic LogicSig template:
// 1. Create a new package in lsig/<template>/
// 2. Implement the Template interface
// 3. Add registration in the provider package that calls genericlsig.Register()
// 4. Add the appropriate RegisterClient/RegisterSigner call to lsig/all.go
package genericlsig

import (
	"context"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"

	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
)

// Template defines the interface for generic LogicSig templates.
// Implementations represent parameterized TEAL programs that authorize
// transactions through program evaluation (not cryptographic signatures).
//
// Template extends lsigprovider.LSigProvider with TEAL generation methods.
type Template interface {
	lsigprovider.LSigProvider

	// TEAL Generation
	GenerateTEAL(params map[string]string) (string, error)
	Compile(ctx context.Context, params map[string]string, algodClient *algod.Client) (bytecode []byte, address string, err error)
	CompileWithSalt(ctx context.Context, params map[string]string, algodClient *algod.Client) (lsigsalt.FindResult, error)
}

// SaltedTemplate is implemented by templates that expose the
// off-curve salt metadata used for deterministic key-file storage.
type SaltedTemplate interface {
	CompileWithSalt(ctx context.Context, params map[string]string, algodClient *algod.Client) (lsigsalt.FindResult, error)
}
