// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

// Package genericlsig provides the Template interface for generic LogicSig templates.
// Generic LogicSigs authorize transactions through TEAL program evaluation only,
// without requiring cryptographic signatures (unlike DSA-based LogicSigs like Falcon-1024).
//
// To add a new generic LogicSig template:
// 1. Create a new package in lsig/<template>/
// 2. Implement the Template interface
// 3. Register via init() using genericlsig.Register()
// 4. Add a blank import to lsig/all.go
package genericlsig

import (
	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"

	"github.com/aplane-algo/aplane/internal/lsigprovider"
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
	Compile(params map[string]string, algodClient *algod.Client) (bytecode []byte, address string, err error)
}
