// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

// Package lsig provides centralized registration for all LogicSig providers.
//
// There are two types of LogicSig providers:
//
// DSA-BASED PROVIDERS (e.g., Falcon-1024):
// - Require cryptographic key generation and signing
// - Register with: logicsigdsa, signing/scheme, algorithm, keygen, mnemonic registries
//
// GENERIC TEMPLATES (e.g., Timelock):
// - Authorize transactions through TEAL program evaluation only
// - Register with: genericlsig registry
//
// TO ADD A NEW PROVIDER:
// 1. Create your provider package in lsig/<provider>/
// 2. Add a Register*() call to RegisterAll() below
// 3. No other file changes required!
package lsig

import (
	"sync"

	falcon "github.com/aplane-algo/aplane/lsig/falcon1024"
	falcon1024template "github.com/aplane-algo/aplane/lsig/falcon1024/v1/template"
	"github.com/aplane-algo/aplane/lsig/hashlock"
	"github.com/aplane-algo/aplane/lsig/multitemplate"
	"github.com/aplane-algo/aplane/lsig/timelock"
)

var registerAllOnce sync.Once

// RegisterAll registers all LogicSig providers with their respective registries.
// This is idempotent and safe to call multiple times.
//
// Registration includes:
// - DSA-based LogicSig providers (Falcon-1024)
// - Generic LogicSig templates (timelock, hashlock, YAML-based templates)
func RegisterAll() {
	registerAllOnce.Do(func() {
		// DSA-based LogicSig providers (require cryptographic signing)
		falcon.RegisterAll()

		// YAML-based Falcon-1024 compositions (DSA + constraints)
		falcon1024template.RegisterTemplates()

		// Generic LogicSig templates (TEAL-only authorization)
		timelock.RegisterTemplate()
		hashlock.RegisterTemplate()
		multitemplate.RegisterTemplates()
	})
}
