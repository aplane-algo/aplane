// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package lsig holds everything that produces a LogicSig program for an
// account: the DSA families, the rotating account types, the YAML template
// machinery, and the registration entry points that wire them into the two
// binary roles.
//
// # Entry points
//
// There are two, one per binary role, and they are separate Go packages
// because the package is Go's unit of linkage:
//
//   - RegisterClient (this package): client-safe metadata only — key type
//     catalog rows, display metadata, sizes, address derivation. apshell links
//     this and nothing more; cmd/apshell/deps_test.go
//     (TestClientDoesNotLinkSignerRegistration) pins it.
//   - lsig/signerreg.RegisterSigner: everything the client registers plus
//     key generation, mnemonics and signing. Only signer-side binaries link
//     it.
//
// # Four kinds of directory
//
// Every top-level directory is one of:
//
//   - an entry point: this package, signerreg;
//   - template infrastructure: composeddsa (runtime TEAL composer and the
//     composed YAML template parser, including the bounded1 renderer),
//     generictemplate (generic YAML templates), dsafamily (the registration
//     descriptor a DSA family fills in);
//   - a DSA family: falcon1024, ed25519lsig, falcon1024_guarded. Each
//     registers an lsigprovider that assembles a LogicSig from stored
//     bytecode and signature arguments for ordinary /sign;
//   - a rotating type: rotatinghybrid, rotatingwots, rotatingtriple. These
//     have no lsigprovider; they derive a fresh stage program per spend and
//     sign only through the rotating1 flow.
//
// # Inside a family or type
//
// The split is always client-safe versus signer-only. A DSA family keeps
// constants, metadata and address derivation in packages the client may link
// (falcon1024/family, falcon1024/keys) and private-key operations in
// packages only the signer links (falcon1024/family/ops, falcon1024/signerops).
// A rotating type keeps the frozen stage program in stage/ (client-safe) and
// derivation and signing in signerops/. In both, X/signerreg is the
// signer-side registration of X; lsig/signerreg fans out to each of them.
//
// # Where the bounded contract lives
//
// bounded1 is owned by neutral packages under internal/: boundedmeta (durable
// metadata, canonical vocabulary, validation), txeffects (transaction-effect
// classification) and boundedadmin (contract-admin messages and ceremony).
// composeddsa holds only its program renderer and template-level profile
// validation. Shared code under internal/ reaches composeddsa for template
// parsing and registration, never for rendering.
//
// # Dependency rules
//
// test/arch/layering_test.go (TestSharedPackagesDoNotImportDSAFamilies)
// forbids internal/ and pkg/ from importing a family or type directly;
// families register behaviour through the core registries
// (internal/lsigprovider, internal/logicsigdsa, internal/signing,
// internal/keygen). composeddsa and generictemplate are exempt as template
// infrastructure. The test checks direct imports only.
package lsig
