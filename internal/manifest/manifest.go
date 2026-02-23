// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

// Package manifest provides provider manifest generation for auditing.
// Use --print-manifest flag to generate a JSON manifest of all registered providers.
package manifest

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/aplane-algo/aplane/internal/algorithm"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/signing"
)

// ProviderManifest contains complete information about all registered providers
type ProviderManifest struct {
	// Unified LogicSigDSA registry (post-quantum DSAs with versioned derivation)
	LogicSigDSAs []LogicSigDSAInfo `json:"logicsig_dsas"`

	// Supporting registries
	SigningProviders  []SigningProviderInfo   `json:"signing_providers"`
	AlgorithmMetadata []AlgorithmMetadataInfo `json:"algorithm_metadata"`
}

// LogicSigDSAInfo contains information about a unified LogicSigDSA implementation
type LogicSigDSAInfo struct {
	KeyType           string `json:"key_type"`            // e.g., "falcon1024-v1"
	SignatureSize     int    `json:"signature_size"`      // Max signature size in bytes
	MnemonicScheme    string `json:"mnemonic_scheme"`     // "bip39" or "algorand"
	MnemonicWordCount int    `json:"mnemonic_word_count"` // e.g., 24
	DisplayColor      string `json:"display_color,omitempty"`
}

// SigningProviderInfo contains information about a signing provider
type SigningProviderInfo struct {
	Family string `json:"family"` // e.g., "ed25519", "falcon1024"
}

// AlgorithmMetadataInfo contains metadata about a signature algorithm
type AlgorithmMetadataInfo struct {
	Family                string `json:"family"` // e.g., "ed25519", "falcon1024"
	SignatureSize         int    `json:"signature_size"`
	MnemonicWordCount     int    `json:"mnemonic_word_count"`
	MnemonicScheme        string `json:"mnemonic_scheme"`
	RequiresLogicSig      bool   `json:"requires_logicsig"`
	CurrentLsigVersion    int    `json:"current_lsig_version,omitempty"`
	SupportedLsigVersions []int  `json:"supported_lsig_versions,omitempty"`
	DefaultDerivation     string `json:"default_derivation"`
	DisplayColor          string `json:"display_color,omitempty"`
}

// Generate builds a ProviderManifest from all registries
func Generate() *ProviderManifest {
	manifest := &ProviderManifest{
		LogicSigDSAs:      []LogicSigDSAInfo{},
		SigningProviders:  []SigningProviderInfo{},
		AlgorithmMetadata: []AlgorithmMetadataInfo{},
	}

	// Collect LogicSigDSA implementations (unified registry)
	for _, dsa := range logicsigdsa.GetAll() {
		manifest.LogicSigDSAs = append(manifest.LogicSigDSAs, LogicSigDSAInfo{
			KeyType:           dsa.KeyType(),
			SignatureSize:     dsa.CryptoSignatureSize(),
			MnemonicScheme:    dsa.MnemonicScheme(),
			MnemonicWordCount: dsa.MnemonicWordCount(),
			DisplayColor:      dsa.DisplayColor(),
		})
	}

	// Collect signing providers (for key file operations)
	for _, family := range signing.GetRegisteredFamilies() {
		manifest.SigningProviders = append(manifest.SigningProviders, SigningProviderInfo{
			Family: family,
		})
	}

	// Collect algorithm metadata
	for _, family := range algorithm.GetRegisteredFamilies() {
		meta, err := algorithm.GetMetadata(family)
		if err != nil {
			continue
		}
		info := AlgorithmMetadataInfo{
			Family:            family,
			SignatureSize:     meta.CryptoSignatureSize(),
			MnemonicWordCount: meta.MnemonicWordCount(),
			MnemonicScheme:    meta.MnemonicScheme(),
			RequiresLogicSig:  meta.RequiresLogicSig(),
			DefaultDerivation: meta.DefaultDerivation(),
			DisplayColor:      meta.DisplayColor(),
		}
		if meta.RequiresLogicSig() {
			info.CurrentLsigVersion = meta.CurrentLsigVersion()
			info.SupportedLsigVersions = meta.SupportedLsigVersions()
		}
		manifest.AlgorithmMetadata = append(manifest.AlgorithmMetadata, info)
	}

	return manifest
}

// Print outputs the manifest as formatted JSON to stdout
func Print() error {
	manifest := Generate()
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal manifest: %w", err)
	}
	fmt.Println(string(data))
	return nil
}

// PrintAndExit prints the manifest and exits with code 0 on success, 1 on error
func PrintAndExit() {
	if err := Print(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}
