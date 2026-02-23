// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package v1

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/tealsubst"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
	"github.com/aplane-algo/aplane/lsig/multitemplate"

	"filippo.io/edwards25519"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// ErrNoSuitableCounter is returned when no counter value 0-255 produces
// a LogicSig address that is not on the ed25519 curve.
var ErrNoSuitableCounter = errors.New("no suitable counter value found (all addresses are on the ed25519 curve)")

// counterPattern is the bytecblock opcode pattern containing the counter byte.
// Format: [bytecblock] [count=1] [len=1] [counter]
// The counter is at offset 4 in the bytecode.
var counterPattern = []byte{0x26, 0x01, 0x01}

// ComposedDSA represents a composed LogicSig that combines a Falcon DSA base
// with an optional TEAL suffix containing @variable substitution.
// It uses runtime TEAL compilation for safety (no bytecode patching except
// for the counter byte).
type ComposedDSA struct {
	// Identity
	keyType     string
	familyName  string
	version     int
	displayName string
	description string

	// Components
	base        family.DSABase
	tealSuffix  string                       // Raw TEAL with @variable refs
	params      []lsigprovider.ParameterDef  // Creation-time parameters
	runtimeArgs []lsigprovider.RuntimeArgDef // Signing-time arguments

	// Algod client for TEAL compilation (must be set before DeriveLsig)
	algodClient *algod.Client
}

// ComposedDSAConfig holds configuration for creating a ComposedDSA.
type ComposedDSAConfig struct {
	KeyType     string // e.g., "falcon1024-hashlock-v1"
	FamilyName  string // e.g., "falcon1024"
	Version     int
	DisplayName string
	Description string

	Base        family.DSABase
	TEALSuffix  string                       // Raw TEAL with @variable refs
	Params      []lsigprovider.ParameterDef  // Creation-time parameters
	RuntimeArgs []lsigprovider.RuntimeArgDef // Signing-time arguments
}

// NewComposedDSA creates a new composed DSA provider from configuration.
func NewComposedDSA(cfg ComposedDSAConfig) *ComposedDSA {
	return &ComposedDSA{
		keyType:     cfg.KeyType,
		familyName:  cfg.FamilyName,
		version:     cfg.Version,
		displayName: cfg.DisplayName,
		description: cfg.Description,
		base:        cfg.Base,
		tealSuffix:  cfg.TEALSuffix,
		params:      cfg.Params,
		runtimeArgs: cfg.RuntimeArgs,
	}
}

// SetAlgodClient sets the algod client used for TEAL compilation.
// This must be called before DeriveLsig.
func (c *ComposedDSA) SetAlgodClient(client *algod.Client) {
	c.algodClient = client
}

// KeyType returns the full identifier including version.
func (c *ComposedDSA) KeyType() string {
	return c.keyType
}

// Family returns the algorithm family without version.
func (c *ComposedDSA) Family() string {
	return c.familyName
}

// Version returns the derivation version number.
func (c *ComposedDSA) Version() int {
	return c.version
}

// Category returns the LSig category (always DSA for composed providers).
func (c *ComposedDSA) Category() string {
	return lsigprovider.CategoryDSALsig
}

// DisplayName returns the human-readable name.
func (c *ComposedDSA) DisplayName() string {
	return c.displayName
}

// Description returns a short description for UI display.
func (c *ComposedDSA) Description() string {
	return c.description
}

// DisplayColor returns the ANSI color code for UI display.
func (c *ComposedDSA) DisplayColor() string {
	return c.base.DisplayColor()
}

// CryptoSignatureSize returns the maximum signature size in bytes.
func (c *ComposedDSA) CryptoSignatureSize() int {
	return c.base.CryptoSignatureSize()
}

// MnemonicScheme returns the mnemonic scheme.
func (c *ComposedDSA) MnemonicScheme() string {
	return c.base.MnemonicScheme()
}

// MnemonicWordCount returns the expected number of mnemonic words.
func (c *ComposedDSA) MnemonicWordCount() int {
	return c.base.MnemonicWordCount()
}

// CreationParams returns the parameter definitions for this provider.
func (c *ComposedDSA) CreationParams() []lsigprovider.ParameterDef {
	return c.params
}

// ValidateCreationParams validates parameters against the stored definitions.
// Checks for unknown params, missing required values, type correctness,
// byte lengths, and min/max constraints.
func (c *ComposedDSA) ValidateCreationParams(params map[string]string) error {
	return multitemplate.ValidateParameterValues(params, c.params)
}

// RuntimeArgs returns all runtime argument definitions.
func (c *ComposedDSA) RuntimeArgs() []lsigprovider.RuntimeArgDef {
	return c.runtimeArgs
}

// BuildArgs assembles the LogicSig Args array.
// For composed DSAs, args are: [signature, runtime args...].
// Runtime args are ordered according to RuntimeArgs().
func (c *ComposedDSA) BuildArgs(signature []byte, runtimeArgs map[string][]byte) ([][]byte, error) {
	if signature == nil {
		return nil, fmt.Errorf("signature is required for DSA LogicSig")
	}
	args := [][]byte{signature}
	for _, argDef := range c.runtimeArgs {
		if val, ok := runtimeArgs[argDef.Name]; ok {
			args = append(args, val)
		} else if argDef.Required {
			return nil, fmt.Errorf("missing required arg: %s", argDef.Name)
		}
	}
	return args, nil
}

// GenerateKeypair generates a keypair using the DSA base.
func (c *ComposedDSA) GenerateKeypair(seed []byte) (publicKey, privateKey []byte, err error) {
	return c.base.GenerateKeypair(seed)
}

// Sign signs a message using the DSA base.
func (c *ComposedDSA) Sign(privateKey []byte, message []byte) (signature []byte, err error) {
	return c.base.Sign(privateKey, message)
}

// GenerateTEAL generates the complete TEAL source for this composed LogicSig.
// The structure is: preamble (pragma + counter) + substituted TEAL suffix + Falcon verification.
func (c *ComposedDSA) GenerateTEAL(publicKey []byte, params map[string]string) (string, error) {
	if err := c.ValidateCreationParams(params); err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString("#pragma version 12\n\n")

	// Counter byte using bytecblock (same as standard falcon1024-v1)
	// This will be patched post-compilation to find non-ed25519 address
	b.WriteString("// Counter byte (varied 0-255 to avoid ed25519 curve addresses)\n")
	b.WriteString("bytecblock 0x00\n\n")

	// Add substituted TEAL suffix (if any)
	if c.tealSuffix != "" {
		paramDefs := make([]tealsubst.ParamDef, len(c.params))
		for i, p := range c.params {
			paramDefs[i] = tealsubst.ParamDef{Name: p.Name, Type: p.Type}
		}

		substituted, err := tealsubst.SubstituteVariables(c.tealSuffix, params, paramDefs)
		if err != nil {
			return "", fmt.Errorf("failed to substitute variables: %w", err)
		}
		b.WriteString(substituted)
		b.WriteString("\n\n")
	}

	// Add DSA verification TEAL (same structure as falcon1024-v1)
	b.WriteString("// === Falcon-1024 Signature Verification ===\n")
	b.WriteString("txn TxID\n")
	b.WriteString("arg 0\n")
	b.WriteString(fmt.Sprintf("pushbytes 0x%s\n", hex.EncodeToString(publicKey)))
	b.WriteString("falcon_verify\n")

	return b.String(), nil
}

// DeriveLsig derives the LogicSig bytecode and address from a public key.
// Requires SetAlgodClient to be called first.
func (c *ComposedDSA) DeriveLsig(publicKey []byte, params map[string]string) ([]byte, string, error) {
	if c.algodClient == nil {
		return nil, "", fmt.Errorf("algod client not set: call SetAlgodClient before DeriveLsig")
	}

	if len(publicKey) != c.base.PublicKeySize() {
		return nil, "", fmt.Errorf("invalid public key size: expected %d, got %d",
			c.base.PublicKeySize(), len(publicKey))
	}

	// Generate TEAL source with @variable substitution
	teal, err := c.GenerateTEAL(publicKey, params)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate TEAL: %w", err)
	}

	// Compile via algod - the compiler validates the entire program
	result, err := c.algodClient.TealCompile([]byte(teal)).Do(context.Background())
	if err != nil {
		return nil, "", fmt.Errorf("TEAL compilation failed: %w", err)
	}

	bytecode, err := base64.StdEncoding.DecodeString(result.Result)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decode compiled bytecode: %w", err)
	}

	// Find counter byte offset and iterate to find non-ed25519 address
	counterOffset, err := findCounterOffset(bytecode)
	if err != nil {
		return nil, "", fmt.Errorf("failed to find counter offset: %w", err)
	}

	// Iterate counter 0-255 to find address not on ed25519 curve
	for counter := 0; counter <= 255; counter++ {
		bytecode[counterOffset] = byte(counter)
		addr, err := deriveAddress(bytecode)
		if err != nil {
			return nil, "", err
		}
		if !isOnTheCurve(addr[:]) {
			return bytecode, addr.String(), nil
		}
	}

	return nil, "", ErrNoSuitableCounter
}

// findCounterOffset finds the offset of the counter byte in compiled bytecode.
// The counter is in the bytecblock opcode: [0x26] [count=0x01] [len=0x01] [counter]
func findCounterOffset(bytecode []byte) (int, error) {
	for i := 0; i <= len(bytecode)-4; i++ {
		if bytecode[i] == counterPattern[0] &&
			bytecode[i+1] == counterPattern[1] &&
			bytecode[i+2] == counterPattern[2] {
			return i + 3, nil // counter is at offset +3 from pattern start
		}
	}
	return -1, fmt.Errorf("bytecblock counter pattern not found in bytecode")
}

// deriveAddress computes the LogicSig address from bytecode.
func deriveAddress(bytecode []byte) (types.Address, error) {
	lsig := crypto.LogicSigAccount{
		Lsig: types.LogicSig{Logic: bytecode},
	}
	return lsig.Address()
}

// isOnTheCurve returns true if the 32-byte value decodes to a valid edwards25519
// curve point (i.e., could be an ed25519 public key).
func isOnTheCurve(address []byte) bool {
	_, err := new(edwards25519.Point).SetBytes(address)
	return err == nil
}

// SeedFromMnemonic derives a seed from a mnemonic phrase.
func (c *ComposedDSA) SeedFromMnemonic(words []string, passphrase string) ([]byte, error) {
	return c.base.SeedFromMnemonic(words, passphrase)
}

// EntropyToMnemonic converts entropy bytes to mnemonic words.
func (c *ComposedDSA) EntropyToMnemonic(entropy []byte) ([]string, error) {
	return c.base.EntropyToMnemonic(entropy)
}

// Compile-time interface checks.
var (
	_ logicsigdsa.LogicSigDSA       = (*ComposedDSA)(nil)
	_ lsigprovider.LSigProvider     = (*ComposedDSA)(nil)
	_ lsigprovider.SigningProvider  = (*ComposedDSA)(nil)
	_ lsigprovider.MnemonicProvider = (*ComposedDSA)(nil)
)
