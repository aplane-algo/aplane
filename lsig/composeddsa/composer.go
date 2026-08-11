// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package composeddsa provides a generic runtime-compiled LogicSig composer
// for DSA-based schemes (Falcon, ECDSA, etc.).
package composeddsa

import (
	"context"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/internal/tealtemplate"
	"github.com/aplane-algo/aplane/lsig/generictemplate"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
)

// ErrNoSuitableCounter is returned when no counter value 0-255 produces
// a LogicSig address that is not on the ed25519 curve.
var ErrNoSuitableCounter = lsigsalt.ErrNoSuitableCounter

var returnTokenPattern = regexp.MustCompile(`\breturn\b`)

// DSAOps defines client-safe algorithm-specific operations needed by the generic composer.
//
// The composer handles program structure, variable substitution, runtime
// compilation, and address derivation. DSAOps provides the algorithm-specific
// metadata, verification TEAL footer, and signature argument packing.
type DSAOps interface {
	// Metadata
	PublicKeySize() int
	CryptoSignatureSize() int
	MnemonicScheme() string
	MnemonicWordCount() int
	DisplayColor() string

	// TEAL construction for signature verification.
	BuildVerifyTEAL(publicKey []byte) (string, error)
	TEALVersion() int

	// Signature argument packing for LogicSig.Args.
	// Falcon uses one arg [sig], ECDSA can split into [r, s], etc.
	BuildSignatureArgs(signature []byte) ([][]byte, error)
}

// SignatureArgLayout describes the static LogicSig argument shape emitted by a
// DSA base. Bounded-capable bases must expose this without probing dummy
// signatures. It aliases the durable boundedmeta shape so the generation-side
// and stored layouts are the same type.
type SignatureArgLayout = boundedmeta.SignatureArgLayout

// BoundedCapableDSAOps is implemented by DSA bases whose signature argument
// layout is static and therefore safe to compose with bounded routing.
type BoundedCapableDSAOps interface {
	DSAOps
	SignatureArgLayout() SignatureArgLayout
}

// Config holds configuration for creating a ComposedDSA.
type Config struct {
	// Identity
	KeyType     string // e.g., "aplane.falcon1024-timelock.v1"
	BaseKeyType string // e.g., "aplane.falcon1024.v1"
	FamilyName  string // qualified registry family, e.g. "aplane.falcon1024"
	Version     int
	DisplayName string
	Description string

	// Components
	Ops          DSAOps
	TEALSuffix   string // Raw TEAL with @variable refs
	SaltStyle    lsigsalt.Style
	TemplateMode string // legacy, generated, or strict; empty means legacy
	TemplateVars []tealtemplate.TemplateVariable
	Params       []lsigprovider.ParameterDef  // Creation-time parameters
	RuntimeArgs  []lsigprovider.RuntimeArgDef // Signing-time arguments
	// BoundedRuntimeArgs and DerivedArgs carry schema-v2-only slot metadata.
	BoundedRuntimeArgs []boundedmeta.RuntimeArg
	DerivedArgs        []boundedmeta.DerivedArg
	Bounded            *BoundedAuthorizationProfile
	Layer3             *Layer3Policy
}

// ComposedDSA composes:
//  1. Standard LogicSig structure (preamble + optional suffix + verify footer)
//  2. Runtime TEAL compilation via algod
//  3. Algorithm-specific verify operations via DSAOps
type ComposedDSA struct {
	// Identity
	keyType     string
	baseKeyType string
	// familyName is the qualified registry family ("publisher.family"). For a
	// composed template it is the base DSA's family; for a self-generating DSA
	// it is the provider's own family.
	familyName  string
	version     int
	displayName string
	description string

	// Components
	ops                DSAOps
	tealSuffix         string
	saltStyle          lsigsalt.Style
	templateMode       string
	templateVars       []tealtemplate.TemplateVariable
	params             []lsigprovider.ParameterDef
	runtimeArgs        []lsigprovider.RuntimeArgDef
	boundedRuntimeArgs []boundedmeta.RuntimeArg
	derivedArgs        []boundedmeta.DerivedArg
	bounded            *BoundedAuthorizationProfile
	layer3             *Layer3Policy

	// Algod client for TEAL compilation (must be set before DeriveLsig)
	algodClient *algod.Client
	algodMu     sync.RWMutex
}

// NewComposedDSA creates a generic composed DSA provider.
// Panics if cfg.Ops is nil.
func NewComposedDSA(cfg Config) *ComposedDSA {
	if cfg.Ops == nil {
		panic("composeddsa: Config.Ops is required")
	}
	params := append([]lsigprovider.ParameterDef(nil), cfg.Params...)
	bounded := cloneBoundedProfile(cfg.Bounded)
	if boundedRequiresAdminKey(bounded) && !hasParameter(params, BoundedAdminPublicKeyParameter) {
		params = append(params, boundedAdminPublicKeyParameterDef())
	}
	if bounded != nil && bounded.Sentry != nil && !hasParameter(params, BoundedSentryPublicKeyParameter) {
		params = append(params, boundedSentryPublicKeyParameterDef())
	}
	return &ComposedDSA{
		keyType:            cfg.KeyType,
		baseKeyType:        cfg.BaseKeyType,
		familyName:         cfg.FamilyName,
		version:            cfg.Version,
		displayName:        cfg.DisplayName,
		description:        cfg.Description,
		ops:                cfg.Ops,
		tealSuffix:         cfg.TEALSuffix,
		saltStyle:          cfg.SaltStyle,
		templateMode:       cfg.TemplateMode,
		templateVars:       cfg.TemplateVars,
		params:             params,
		runtimeArgs:        cfg.RuntimeArgs,
		boundedRuntimeArgs: append([]boundedmeta.RuntimeArg(nil), cfg.BoundedRuntimeArgs...),
		derivedArgs:        append([]boundedmeta.DerivedArg(nil), cfg.DerivedArgs...),
		bounded:            bounded,
		layer3:             cloneLayer3Policy(cfg.Layer3),
	}
}

// SetAlgodClient sets the algod client used for TEAL compilation.
// This must be called before DeriveLsig.
func (c *ComposedDSA) SetAlgodClient(client *algod.Client) {
	c.algodMu.Lock()
	defer c.algodMu.Unlock()
	c.algodClient = client
}

// KeyType returns the full identifier including version.
func (c *ComposedDSA) KeyType() string {
	return c.keyType
}

// BaseKeyType returns the underlying DSA key type used for key generation and
// signature packing. It is empty for older wrappers that did not provide one.
func (c *ComposedDSA) BaseKeyType() string {
	return c.baseKeyType
}

// RoutingFamily returns the qualified registry family ("publisher.family"). For a
// composed template this is the base DSA's family (set from the base
// registration), so keygen/signing/metadata lookups via RoutingFamily route to the
// base provider's ops. For a DSA that owns its key generation, it is that
// provider's own qualified family.
func (c *ComposedDSA) RoutingFamily() string {
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
	return c.ops.DisplayColor()
}

// CryptoSignatureSize returns the maximum signature size in bytes.
func (c *ComposedDSA) CryptoSignatureSize() int {
	return c.ops.CryptoSignatureSize()
}

// MnemonicScheme returns the mnemonic scheme.
func (c *ComposedDSA) MnemonicScheme() string {
	return c.ops.MnemonicScheme()
}

// MnemonicWordCount returns the expected number of mnemonic words.
func (c *ComposedDSA) MnemonicWordCount() int {
	return c.ops.MnemonicWordCount()
}

func (c *ComposedDSA) SupportsMnemonicImport() bool {
	return false
}

// CreationParams returns the parameter definitions for this provider.
func (c *ComposedDSA) CreationParams() []lsigprovider.ParameterDef {
	return c.params
}

// ValidateCreationParams validates parameters against the stored definitions.
func (c *ComposedDSA) ValidateCreationParams(params map[string]string) error {
	normalized, err := lsigprovider.NormalizeCreationParams(params, c.params)
	if err != nil {
		return err
	}
	return generictemplate.ValidateParameterValues(normalized, c.params)
}

// RuntimeArgs returns all runtime argument definitions.
func (c *ComposedDSA) RuntimeArgs() []lsigprovider.RuntimeArgDef {
	return c.runtimeArgs
}

// BoundedAuthorizationProfile returns a defensive copy of this
// provider's bounded profile, or nil for legacy composed providers.
func (c *ComposedDSA) BoundedAuthorizationProfile() *BoundedAuthorizationProfile {
	return cloneBoundedProfile(c.bounded)
}

// Layer3PolicyName identifies whether the provider uses framework-owned or
// contained custom Layer-3 policy.
func (c *ComposedDSA) Layer3PolicyName() string {
	return layer3PolicyName(c.layer3)
}

// SignatureArgLayout returns the static base signature layout when the base
// advertises bounded capability.
func (c *ComposedDSA) SignatureArgLayout() (SignatureArgLayout, bool) {
	ops, ok := c.ops.(BoundedCapableDSAOps)
	if !ok {
		return SignatureArgLayout{}, false
	}
	return cloneSignatureArgLayout(ops.SignatureArgLayout()), true
}

// BuildArgs assembles LogicSig Args in the provider's declared order.
func (c *ComposedDSA) BuildArgs(signature []byte, runtimeArgs map[string][]byte) ([][]byte, error) {
	if signature == nil {
		return nil, fmt.Errorf("signature is required for DSA LogicSig")
	}

	sigArgs, err := c.ops.BuildSignatureArgs(signature)
	if err != nil {
		return nil, err
	}
	if len(sigArgs) == 0 {
		return nil, fmt.Errorf("algorithm returned no signature arguments")
	}
	if c.bounded != nil {
		layout, err := c.validatedSignatureArgLayout()
		if err != nil {
			return nil, err
		}
		if err := validateBuiltSignatureArgs(sigArgs, layout); err != nil {
			return nil, err
		}
	}

	runtimeArgBytes, err := lsigprovider.ValidateAndOrderArgs(c.runtimeArgs, runtimeArgs)
	if err != nil {
		return nil, err
	}
	if c.bounded != nil {
		return c.buildBoundedSpendArgs(sigArgs, runtimeArgBytes)
	}

	ordered := make([][]byte, 0, len(sigArgs)+len(runtimeArgBytes))
	ordered = append(ordered, sigArgs...)
	ordered = append(ordered, runtimeArgBytes...)
	return ordered, nil
}

func (c *ComposedDSA) buildBoundedSpendArgs(signatureArgs, runtimeArgs [][]byte) ([][]byte, error) {
	metadata, err := c.boundedAuthorizationMetadataBase()
	if err != nil {
		return nil, err
	}
	if metadata == nil {
		return nil, fmt.Errorf("bounded argument assembly requires bounded metadata")
	}

	args := make([][]byte, len(metadata.ArgumentLayout))
	baseIndex, runtimeIndex := 0, 0
	for _, slot := range metadata.ArgumentLayout {
		if slot.Index < 0 || slot.Index >= len(args) {
			return nil, fmt.Errorf("bounded argument slot %q has invalid index %d", slot.Name, slot.Index)
		}
		value := []byte{}
		switch slot.Source {
		case boundedmeta.ArgSourceBaseSignature:
			if baseIndex >= len(signatureArgs) {
				return nil, fmt.Errorf("bounded base signature slot %q has no value", slot.Name)
			}
			value = signatureArgs[baseIndex]
			baseIndex++
		case boundedmeta.ArgSourceDerived, boundedmeta.ArgSourceSentry, boundedmeta.ArgSourceAdmin:
			// BuildArgs has no transaction context or external admin authority.
			// Keep interior slots explicit so later runtime values retain their
			// frozen indexes; unused trailing slots are trimmed below.
		case boundedmeta.ArgSourceRuntime:
			if runtimeIndex >= len(runtimeArgs) {
				return nil, fmt.Errorf("bounded runtime slot %q has no value", slot.Name)
			}
			value = runtimeArgs[runtimeIndex]
			runtimeIndex++
		default:
			return nil, fmt.Errorf("bounded argument slot %q has unsupported source %q", slot.Name, slot.Source)
		}

		switch slot.Paths.Spend {
		case boundedmeta.ArgRequired:
			if len(value) == 0 {
				return nil, fmt.Errorf("required bounded spend argument slot %q is empty", slot.Name)
			}
		case boundedmeta.ArgOptional:
		case boundedmeta.ArgForbidden:
			if len(value) != 0 {
				return nil, fmt.Errorf("forbidden bounded spend argument slot %q is populated", slot.Name)
			}
		default:
			return nil, fmt.Errorf("bounded argument slot %q has invalid spend rule %q", slot.Name, slot.Paths.Spend)
		}
		if len(value) > slot.MaxSize {
			return nil, fmt.Errorf("bounded argument slot %q exceeds maximum size %d", slot.Name, slot.MaxSize)
		}
		args[slot.Index] = value
	}
	if baseIndex != len(signatureArgs) || runtimeIndex != len(runtimeArgs) {
		return nil, fmt.Errorf("bounded argument layout did not consume all provider arguments")
	}
	for len(args) > 0 && len(args[len(args)-1]) == 0 {
		args = args[:len(args)-1]
	}
	return args, nil
}

// CompatibilityFingerprint returns a stable semantic fingerprint for the
// behavior-bearing parts of this composed provider definition.
// CompatibilityFingerprint returns a stable, behavior-only compatibility
// fingerprint for this composed provider definition. It hashes only
// behavior-bearing fields: identity/display strings (key_type, family, version)
// are excluded, and the renameable base_key_type is projected to a stable
// base_primitive token so the fingerprint survives a pure base rename. It is
// provenance only and is never read on the signing path.
func (c *ComposedDSA) CompatibilityFingerprint() string {
	type canonicalSpec struct {
		BasePrimitive string                             `json:"base_primitive,omitempty"`
		TEALSuffix    string                             `json:"teal_suffix"`
		SaltStyle     string                             `json:"salt_style"`
		TemplateMode  string                             `json:"template_mode,omitempty"`
		TemplateVars  []tealtemplate.TemplateVariable    `json:"template_variables,omitempty"`
		Parameters    []lsigprovider.CanonicalParameter  `json:"parameters,omitempty"`
		RuntimeArgs   []lsigprovider.CanonicalRuntimeArg `json:"runtime_args,omitempty"`
		Bounded       any                                `json:"bounded,omitempty"`
		Layer3        *Layer3Policy                      `json:"layer3,omitempty"`
	}

	params := make([]lsigprovider.CanonicalParameter, len(c.params))
	for i, p := range c.params {
		params[i] = lsigprovider.ProjectParameterDef(p)
	}

	runtimeArgs := make([]lsigprovider.CanonicalRuntimeArg, len(c.runtimeArgs))
	for i, a := range c.runtimeArgs {
		runtimeArgs[i] = lsigprovider.ProjectRuntimeArgDef(a)
	}

	metadata, metadataErr := c.boundedAuthorizationMetadataBase()
	boundedProjection := boundedFingerprintProjection(c.bounded, metadata)
	if metadataErr != nil {
		boundedProjection = map[string]string{"invalid": metadataErr.Error()}
	}
	return lsigprovider.HashCompatibilitySpec(canonicalSpec{
		BasePrimitive: lsigprovider.FingerprintBasePrimitive(c.baseKeyType),
		TEALSuffix:    strings.TrimSpace(c.tealSuffix),
		SaltStyle:     c.fingerprintSaltStyle(),
		TemplateMode:  c.effectiveTemplateMode(),
		TemplateVars:  c.templateVars,
		Parameters:    params,
		RuntimeArgs:   runtimeArgs,
		Bounded:       boundedProjection,
		Layer3:        cloneLayer3Policy(c.layer3),
	})
}

// GenerateTEAL generates the complete TEAL source for this composed LogicSig.
//
// Empty-suffix programs preserve the canonical bare-DSA layout:
// preamble + algorithm-specific verify footer.
//
// Non-empty suffixes use verifier-first composition:
// preamble + verify footer + assert + substituted suffix + final return.
// The suffix is a predicate fragment, not a standalone TEAL program, and must
// not contain its own return instructions.
func (c *ComposedDSA) GenerateTEAL(publicKey []byte, params map[string]string) (string, error) {
	normalizedParams, err := lsigprovider.NormalizeCreationParams(params, c.params)
	if err != nil {
		return "", err
	}
	if err := generictemplate.ValidateParameterValues(normalizedParams, c.params); err != nil {
		return "", err
	}
	boundedProfile, _, err := c.validateBoundedConfig()
	if err != nil {
		return "", err
	}

	if len(publicKey) != c.ops.PublicKeySize() {
		return "", fmt.Errorf("invalid public key size: expected %d, got %d",
			c.ops.PublicKeySize(), len(publicKey))
	}

	version := c.ops.TEALVersion()
	if version <= 0 {
		return "", fmt.Errorf("invalid TEAL version: %d", version)
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("#pragma version %d\n\n", version))

	mode := c.effectiveTemplateMode()
	hasSuffix := c.hasSuffix()
	style, err := c.resolvedSaltStyle()
	if err != nil {
		return "", err
	}
	var strictSuffix tealtemplate.RenderedTemplate
	if strings.TrimSpace(c.tealSuffix) != "" {
		if err := validateSuffixControlFlow(c.tealSuffix); err != nil {
			return "", err
		}
		switch mode {
		case generictemplate.TemplateModeStrict:
			strictSuffix, err = tealtemplate.RenderStrictFragment(c.tealSuffix, normalizedParams, c.templateVars)
			if err != nil {
				return "", fmt.Errorf("failed to render strict template suffix: %w", err)
			}
			if strictSuffix.ConstantBlocks != "" {
				b.WriteString("// Template constants\n")
				b.WriteString(strictSuffix.ConstantBlocks)
				b.WriteString("\n\n")
			}
		case generictemplate.TemplateModeLegacy, generictemplate.TemplateModeGenerated:
		default:
			return "", fmt.Errorf("unsupported template_mode %q", c.templateMode)
		}
	}

	if style != lsigsalt.StyleNone && style != lsigsalt.StyleAlgodAutoSalt && style != lsigsalt.StyleTrailingBytecblock {
		preamble, err := c.saltPreamble(style)
		if err != nil {
			return "", err
		}
		b.WriteString(preamble)
	}

	verifyFooter, err := c.ops.BuildVerifyTEAL(publicKey)
	if err != nil {
		return "", err
	}
	b.WriteString(verifyFooter)
	if !strings.HasSuffix(verifyFooter, "\n") {
		b.WriteString("\n")
	}

	if boundedProfile == nil && !hasSuffix {
		return c.finishSaltedTEAL(b.String(), style)
	}

	b.WriteString("assert\n\n")
	if boundedProfile != nil {
		prelude, err := c.renderBoundedPrelude(publicKey, normalizedParams, boundedProfile)
		if err != nil {
			return "", fmt.Errorf("failed to render bounded1 envelope: %w", err)
		}
		b.WriteString(prelude)
	}

	if c.layer3 != nil {
		layer3, err := c.renderLayer3Policy(normalizedParams, boundedProfile)
		if err != nil {
			return "", fmt.Errorf("failed to render Layer-3 policy: %w", err)
		}
		b.WriteString(layer3)
		b.WriteString("\n")
	} else {
		switch mode {
		case generictemplate.TemplateModeStrict:
			b.WriteString(strictSuffix.TEAL)
			b.WriteString("\n\n")
		case generictemplate.TemplateModeLegacy, generictemplate.TemplateModeGenerated:
			// Optional user-supplied suffix with @variable substitution.
			paramDefs := make([]tealtemplate.ParamDef, len(c.params))
			for i, p := range c.params {
				paramDefs[i] = tealtemplate.ParamDef{Name: p.Name, Type: composedTemplateParamType(p.Type)}
			}

			expanded, err := tealtemplate.ExpandLists(c.tealSuffix, normalizedParams, paramDefs)
			if err != nil {
				return "", fmt.Errorf("failed to expand list templates: %w", err)
			}

			substituted, err := tealtemplate.SubstituteVariables(expanded, normalizedParams, paramDefs)
			if err != nil {
				return "", fmt.Errorf("failed to substitute variables: %w", err)
			}
			b.WriteString(substituted)
			b.WriteString("\n\n")
		default:
			return "", fmt.Errorf("unsupported template_mode %q", c.templateMode)
		}
	}

	if boundedProfile != nil {
		b.WriteString(renderBoundedAccept())
	} else {
		b.WriteString("int 1\nreturn\n")
	}

	return c.finishSaltedTEAL(b.String(), style)
}

func (c *ComposedDSA) saltPreamble(style lsigsalt.Style) (string, error) {
	preamble, err := style.SourcePreamble()
	if err != nil {
		return "", err
	}
	return "// Counter byte (varied 0-255 to avoid ed25519 curve addresses)\n" + preamble + "\n", nil
}

func (c *ComposedDSA) finishSaltedTEAL(teal string, style lsigsalt.Style) (string, error) {
	trailer, err := style.SourceTrailer()
	if err != nil {
		return "", err
	}
	if trailer == "" {
		return teal, nil
	}
	return strings.TrimRight(teal, "\n") +
		"\n\n// Counter byte (varied 0-255 to avoid ed25519 curve addresses)\n" +
		strings.TrimSuffix(trailer, "\n") + "\n", nil
}

func (c *ComposedDSA) saltLocator() (lsigsalt.Locator, error) {
	style, err := c.resolvedSaltStyle()
	if err != nil {
		return nil, err
	}
	if style == lsigsalt.StyleNone || style == lsigsalt.StyleAlgodAutoSalt {
		return nil, fmt.Errorf("LogicSig salt style %q has no salt locator", style)
	}
	return style.Locator()
}

func (c *ComposedDSA) hasSuffix() bool {
	return strings.TrimSpace(c.tealSuffix) != "" || c.layer3 != nil
}

func (c *ComposedDSA) resolvedSaltStyle() (lsigsalt.Style, error) {
	if c.saltStyle != "" {
		if c.saltStyle == lsigsalt.StyleAlgodAutoSalt {
			if c.ops.TEALVersion() < 13 {
				return "", fmt.Errorf("composed DSA salt style %q requires TEAL v13+, got v%d", c.saltStyle, c.ops.TEALVersion())
			}
			return c.saltStyle, nil
		}
		if c.saltStyle == lsigsalt.StyleNone {
			return c.saltStyle, nil
		}
		if c.saltStyle == lsigsalt.StyleBytecblock && c.hasSuffix() {
			return "", fmt.Errorf("composed DSA salt style %q cannot be used with a TEAL suffix; use %q", c.saltStyle, lsigsalt.StylePushbytes)
		}
		if c.saltStyle == lsigsalt.StyleTrailingBytecblock && !c.hasSuffix() {
			return "", fmt.Errorf("composed DSA salt style %q requires a TEAL suffix with a composer-owned final return", c.saltStyle)
		}
		if _, err := c.saltStyle.Locator(); err != nil {
			return "", err
		}
		return c.saltStyle, nil
	}
	if c.hasSuffix() {
		return lsigsalt.StylePushbytes, nil
	}
	return lsigsalt.StyleBytecblock, nil
}

func (c *ComposedDSA) fingerprintSaltStyle() string {
	style, err := c.resolvedSaltStyle()
	if err != nil {
		return string(c.saltStyle)
	}
	return string(style)
}

func (c *ComposedDSA) effectiveTemplateMode() string {
	if c.templateMode != "" {
		return c.templateMode
	}
	return generictemplate.TemplateModeLegacy
}

func validateSuffixControlFlow(teal string) error {
	for _, line := range strings.Split(teal, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") {
			continue
		}
		if idx := strings.Index(trimmed, "//"); idx >= 0 {
			trimmed = strings.TrimSpace(trimmed[:idx])
		}
		if returnTokenPattern.MatchString(trimmed) {
			return fmt.Errorf("composed DSA TEAL suffix must not contain return; use assert/branching and fall through to composer return")
		}
	}
	return nil
}

func composedTemplateParamType(paramType string) string {
	switch paramType {
	case "address":
		return "address_bytes"
	case "address[]":
		return "address_bytes[]"
	default:
		return paramType
	}
}

// DeriveLsig derives LogicSig bytecode and address from public key and params.
// Requires SetAlgodClient to be called first.
func (c *ComposedDSA) DeriveLsig(ctx context.Context, publicKey []byte, params map[string]string) ([]byte, string, error) {
	result, err := c.DeriveLsigWithSalt(ctx, publicKey, params)
	if err != nil {
		return nil, "", err
	}
	return result.Bytecode, result.Address.String(), nil
}

// DeriveLsigWithSalt derives LogicSig bytecode, address, and salt metadata
// from public key and params. Requires SetAlgodClient to be called first.
func (c *ComposedDSA) DeriveLsigWithSalt(ctx context.Context, publicKey []byte, params map[string]string) (lsigsalt.FindResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	c.algodMu.RLock()
	client := c.algodClient
	c.algodMu.RUnlock()
	if client == nil {
		return lsigsalt.FindResult{}, fmt.Errorf("algod client not set: call SetAlgodClient before DeriveLsig")
	}

	teal, err := c.GenerateTEAL(publicKey, params)
	if err != nil {
		return lsigsalt.FindResult{}, fmt.Errorf("failed to generate TEAL: %w", err)
	}

	result, err := client.TealCompile([]byte(teal)).Do(ctx)
	if err != nil {
		return lsigsalt.FindResult{}, fmt.Errorf("TEAL compilation failed: %w", err)
	}

	bytecode, err := base64.StdEncoding.DecodeString(result.Result)
	if err != nil {
		return lsigsalt.FindResult{}, fmt.Errorf("failed to decode compiled bytecode: %w", err)
	}

	style, err := c.resolvedSaltStyle()
	if err != nil {
		return lsigsalt.FindResult{}, err
	}
	if style == lsigsalt.StyleAlgodAutoSalt {
		autoSalted, err := lsigsalt.UseCompilerAutoSalted(bytecode, result.Hash)
		if err != nil {
			return lsigsalt.FindResult{}, fmt.Errorf("failed to validate compiler-auto-salted LogicSig: %w", err)
		}
		return autoSalted, nil
	}
	if style == lsigsalt.StyleNone {
		unsalted, err := lsigsalt.UseUnmodifiedOffCurve(bytecode)
		if err != nil {
			return lsigsalt.FindResult{}, fmt.Errorf("failed to validate unsalted off-curve LogicSig address: %w", err)
		}
		return unsalted, nil
	}
	locate, err := c.saltLocator()
	if err != nil {
		return lsigsalt.FindResult{}, err
	}
	salted, err := lsigsalt.FindOffCurve(bytecode, locate)
	if err != nil {
		return lsigsalt.FindResult{}, fmt.Errorf("failed to derive off-curve LogicSig address: %w", err)
	}
	return salted, nil
}

// Compile-time interface checks.
var (
	_ logicsigdsa.LogicSigDSA        = (*ComposedDSA)(nil)
	_ logicsigdsa.SaltedDeriver      = (*ComposedDSA)(nil)
	_ lsigprovider.LSigProvider      = (*ComposedDSA)(nil)
	_ lsigprovider.SigningProvider   = (*ComposedDSA)(nil)
	_ lsigprovider.MnemonicProvider  = (*ComposedDSA)(nil)
	_ lsigprovider.AlgodConfigurable = (*ComposedDSA)(nil)
)
