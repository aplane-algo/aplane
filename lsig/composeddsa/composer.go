// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package composeddsa provides a generic runtime-compiled LogicSig composer
// for DSA-based schemes.
package composeddsa

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/aplane-algo/aplane/internal/hostmeta"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/internal/sigconstruction"
	"github.com/aplane-algo/aplane/internal/tealtemplate"
	"github.com/aplane-algo/aplane/lsig/generictemplate"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
)

var returnTokenPattern = regexp.MustCompile(`\breturn\b`)

// DSAOps defines client-safe algorithm-specific operations needed by the generic composer.
//
// The composer handles program structure, variable substitution, runtime
// compilation, and address derivation. DSAOps provides the algorithm-specific
// metadata, verification TEAL footer, and signature argument packing.
//
// Construction names the signature construction the ops render. Bounded key
// separation reads its components, so a witness key reused as one component is
// refused, and a base registered under a catalog name must render that name's
// construction (see RegisterBase). Ops with no catalog construction, such as test
// stubs under a non-catalog base name, return the zero Construction.
type DSAOps interface {
	Construction() sigconstruction.Construction

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
	// A primitive's signature can span several args, so callers must not assume one.
	BuildSignatureArgs(signature []byte) ([][]byte, error)
}

// SignatureArgLayout describes the static LogicSig argument shape emitted by a
// DSA base. Bounded-capable bases must expose this without probing dummy
// signatures. It aliases the durable hostmeta shape so the generation-side
// and stored layouts are the same type.
type SignatureArgLayout = hostmeta.SignatureArgLayout

// HostCapableDSAOps is implemented by DSA bases whose signature argument
// layout is static and therefore safe to compose with bounded routing.
type HostCapableDSAOps interface {
	DSAOps
	SignatureArgLayout() SignatureArgLayout
}

// Config holds configuration for creating a ComposedDSA.
type Config struct {
	// Identity
	KeyType     string // e.g., "example.falcon1024-timelock.v1"
	BaseKeyType string // e.g., "aplane.falcon1024.v1"
	FamilyName  string // qualified registry family, e.g. "aplane.falcon1024"
	Version     int
	DisplayName string
	Description string

	// Components
	Ops          DSAOps
	TEALSuffix   string // Raw TEAL with @variable refs
	SaltStyle    lsigsalt.Style
	TemplateMode string // generated or strict; required with a TEAL suffix
	TemplateVars []tealtemplate.TemplateVariable
	Params       []lsigprovider.ParameterDef // Creation-time parameters
	// RuntimeArgs are the signing-time arguments. A bounded composer records
	// them in its metadata as given, so a bounded composer's arguments must
	// come from a validated template spec (newProviderFromBase), whose bounded
	// runtime_args have passed the bounded argument checks. A Config built by
	// hand with Host and RuntimeArgs skips those checks.
	RuntimeArgs []lsigprovider.RuntimeArgDef
	// DerivedArgs carries schema-v2-only slot metadata.
	DerivedArgs   []hostmeta.DerivedArg
	Host          *HostProfile
	Layer3        *Layer3Policy
	OpcodeProfile lsigresource.OpcodeProfile
	// RekeyTargetDeclaration is an installed template's valid_rekey_target,
	// part of its definition and its fingerprint. A compiled key type, a plain
	// host's programs included, leaves it nil: it declares the attribute in
	// its catalog entry alone.
	RekeyTargetDeclaration *bool
}

// ComposedDSA composes:
//  1. Standard LogicSig structure (pragma + verify footer + optional suffix)
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
	ops          DSAOps
	tealSuffix   string
	saltStyle    lsigsalt.Style
	templateMode string
	templateVars []tealtemplate.TemplateVariable
	params       []lsigprovider.ParameterDef
	runtimeArgs  []lsigprovider.RuntimeArgDef
	// hostRuntimeArgs is runtimeArgs as a bounded account records them,
	// for a bounded composer.
	hostRuntimeArgs []hostmeta.RuntimeArg
	derivedArgs     []hostmeta.DerivedArg
	host            *HostProfile
	layer3          *Layer3Policy
	opcodeProfile   lsigresource.OpcodeProfile
	// rekeyTargetDeclaration is Config.RekeyTargetDeclaration.
	rekeyTargetDeclaration *bool

	// generationPolicy replaces the production support policy for this composer
	// only. It stays nil outside tests: nothing but export_test.go sets it.
	generationPolicy hostGenerationPolicy

	// Algod client for TEAL compilation (must be set before DeriveLsig)
	algodClient *algod.Client
	algodMu     sync.RWMutex
}

// NewComposedDSA creates a generic composed DSA provider.
// Panics if cfg.Ops is nil. A TEALSuffix needs a TemplateMode; GenerateTEAL
// refuses one without it.
func NewComposedDSA(cfg Config) *ComposedDSA {
	if cfg.Ops == nil {
		panic("composeddsa: Config.Ops is required")
	}
	params := append([]lsigprovider.ParameterDef(nil), cfg.Params...)
	host := cloneHostProfile(cfg.Host)
	opcodeProfile := cfg.OpcodeProfile
	if opcodeProfile != (lsigresource.OpcodeProfile{}) {
		if err := opcodeProfile.Validate(host != nil); err != nil {
			panic("composeddsa: invalid opcode profile: " + err.Error())
		}
	}
	if host != nil && host.Cosigner != nil && !hasParameter(params, CosignerPublicKeyParameter) {
		params = append(params, CosignerParameterDef(host.Cosigner.ComponentKeyType))
	}
	if host != nil && host.RekeyList != nil && !hasParameter(params, RekeyToParameter) {
		params = append(params, rekeyListEntriesParameterDef(host.Rekey))
	}
	var hostRuntimeArgs []hostmeta.RuntimeArg
	if host != nil {
		for _, arg := range cfg.RuntimeArgs {
			hostRuntimeArgs = append(hostRuntimeArgs, hostmeta.RuntimeArg{
				Name: arg.Name, Label: arg.Label, Description: arg.Description, Type: arg.Type,
				Required: arg.Required, ByteLength: arg.ByteLength, MaxSize: arg.MaxSize,
			})
		}
	}
	return &ComposedDSA{
		keyType:                cfg.KeyType,
		baseKeyType:            cfg.BaseKeyType,
		familyName:             cfg.FamilyName,
		version:                cfg.Version,
		displayName:            cfg.DisplayName,
		description:            cfg.Description,
		ops:                    cfg.Ops,
		tealSuffix:             cfg.TEALSuffix,
		saltStyle:              cfg.SaltStyle,
		templateMode:           cfg.TemplateMode,
		templateVars:           cfg.TemplateVars,
		params:                 params,
		runtimeArgs:            cfg.RuntimeArgs,
		hostRuntimeArgs:        hostRuntimeArgs,
		derivedArgs:            append([]hostmeta.DerivedArg(nil), cfg.DerivedArgs...),
		host:                   host,
		layer3:                 cloneLayer3Policy(cfg.Layer3),
		opcodeProfile:          opcodeProfile,
		rekeyTargetDeclaration: cloneBool(cfg.RekeyTargetDeclaration),
	}
}

func cloneBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
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

// LogicSigOpcodeProfile returns the provider-owned reviewed resource contract.
func (c *ComposedDSA) LogicSigOpcodeProfile() lsigresource.OpcodeProfile {
	return c.opcodeProfile
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

// HostProfile returns a defensive copy of this
// provider's bounded profile, or nil for legacy composed providers.
func (c *ComposedDSA) HostProfile() *HostProfile {
	return cloneHostProfile(c.host)
}

// Layer3PolicyName identifies whether the provider uses framework-owned or
// contained custom Layer-3 policy.
func (c *ComposedDSA) Layer3PolicyName() string {
	return layer3PolicyName(c.layer3, c.hasAuthorTEAL())
}

// SignatureArgLayout returns the static base signature layout when the base
// advertises bounded capability.
func (c *ComposedDSA) SignatureArgLayout() (SignatureArgLayout, bool) {
	ops, ok := c.ops.(HostCapableDSAOps)
	if !ok {
		return SignatureArgLayout{}, false
	}
	return cloneSignatureArgLayout(ops.SignatureArgLayout()), true
}

// errHostBuildArgs refuses BuildArgs on a bounded composer. The signer
// packs a bounded account's spending signature through its base key type's
// provider and places every argument by the account's stored layout.
var errHostBuildArgs = errors.New("bounded accounts are assembled from their stored metadata")

// BuildArgs assembles LogicSig Args in the provider's declared order. A bounded
// composer refuses (errHostBuildArgs).
func (c *ComposedDSA) BuildArgs(signature []byte, runtimeArgs map[string][]byte) ([][]byte, error) {
	if c.host != nil {
		return nil, errHostBuildArgs
	}
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

	runtimeArgBytes, err := lsigprovider.ValidateAndOrderArgs(c.runtimeArgs, runtimeArgs)
	if err != nil {
		return nil, err
	}

	ordered := make([][]byte, 0, len(sigArgs)+len(runtimeArgBytes))
	ordered = append(ordered, sigArgs...)
	ordered = append(ordered, runtimeArgBytes...)
	return ordered, nil
}

// CompatibilityFingerprint returns a stable compatibility fingerprint for this
// composed provider definition. It hashes the behavior-bearing fields and a
// template's valid_rekey_target declaration: identity/display strings
// (key_type, family, version) are excluded, and the renameable base_key_type
// is projected to a stable base_primitive token so the fingerprint survives a
// pure base rename. It is provenance only and is never read on the signing
// path.
func (c *ComposedDSA) CompatibilityFingerprint() string {
	type canonicalSpec struct {
		BasePrimitive string                             `json:"base_primitive,omitempty"`
		OpcodeProfile lsigresource.OpcodeProfile         `json:"opcode_profile"`
		TEALSuffix    string                             `json:"teal_suffix"`
		SaltStyle     string                             `json:"salt_style"`
		TemplateMode  string                             `json:"template_mode,omitempty"`
		TemplateVars  []tealtemplate.TemplateVariable    `json:"template_variables,omitempty"`
		Parameters    []lsigprovider.CanonicalParameter  `json:"parameters,omitempty"`
		RuntimeArgs   []lsigprovider.CanonicalRuntimeArg `json:"runtime_args,omitempty"`
		Host          any                                `json:"bounded,omitempty"`
		Layer3        *Layer3Policy                      `json:"layer3,omitempty"`
		// ValidRekeyTarget is a template's declaration, part of its
		// definition: a template that declares another value is another
		// definition. A compiled key type has none here; its catalog entry
		// declares it.
		ValidRekeyTarget *bool `json:"valid_rekey_target,omitempty"`
	}

	params := make([]lsigprovider.CanonicalParameter, len(c.params))
	for i, p := range c.params {
		params[i] = lsigprovider.ProjectParameterDef(p)
	}

	runtimeArgs := make([]lsigprovider.CanonicalRuntimeArg, len(c.runtimeArgs))
	for i, a := range c.runtimeArgs {
		runtimeArgs[i] = lsigprovider.ProjectRuntimeArgDef(a)
	}

	metadata, metadataErr := c.hostMetadataBase()
	hostProjection := hostFingerprintProjection(c.host, metadata)
	if metadataErr != nil {
		hostProjection = map[string]string{"invalid": metadataErr.Error()}
	}
	return lsigprovider.HashCompatibilitySpec(canonicalSpec{
		BasePrimitive:    lsigprovider.FingerprintBasePrimitive(c.baseKeyType),
		OpcodeProfile:    c.opcodeProfile,
		TEALSuffix:       strings.TrimSpace(c.tealSuffix),
		SaltStyle:        string(c.saltStyle),
		TemplateMode:     c.templateMode,
		TemplateVars:     c.templateVars,
		Parameters:       params,
		RuntimeArgs:      runtimeArgs,
		Host:             hostProjection,
		Layer3:           cloneLayer3Policy(c.layer3),
		ValidRekeyTarget: c.rekeyTargetDeclaration,
	})
}

// GenerateTEAL generates the complete TEAL source for this composed LogicSig.
//
// Empty-suffix programs preserve the canonical bare-DSA layout:
// pragma + algorithm-specific verify footer.
//
// Non-empty suffixes use verifier-first composition:
// pragma + verify footer + assert + substituted suffix + final return.
// The suffix is a predicate fragment, not a standalone TEAL program, and must
// not contain its own return instructions.
func (c *ComposedDSA) GenerateTEAL(publicKey []byte, params map[string]string) (string, error) {
	if err := c.checkHostGenerationSupport(); err != nil {
		return "", err
	}
	// The rekey-to list's root is the generator's, not a creation parameter.
	params, generated := SplitGeneratedParams(params)
	normalizedParams, err := lsigprovider.NormalizeCreationParams(params, c.params)
	if err != nil {
		return "", err
	}
	if err := generictemplate.ValidateParameterValues(normalizedParams, c.params); err != nil {
		return "", err
	}
	hostProfile, _, err := c.validateHostConfig()
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

	// Author TEAL never sees a rekey-to list's entries, which only its root may
	// reveal; validateHostReservedNames refuses a reference with a reason.
	authorParams, authorDefs := normalizedParams, c.params
	if hostProfile != nil && hostProfile.RekeyList != nil {
		authorParams = maps.Clone(normalizedParams)
		delete(authorParams, RekeyToParameter)
		authorDefs = slices.DeleteFunc(slices.Clone(c.params), func(p lsigprovider.ParameterDef) bool {
			return p.Name == RekeyToParameter
		})
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("#pragma version %d\n\n", version))

	mode := c.templateMode
	hasSuffix := c.hasSuffix()
	if err := c.checkSaltStyle(); err != nil {
		return "", err
	}
	var strictSuffix tealtemplate.RenderedTemplate
	if c.hasAuthorTEAL() {
		if err := validateSuffixControlFlow(c.tealSuffix); err != nil {
			return "", err
		}
		switch mode {
		case generictemplate.TemplateModeStrict:
			strictSuffix, err = tealtemplate.RenderStrictFragment(c.tealSuffix, authorParams, c.templateVars)
			if err != nil {
				return "", fmt.Errorf("failed to render strict template suffix: %w", err)
			}
			if strictSuffix.ConstantBlocks != "" {
				b.WriteString("// Template constants\n")
				b.WriteString(strictSuffix.ConstantBlocks)
				b.WriteString("\n\n")
			}
		case generictemplate.TemplateModeGenerated:
		case "":
			return "", fmt.Errorf("template_mode is required with a TEAL suffix (generated or strict)")
		default:
			return "", fmt.Errorf("unsupported template_mode %q", c.templateMode)
		}
	}

	verifyFooter, err := c.ops.BuildVerifyTEAL(publicKey)
	if err != nil {
		return "", err
	}
	b.WriteString(verifyFooter)
	if !strings.HasSuffix(verifyFooter, "\n") {
		b.WriteString("\n")
	}

	if hostProfile == nil && !hasSuffix {
		return b.String(), nil
	}

	b.WriteString("assert\n\n")
	if hostProfile != nil {
		preludeParams := normalizedParams
		if generated != nil {
			preludeParams = maps.Clone(normalizedParams)
			maps.Copy(preludeParams, generated)
		}
		prelude, err := c.renderHostPrelude(publicKey, preludeParams, hostProfile)
		if err != nil {
			return "", fmt.Errorf("failed to render bounded envelope: %w", err)
		}
		b.WriteString(prelude)
	}

	if c.layer3 != nil {
		layer3, err := c.renderLayer3Policy(normalizedParams, hostProfile)
		if err != nil {
			return "", fmt.Errorf("failed to render Layer-3 policy: %w", err)
		}
		b.WriteString(layer3)
		b.WriteString("\n")
	}
	// A framework allowlist is emitted first and falls through, so author TEAL
	// can only narrow what it admits and nothing the author writes can skip it.
	// Author TEAL is always present here: a composer with no framework policy
	// has some (validateHostConfig, or the early return above), so the
	// suffix switch has already refused a missing or unknown mode.
	if c.layer3 == nil || c.hasAuthorTEAL() {
		switch mode {
		case generictemplate.TemplateModeStrict:
			b.WriteString(strictSuffix.TEAL)
			b.WriteString("\n\n")
		case generictemplate.TemplateModeGenerated:
			// User-supplied suffix with @variable substitution.
			paramDefs := make([]tealtemplate.ParamDef, len(authorDefs))
			for i, p := range authorDefs {
				paramDefs[i] = tealtemplate.ParamDef{Name: p.Name, Type: composedTemplateParamType(p.Type)}
			}

			expanded, err := tealtemplate.ExpandLists(c.tealSuffix, authorParams, paramDefs)
			if err != nil {
				return "", fmt.Errorf("failed to expand list templates: %w", err)
			}

			substituted, err := tealtemplate.SubstituteVariables(expanded, authorParams, paramDefs)
			if err != nil {
				return "", fmt.Errorf("failed to substitute variables: %w", err)
			}
			b.WriteString(substituted)
			b.WriteString("\n\n")
		default:
			// Deliberately layered: the suffix switch above has already refused
			// this mode. Should that ever stop holding, refusing here keeps a
			// program from being emitted without the author's narrowing TEAL.
			return "", fmt.Errorf("unsupported template_mode %q", c.templateMode)
		}
	}

	if hostProfile != nil {
		b.WriteString(renderHostAccept())
	} else {
		b.WriteString("int 1\nreturn\n")
	}

	return b.String(), nil
}

func (c *ComposedDSA) hasSuffix() bool {
	return c.hasAuthorTEAL() || c.layer3 != nil
}

// hasAuthorTEAL reports whether the template supplied TEAL of its own.
// hasSuffix is also true for a framework policy, which has none.
func (c *ComposedDSA) hasAuthorTEAL() bool {
	return strings.TrimSpace(c.tealSuffix) != ""
}

// checkSaltStyle refuses a salt style the composer cannot derive with. Algod's
// TEAL v13 assembler salts an auto-salt program; an unsalted one is used as
// compiled, so its address must already be off the curve.
func (c *ComposedDSA) checkSaltStyle() error {
	switch c.saltStyle {
	case lsigsalt.StyleNone:
		return nil
	case lsigsalt.StyleAlgodAutoSalt:
		if c.ops.TEALVersion() < 13 {
			return fmt.Errorf("composed DSA salt style %q requires TEAL v13+, got v%d", c.saltStyle, c.ops.TEALVersion())
		}
		return nil
	default:
		return fmt.Errorf("composed DSA salt style %q is not %q or %q", c.saltStyle, lsigsalt.StyleNone, lsigsalt.StyleAlgodAutoSalt)
	}
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

	// GenerateTEAL has refused any other salt style.
	if c.saltStyle == lsigsalt.StyleAlgodAutoSalt {
		autoSalted, err := lsigsalt.UseCompilerAutoSalted(bytecode, result.Hash)
		if err != nil {
			return lsigsalt.FindResult{}, fmt.Errorf("failed to validate compiler-auto-salted LogicSig: %w", err)
		}
		return autoSalted, nil
	}
	unsalted, err := lsigsalt.UseUnmodifiedOffCurve(bytecode)
	if err != nil {
		return lsigsalt.FindResult{}, fmt.Errorf("failed to validate unsalted off-curve LogicSig address: %w", err)
	}
	return unsalted, nil
}

// Compile-time interface checks.
var (
	_ logicsigdsa.LogicSigDSA        = (*ComposedDSA)(nil)
	_ logicsigdsa.SaltedDeriver      = (*ComposedDSA)(nil)
	_ lsigprovider.LSigProvider      = (*ComposedDSA)(nil)
	_ lsigprovider.SigningProvider   = (*ComposedDSA)(nil)
	_ lsigprovider.AlgodConfigurable = (*ComposedDSA)(nil)
)
