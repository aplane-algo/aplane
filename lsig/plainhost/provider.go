// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package plainhost makes a plain LogicSig key type a host for the account
// overlays. With a cosigner, and optionally a rekey-to list, the key type
// renders the plain1 contract over its own base: the spending key and the
// overlays, with no fee ceiling and no transaction-type list. With no parameters
// it is the plain program it always was: the composition base every bounded and
// composed account names, and the program of restored plain keys. That program
// is never created as an account (see Unavailable).
//
// It depends on no signature family, so each family wraps its own plain provider.
package plainhost

import (
	"context"
	"fmt"
	"maps"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"

	"github.com/aplane-algo/aplane/internal/boundary"
	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/internal/rekeylist"
	txsigning "github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
)

// The request vocabulary is the general bounded type's, so a cosigner and a
// rekey-to list are asked for the same way on both hosts.
const (
	ParameterCosigner       = boundary.ParameterCosigner
	ParameterRekeyAuthority = boundary.ParameterRekeyAuthority
	ParameterRekeyTo        = boundary.ParameterRekeyTo

	RekeyRefused      = boundary.RekeyRefused
	RekeySpendingKey  = boundary.RekeySpendingKey
	RekeyOnlyThese    = boundary.RekeyOnlyThese
	RekeyPlusCosigned = boundary.RekeyPlusCosigned

	// opcodeCost is every path's ceiling: two signature checks and, on a listed
	// rekey, the list proof, within one transaction's budget.
	opcodeCost = lsigresource.SingleTransactionOpcodeCeiling
)

// RekeyAuthorities is the plain host's grammar, in order: every arrangement is
// cosigned, with each rekey setting. A plain host's spends are unrestricted, so
// refusing rekeys traps nothing; a close still empties it, with the cosigner.
var RekeyAuthorities = []string{RekeyRefused, RekeySpendingKey, RekeyOnlyThese, RekeyPlusCosigned}

// Plain is the plain provider a host wraps. Its methods answer for the plain
// program; Provider overrides the ones that depend on the parameters.
type Plain interface {
	logicsigdsa.LogicSigDSA
	logicsigdsa.TEALGenerator
	logicsigdsa.SaltedDeriver
	lsigprovider.SigningProvider
	lsigprovider.AlgodConfigurable
	lsigprovider.OpcodeProfileProvider
}

// Base is what an overlay program composes over: the base key type's signature
// operations and its salt style. They must be the plain program's own, so a
// plain host and a plain key on the same spending key differ only by overlays.
type Base struct {
	Ops       composeddsa.DSAOps
	SaltStyle lsigsalt.Style
}

// arrangement is one rekey setting's composer and provenance.
type arrangement struct {
	rekey       string
	composer    *composeddsa.ComposedDSA
	fingerprint string
}

// Provider is a plain key type with the overlay arrangements. It holds no
// per-account state: each request selects one of the shared composers.
type Provider struct {
	Plain
	params            []lsigprovider.ParameterDef
	byRekey           map[string]*arrangement
	ordered           []*arrangement
	grammar           string
	cosignerComponent string
}

// Wrap builds a plain key type's overlay arrangements. It fails if any cannot be
// built, because the grammar must not offer an arrangement that errors on first
// use. Generation admission still decides per base at GenerateTEAL.
func Wrap(plain Plain, base Base) (*Provider, error) {
	if plain == nil || base.Ops == nil {
		return nil, fmt.Errorf("plain host needs a plain provider and its base operations")
	}
	provider := &Provider{Plain: plain, params: creationParameters(), byRekey: make(map[string]*arrangement)}
	for _, rekey := range RekeyAuthorities {
		composer, err := newComposer(plain, base, rekey)
		if err != nil {
			return nil, fmt.Errorf("plain host %s, %s=%s: %w", plain.KeyType(), ParameterRekeyAuthority, rekey, err)
		}
		built := &arrangement{rekey: rekey, composer: composer, fingerprint: arrangementFingerprint(rekey, composer)}
		provider.byRekey[rekey] = built
		provider.ordered = append(provider.ordered, built)
		provider.cosignerComponent = composer.BoundedAuthorizationMetadata().Cosigner.ComponentKeyType
	}
	provider.grammar = grammarFingerprint(plain.KeyType(), provider.ordered)
	return provider, nil
}

// MustWrap is Wrap for registration, where a plain host that can't be built is a
// programming error.
func MustWrap(plain Plain, base Base) *Provider {
	provider, err := Wrap(plain, base)
	if err != nil {
		panic(err)
	}
	return provider
}

func newComposer(plain Plain, base Base, rekey string) (*composeddsa.ComposedDSA, error) {
	setting := boundedmeta.RekeyRefused
	if rekey == RekeySpendingKey || rekey == RekeyPlusCosigned {
		setting = boundedmeta.RekeySpendingKey
	}
	profile := &composeddsa.BoundedAuthorizationProfile{
		Contract: composeddsa.PlainContract,
		Rekey:    setting,
		Cosigner: &boundedmeta.CosignerAuthorization{
			Contract:         boundedmeta.CosignerContractV1,
			ComponentKeyType: boundedmeta.CosignerComponentKeyTypeV1,
			SignatureMaxSize: boundedmeta.CosignerSignatureMaxSizeV1,
			RequiredOn:       boundedmeta.CosignerRequiredOn(setting),
		},
	}
	if rekey == RekeyOnlyThese || rekey == RekeyPlusCosigned {
		profile.RekeyList = &boundedmeta.RekeyList{Contract: boundedmeta.RekeyListContractV1, Depth: rekeylist.Depth}
	}
	composer := composeddsa.NewComposedDSA(composeddsa.Config{
		KeyType:       plain.KeyType(),
		BaseKeyType:   plain.KeyType(),
		FamilyName:    plain.RoutingFamily(),
		Version:       plain.Version(),
		DisplayName:   plain.DisplayName(),
		Description:   plain.Description(),
		Ops:           base.Ops,
		SaltStyle:     base.SaltStyle,
		OpcodeProfile: lsigresource.BoundedOpcodeProfile(opcodeCost, opcodeCost, opcodeCost),
		Bounded:       profile,
		Layer3:        &composeddsa.Layer3Policy{Policy: composeddsa.Layer3PolicyNone},
	})
	metadata := composer.BoundedAuthorizationMetadata()
	if metadata == nil || metadata.Cosigner == nil {
		return nil, fmt.Errorf("the overlay program has no valid contract")
	}
	return composer, nil
}

// creationParameters is the vocabulary. Every parameter is optional here, since
// no parameters select the plain program; an overlay request must give a
// cosigner and a rekey authority, which resolve checks.
func creationParameters() []lsigprovider.ParameterDef {
	cosigner := composeddsa.BoundedCosignerParameterDef()
	cosigner.Required = false
	return []lsigprovider.ParameterDef{
		{
			Name:        ParameterRekeyAuthority,
			Label:       "Rekey Authority",
			Description: "How the account can be rekeyed: never (refused); by the spending key and the cosigner together (spending_key); by the spending key alone, only to an address on its rekey-to list (only_these); or by the spending key alone to a listed address and with the cosigner to any other (plus_cosigned).",
			Type:        "string",
			Options:     []string{RekeyRefused, RekeySpendingKey, RekeyOnlyThese, RekeyPlusCosigned},
		},
		{
			Name:        ParameterRekeyTo,
			Label:       "Rekey-To Addresses",
			Description: "With only_these or plus_cosigned: the 1 to 16 addresses the spending key alone may rekey the account to. Each can take the account over.",
			Type:        "address[]",
			MaxItems:    rekeylist.MaxEntries,
		},
		cosigner,
	}
}

// hasOverlays reports whether a request asks for an overlay program. Any overlay
// parameter does, even an empty one, so a mistyped request is refused rather
// than taken as the plain program.
func hasOverlays(params map[string]string) bool {
	for _, name := range []string{ParameterCosigner, ParameterRekeyAuthority, ParameterRekeyTo,
		composeddsa.BoundedCosignerPublicKeyParameter, boundedmeta.RekeyListRootParameter} {
		if _, ok := params[name]; ok {
			return true
		}
	}
	return false
}

// resolve selects the arrangement and the canonical values for an overlay request.
func (p *Provider) resolve(params map[string]string) (*arrangement, map[string]string, error) {
	known := make(map[string]bool, len(p.params))
	for _, def := range p.params {
		known[def.Name] = true
	}
	for name := range params {
		if name == ParameterCosigner {
			return nil, nil, fmt.Errorf("cosigner reference was not resolved")
		}
		if !known[name] {
			return nil, nil, fmt.Errorf("unknown parameter %q", name)
		}
	}
	normalized, err := lsigprovider.NormalizeCreationParams(params, p.params)
	if err != nil {
		return nil, nil, err
	}
	rekey := normalized[ParameterRekeyAuthority]
	selected, ok := p.byRekey[rekey]
	if !ok {
		return nil, nil, fmt.Errorf("%s must be %s", ParameterRekeyAuthority, strings.Join(RekeyAuthorities, ", "))
	}
	cosigner := normalized[composeddsa.BoundedCosignerPublicKeyParameter]
	if cosigner == "" {
		return nil, nil, fmt.Errorf("a plain host needs a cosigner: give %s=<cosigner reference or Witness Key ID>", ParameterCosigner)
	}
	rekeyTo, err := canonicalRekeyTo(params, normalized, rekey)
	if err != nil {
		return nil, nil, err
	}
	values := map[string]string{
		ParameterRekeyAuthority:                       rekey,
		composeddsa.BoundedCosignerPublicKeyParameter: cosigner,
	}
	if rekeyTo != "" {
		values[ParameterRekeyTo] = rekeyTo
	}
	return selected, values, nil
}

// canonicalRekeyTo returns the rekey-to list in canonical order, or "" for an
// arrangement without one. only_these and plus_cosigned take a list, and must
// have one.
func canonicalRekeyTo(params, normalized map[string]string, rekey string) (string, error) {
	_, present := params[ParameterRekeyTo]
	if rekey != RekeyOnlyThese && rekey != RekeyPlusCosigned {
		if present {
			return "", fmt.Errorf("%s needs %s=%s or %s", ParameterRekeyTo, ParameterRekeyAuthority, RekeyOnlyThese, RekeyPlusCosigned)
		}
		return "", nil
	}
	if strings.TrimSpace(normalized[ParameterRekeyTo]) == "" {
		return "", fmt.Errorf("%s=%s needs the addresses the account may be rekeyed to in %s", ParameterRekeyAuthority, rekey, ParameterRekeyTo)
	}
	entries, err := composeddsa.RekeyListEntries(normalized)
	if err != nil {
		return "", err
	}
	addresses := make([]string, len(entries))
	for i, entry := range entries {
		addresses[i] = entry.String()
	}
	return strings.Join(addresses, ","), nil
}

// composerValues keeps only the parameters an arrangement's composer declares:
// the rekey authority selects the composer and isn't one of them.
func composerValues(selected *arrangement, values map[string]string) map[string]string {
	declared := make(map[string]string)
	for _, def := range selected.composer.CreationParams() {
		if value, ok := values[def.Name]; ok {
			declared[def.Name] = value
		}
	}
	return declared
}

// resolveGenerated resolves an overlay request and returns the composer's
// values, with the rekey-to list's root added when generation made one.
func (p *Provider) resolveGenerated(params map[string]string) (*arrangement, map[string]string, error) {
	request, generated := composeddsa.SplitGeneratedParams(params)
	selected, values, err := p.resolve(request)
	if err != nil {
		return nil, nil, err
	}
	composer := composerValues(selected, values)
	maps.Copy(composer, generated)
	return selected, composer, nil
}

// unavailable is why the plain program is not created as an account.
func (p *Provider) unavailable() string {
	return fmt.Sprintf("%s creates an account only with a cosigner: give %s=<cosigner reference or Witness Key ID> and %s=%s",
		p.KeyType(), ParameterCosigner, ParameterRekeyAuthority, strings.Join(RekeyAuthorities, "|"))
}

// BaseKeyType is the plain key type itself: an overlay program verifies the
// same spending key the plain program does.
func (p *Provider) BaseKeyType() string { return p.KeyType() }

// CreationParams returns the overlay vocabulary.
func (p *Provider) CreationParams() []lsigprovider.ParameterDef { return p.params }

// ValidateCreationParams checks an overlay request; no parameters is the plain
// program, which the plain provider validates.
func (p *Provider) ValidateCreationParams(params map[string]string) error {
	if !hasOverlays(params) {
		return p.Plain.ValidateCreationParams(params)
	}
	selected, values, err := p.resolve(params)
	if err != nil {
		return err
	}
	return selected.composer.ValidateCreationParams(composerValues(selected, values))
}

// CosignerComponentKeyType names the cosigner every overlay program needs, so
// a cosigner reference is resolved before an instance is selected.
func (p *Provider) CosignerComponentKeyType(params map[string]string) (string, bool) {
	if !hasOverlays(params) {
		return "", false
	}
	return p.cosignerComponent, true
}

// ResolveInstance selects the arrangement for resolved parameters. No parameters
// select the plain program, which no account is created as.
func (p *Provider) ResolveInstance(params map[string]string) (*lsigprovider.Instance, error) {
	if !hasOverlays(params) {
		values, err := lsigprovider.NormalizeCreationParams(params, nil)
		if err != nil {
			return nil, err
		}
		return &lsigprovider.Instance{Values: values, Unavailable: p.unavailable()}, nil
	}
	selected, values, err := p.resolve(params)
	if err != nil {
		return nil, err
	}
	composer := selected.composer
	composerParams := composerValues(selected, values)
	if err := composer.ValidateCreationParams(composerParams); err != nil {
		return nil, err
	}
	digest, err := boundaryDigest(selected, composerParams)
	if err != nil {
		return nil, err
	}
	return &lsigprovider.Instance{
		Parameters:        composer.CreationParams(),
		Values:            values,
		Bounded:           composer.BoundedAuthorizationMetadata(),
		Fingerprint:       selected.fingerprint,
		ReviewFingerprint: p.grammar,
		BoundaryDigest:    digest,
	}, nil
}

// StoredFingerprint returns the current fingerprint of a stored plain host's
// arrangement, read from its durable metadata alone.
func (p *Provider) StoredFingerprint(_ map[string]string, metadata *boundedmeta.Metadata) (string, error) {
	if metadata == nil || metadata.Contract != boundedmeta.PlainContract {
		return "", fmt.Errorf("stored account is not a plain host")
	}
	rekey := RekeyRefused
	switch {
	case metadata.Rekey == boundedmeta.RekeySpendingKey && metadata.RekeyList != nil:
		rekey = RekeyPlusCosigned
	case metadata.Rekey == boundedmeta.RekeySpendingKey:
		rekey = RekeySpendingKey
	case metadata.RekeyList != nil:
		rekey = RekeyOnlyThese
	}
	selected, ok := p.byRekey[rekey]
	if !ok {
		return "", fmt.Errorf("unsupported plain host arrangement %s", rekey)
	}
	return selected.fingerprint, nil
}

// GrammarFingerprint identifies the arrangements an operator approves.
func (p *Provider) GrammarFingerprint() string { return p.grammar }

// GenerateTEAL renders the selected program.
func (p *Provider) GenerateTEAL(publicKey []byte, params map[string]string) (string, error) {
	if !hasOverlays(params) {
		return p.Plain.GenerateTEAL(publicKey, params)
	}
	selected, values, err := p.resolveGenerated(params)
	if err != nil {
		return "", err
	}
	return selected.composer.GenerateTEAL(publicKey, values)
}

// DeriveLsig derives the selected program and its address.
func (p *Provider) DeriveLsig(ctx context.Context, publicKey []byte, params map[string]string) ([]byte, string, error) {
	if !hasOverlays(params) {
		return p.Plain.DeriveLsig(ctx, publicKey, params)
	}
	selected, values, err := p.resolveGenerated(params)
	if err != nil {
		return nil, "", err
	}
	return selected.composer.DeriveLsig(ctx, publicKey, values)
}

// DeriveLsigWithSalt derives the selected program with its salt metadata.
func (p *Provider) DeriveLsigWithSalt(ctx context.Context, publicKey []byte, params map[string]string) (lsigsalt.FindResult, error) {
	if !hasOverlays(params) {
		return p.Plain.DeriveLsigWithSalt(ctx, publicKey, params)
	}
	selected, values, err := p.resolveGenerated(params)
	if err != nil {
		return lsigsalt.FindResult{}, err
	}
	return selected.composer.DeriveLsigWithSalt(ctx, publicKey, values)
}

// PrepareRekeyList adds the rekey-to list's root once the spending key exists.
// Any other request is unchanged.
func (p *Provider) PrepareRekeyList(privateKey []byte, params map[string]string) (map[string]string, error) {
	if !hasOverlays(params) {
		return params, nil
	}
	selected, values, err := p.resolve(params)
	if err != nil {
		return nil, err
	}
	prepared, err := selected.composer.PrepareRekeyList(privateKey, composerValues(selected, values))
	if err != nil {
		return nil, err
	}
	root, ok := prepared[boundedmeta.RekeyListRootParameter]
	if !ok {
		return params, nil
	}
	out := maps.Clone(params)
	out[boundedmeta.RekeyListRootParameter] = root
	return out, nil
}

// BuildBoundedAuthorizationMetadata snapshots an overlay program's signing
// contract and refuses one the network could not run, before the key is
// persisted. The plain program has none.
func (p *Provider) BuildBoundedAuthorizationMetadata(publicKey []byte, params map[string]string, bytecode []byte) (*boundedmeta.Metadata, error) {
	if !hasOverlays(params) {
		return nil, nil
	}
	selected, values, err := p.resolveGenerated(params)
	if err != nil {
		return nil, err
	}
	metadata, err := selected.composer.BuildBoundedAuthorizationMetadata(publicKey, values, bytecode)
	if err != nil {
		return nil, err
	}
	if err := checkResources(metadata, p.BoundedLogicSigOpcodeProfile(), len(bytecode)); err != nil {
		return nil, err
	}
	return metadata, nil
}

// BoundedLogicSigOpcodeProfile is every overlay program's path ceilings.
func (p *Provider) BoundedLogicSigOpcodeProfile() lsigresource.OpcodeProfile {
	return lsigresource.BoundedOpcodeProfile(opcodeCost, opcodeCost, opcodeCost)
}

// SetAlgodClient configures TEAL compilation for the plain program and every
// arrangement.
func (p *Provider) SetAlgodClient(client *algod.Client) {
	p.Plain.SetAlgodClient(client)
	for _, selected := range p.ordered {
		selected.composer.SetAlgodClient(client)
	}
}

// checkResources is a generation backstop: each path the arrangement has must
// fit one transaction's resources. A plain host has no fee ceiling to check.
// Signing still checks the selected path against the actual network rules.
func checkResources(metadata *boundedmeta.Metadata, opcodes lsigresource.OpcodeProfile, programBytes int) error {
	consensus, err := lsigresource.CurrentConsensus()
	if err != nil {
		return fmt.Errorf("read consensus profile: %w", err)
	}
	type path struct {
		name   string
		opcode uint64
	}
	paths := []path{{boundedmeta.PathSpend, opcodes.Spend}}
	if metadata.Rekey == boundedmeta.RekeySpendingKey {
		paths = append(paths, path{boundedmeta.PathSpendingRekey, opcodes.SpendingRekey})
	}
	if metadata.RekeyList != nil {
		paths = append(paths, path{boundedmeta.PathListedRekey, opcodes.ListedRekey})
	}
	for _, path := range paths {
		if _, err := lsigresource.Solve(consensus, lsigresource.PlanInput{
			TransactionCount: 1,
			LogicSigs: []lsigresource.Usage{{
				ProgramBytes:  uint64(programBytes),
				ArgumentBytes: uint64(metadata.ArgumentBytesForPath(path.name)),
				MaxOpcodeCost: path.opcode,
			}},
			Dummy: lsigresource.Usage{ProgramBytes: uint64(len(txsigning.EmbeddedDummyTealTok)), MaxOpcodeCost: 1},
		}); err != nil {
			return fmt.Errorf("%s path does not fit the network's resource limits: %w", path.name, err)
		}
	}
	return nil
}

// Compile-time interface checks.
var (
	_ logicsigdsa.LogicSigDSA                   = (*Provider)(nil)
	_ logicsigdsa.SaltedDeriver                 = (*Provider)(nil)
	_ logicsigdsa.TEALGenerator                 = (*Provider)(nil)
	_ lsigprovider.SigningProvider              = (*Provider)(nil)
	_ lsigprovider.AlgodConfigurable            = (*Provider)(nil)
	_ lsigprovider.InstanceResolver             = (*Provider)(nil)
	_ lsigprovider.OpcodeProfileProvider        = (*Provider)(nil)
	_ lsigprovider.BoundedOpcodeProfileProvider = (*Provider)(nil)
)
