// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package plainhost makes a plain LogicSig key type a host for the account
// overlays and the bounds. With a rekey setting, and optionally a cosigner and a
// rekey-to list, the key type renders the plain1 contract over its own base: the
// spending key and the overlays, with no fee ceiling and no transaction-type
// list. With bounds as well (transfer kinds, and a recipient list or limits
// only), it renders a bounded2 shape over the same base. With no
// parameters it is the plain program it always was: the composition base every
// composed account names, an account of its own, and the program of restored
// plain keys.
//
// Every arrangement and shape is offered; which one suits an account is the
// user's choice. It depends on no signature family, so each family wraps its own
// plain provider.
package plainhost

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"

	"github.com/aplane-algo/aplane/internal/boundary"
	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/keytypecatalog"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/internal/rekeylist"
	txsigning "github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
)

// The request vocabulary is the boundary file grammar's, so a file and a form
// ask for the same account.
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

// RekeyAuthorities is every rekey setting a plain host takes, in order.
var RekeyAuthorities = []string{RekeyRefused, RekeySpendingKey, RekeyOnlyThese, RekeyPlusCosigned}

// Arrangement is one overlay arrangement: a rekey setting, with or without a
// cosigner. Plus cosigned always has one: without it the spending key alone
// rekeys anywhere, which is spending_key.
type Arrangement struct {
	Rekey    string
	Cosigner bool
}

// HasRekeyList reports whether the arrangement takes a rekey-to list.
func (a Arrangement) HasRekeyList() bool {
	return a.Rekey == RekeyOnlyThese || a.Rekey == RekeyPlusCosigned
}

// Arrangements is the plain host's grammar, in order: each rekey setting
// without and then with a cosigner.
func Arrangements() []Arrangement {
	var arrangements []Arrangement
	for _, rekey := range RekeyAuthorities {
		if rekey != RekeyPlusCosigned {
			arrangements = append(arrangements, Arrangement{Rekey: rekey})
		}
		arrangements = append(arrangements, Arrangement{Rekey: rekey, Cosigner: true})
	}
	return arrangements
}

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

// Base is what an overlay or bounded program composes over: the base key type's
// signature operations and its salt style. They must be the plain program's own,
// so an account and a plain key on the same spending key differ only by
// overlays and bounds.
type Base struct {
	Ops       composeddsa.DSAOps
	SaltStyle lsigsalt.Style
}

// program is one selectable composer, a plain1 arrangement or a bounded2 shape,
// with its provenance.
type program struct {
	descriptor  string
	composer    *composeddsa.ComposedDSA
	fingerprint string
}

// Provider is a plain key type with the overlay arrangements and the bounded
// shapes. It holds no per-account state: each request selects one of the shared
// composers.
type Provider struct {
	Plain
	base              Base
	params            []lsigprovider.ParameterDef
	byArrangement     map[Arrangement]*program
	arrangements      []*program
	cosignerComponent string

	// The bounded shapes, and the grammar fingerprint that covers them, are
	// built once, on first use: there are hundreds, and a process that never
	// selects or reviews one, such as a client, shouldn't pay for them at start.
	shapesOnce sync.Once
	shapesErr  error
	byShape    map[string]*program
	ordered    []*program
	grammar    string

	algodMu sync.Mutex
	algod   *algod.Client

	// custom holds shapes compiled with a fee ceiling other than the default,
	// built when a request or a stored account first names one.
	customMu sync.Mutex
	custom   map[customShape]*program
}

// customShape names a shape compiled with its own fee ceiling.
type customShape struct {
	descriptor string
	maxFee     uint64
}

// customShapesMax bounds the cache of custom-ceiling programs. They are rebuilt
// on demand, so dropping one loses nothing.
const customShapesMax = 1024

// Wrap builds a plain key type's arrangements, and the shapes on first use. A
// program that can't be built fails its first use; the tests build every shape
// of every production base, so none ships. Generation admission still decides
// per base at GenerateTEAL.
func Wrap(plain Plain, base Base) (*Provider, error) {
	if plain == nil || base.Ops == nil {
		return nil, fmt.Errorf("plain host needs a plain provider and its base operations")
	}
	provider := &Provider{
		Plain:         plain,
		base:          base,
		params:        creationParameters(),
		byArrangement: make(map[Arrangement]*program),
	}
	for _, selected := range Arrangements() {
		composer, err := newComposer(plain, base, selected)
		if err != nil {
			return nil, fmt.Errorf("plain host %s, %s: %w", plain.KeyType(), descriptor(selected), err)
		}
		built := &program{descriptor: descriptor(selected), composer: composer, fingerprint: arrangementFingerprint(selected, composer)}
		provider.byArrangement[selected] = built
		provider.arrangements = append(provider.arrangements, built)
		if selected.Cosigner {
			provider.cosignerComponent = composer.BoundedAuthorizationMetadata().Cosigner.ComponentKeyType
		}
	}
	return provider, nil
}

// loadShapes builds every bounded shape and the grammar fingerprint, once.
func (p *Provider) loadShapes() error {
	p.shapesOnce.Do(func() {
		byShape := make(map[string]*program)
		ordered := append([]*program(nil), p.arrangements...)
		for _, shape := range Shapes() {
			composer, err := newShapeComposer(p.Plain, p.base, shape, DefaultMaxFee)
			if err != nil {
				p.shapesErr = fmt.Errorf("plain host %s, shape %s: %w", p.KeyType(), shape.Descriptor(), err)
				return
			}
			built := &program{descriptor: shape.Descriptor(), composer: composer, fingerprint: shapeFingerprint(shape, composer)}
			byShape[shape.Descriptor()] = built
			ordered = append(ordered, built)
		}
		p.algodMu.Lock()
		defer p.algodMu.Unlock()
		if p.algod != nil {
			for _, built := range byShape {
				built.composer.SetAlgodClient(p.algod)
			}
		}
		p.byShape, p.ordered = byShape, ordered
		p.grammar = grammarFingerprint(p.KeyType(), ordered)
	})
	return p.shapesErr
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

func newComposer(plain Plain, base Base, selected Arrangement) (*composeddsa.ComposedDSA, error) {
	rekey := selected.Rekey
	setting := arrangementSetting(rekey)
	profile := &composeddsa.BoundedAuthorizationProfile{
		Contract: composeddsa.PlainContract,
		Rekey:    setting,
	}
	if selected.Cosigner {
		profile.Cosigner = &boundedmeta.CosignerAuthorization{
			Contract:         boundedmeta.CosignerContractV1,
			ComponentKeyType: boundedmeta.CosignerComponentKeyTypeV1,
			SignatureMaxSize: boundedmeta.CosignerSignatureMaxSizeV1,
			RequiredOn:       boundedmeta.CosignerRequiredOn(setting),
		}
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
	if metadata == nil || (metadata.Cosigner != nil) != selected.Cosigner {
		return nil, fmt.Errorf("the overlay program has no valid contract")
	}
	return composer, nil
}

// creationParameters is the vocabulary: the bounds, then the overlays. Every
// parameter is optional here, since no parameters select the plain program; a
// request with overlays or bounds must give a rekey authority, and one with
// bounds the transfer kinds, which resolve checks.
func creationParameters() []lsigprovider.ParameterDef {
	cosigner := composeddsa.BoundedCosignerParameterDef()
	cosigner.Required = false
	return []lsigprovider.ParameterDef{
		{
			Name:        ParameterSpendEffects,
			Label:       "Transfer Kinds",
			Description: "Bounds: comma-separated transfer kinds the account may make: pay, axfer, asset_opt_in. Any bounds parameter makes the account a bounded one, with a fee limit per transaction.",
			Type:        "string",
			Example:     "pay,axfer,asset_opt_in",
		},
		{
			Name:        ParameterRecipients,
			Label:       "Allowed Recipients",
			Description: "Bounds: addresses that may receive payments or asset transfers. Absent with recipient scope any.",
			Type:        "address[]",
			MaxItems:    RecipientsMax,
		},
		{
			Name:        ParameterRecipientScope,
			Label:       "Recipient Scope",
			Description: "Bounds: listed (default) limits transfers to the recipient list; any keeps only the fee limit and transfer kinds.",
			Type:        "string",
			Options:     []string{RecipientScopeListed, RecipientScopeAny},
		},
		{
			Name:        ParameterListEncoding,
			Label:       "List Encoding",
			Description: "Bounds: how the program holds the recipient list. Auto chooses inline through 10 recipients and Merkle above that.",
			Type:        "string",
			Options:     []string{EncodingAuto, EncodingInline, EncodingMerkle},
		},
		{
			Name:        ParameterMaxFee,
			Label:       "Fee Limit",
			Description: "Bounds: the most the account may pay in fees on one transaction, in microAlgos. Absent means 10,000. Below what one of its transactions costs alone, it needs a group that shares the cost or another account to pay.",
			Type:        "uint64",
			Example:     "10000",
		},
		{
			Name:        ParameterCosigner,
			Label:       "Cosigner",
			Description: "A cosigner reference name or Witness Key ID, which the signer resolves to its public key. Leave empty for no cosigner.",
			Type:        "string",
		},
		{
			Name:        ParameterRekeyAuthority,
			Label:       "Rekey Authority",
			Description: "How the account can be rekeyed: never (refused); by the spending key, with the cosigner too on a cosigned account (spending_key); by the spending key alone, only to an address on its rekey-to list (only_these); or by the spending key alone to a listed address and with the cosigner to any other (plus_cosigned).",
			Type:        "string",
			Options:     slices.Clone(RekeyAuthorities),
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

// present refuses a parameter given with an empty value. A request that names a
// parameter but gives no value is ambiguous, and reading it as absent can create a
// weaker account than asked for: an empty transfer list would drop the bounds,
// an empty cosigner the cosigner. Leave a
// parameter out to leave it unset; apadmin's form sends only what was chosen.
func present(params map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(params))
	for name, value := range params {
		if strings.TrimSpace(value) == "" {
			return nil, fmt.Errorf("%s is empty; leave it out to leave it unset", name)
		}
		out[name] = value
	}
	return out, nil
}

// hasContract reports whether a request asks for a program other than the plain
// one, a plain1 or bounded2 contract: any overlay or bounds parameter with a
// value does.
func hasContract(params map[string]string) bool {
	for _, name := range []string{ParameterCosigner, ParameterRekeyAuthority, ParameterRekeyTo,
		composeddsa.BoundedCosignerPublicKeyParameter, boundedmeta.RekeyListRootParameter} {
		if _, ok := params[name]; ok {
			return true
		}
	}
	return hasBounds(params)
}

// checkPlainProgram refuses any parameter on a request for the plain program, so
// a misspelled parameter is an error rather than a weaker account.
func checkPlainProgram(params map[string]string) error {
	for name := range params {
		return fmt.Errorf("unknown parameter %q", name)
	}
	return nil
}

// plainRequest reports whether a request is for the plain program. Every entry
// point applies the same rule as validation: a request naming only parameters
// no program reads is refused, so a caller that derives without validating
// first can't get a weaker account than it asked for.
func plainRequest(params map[string]string) (bool, error) {
	request, err := present(params)
	if err != nil {
		return false, err
	}
	if hasContract(request) {
		return false, nil
	}
	return true, checkPlainProgram(request)
}

// resolve selects the program and the canonical values for a request, given
// without its empty parameters: a bounded2 shape when it has bounds, otherwise a
// plain1 arrangement.
func (p *Provider) resolve(params map[string]string) (*program, map[string]string, error) {
	if hasBounds(params) {
		selected, err := selectShape(params, p.params)
		if err != nil {
			return nil, nil, err
		}
		shape, err := p.shapeProgram(selected.shape, selected.maxFee)
		if err != nil {
			return nil, nil, err
		}
		return shape, selected.values, nil
	}
	if err := checkKnown(params, p.params); err != nil {
		return nil, nil, err
	}
	normalized, err := lsigprovider.NormalizeCreationParams(params, p.params)
	if err != nil {
		return nil, nil, err
	}
	overlays, err := resolveOverlays(params, normalized)
	if err != nil {
		return nil, nil, err
	}
	selected, ok := p.byArrangement[overlays.arrangement]
	if !ok {
		return nil, nil, fmt.Errorf("unsupported plain host arrangement %s", descriptor(overlays.arrangement))
	}
	values := map[string]string{}
	overlays.addTo(values)
	return selected, values, nil
}

// shapeProgram returns a shape's program at a fee ceiling. The grammar's own
// programs carry the default; any other ceiling is the same shape compiled with
// that value, with its own fingerprint.
func (p *Provider) shapeProgram(shape Shape, maxFee uint64) (*program, error) {
	if err := p.loadShapes(); err != nil {
		return nil, err
	}
	standard, ok := p.byShape[shape.Descriptor()]
	if !ok {
		return nil, fmt.Errorf("unsupported bounded shape %s", shape.Descriptor())
	}
	if maxFee == DefaultMaxFee {
		return standard, nil
	}
	key := customShape{shape.Descriptor(), maxFee}
	p.customMu.Lock()
	built, ok := p.custom[key]
	p.customMu.Unlock()
	if ok {
		return built, nil
	}
	// Built outside the lock, so one request's build never holds up another's.
	// Two requests may build the same program; the first stored is kept.
	composer, err := newShapeComposer(p.Plain, p.base, shape, maxFee)
	if err != nil {
		return nil, fmt.Errorf("plain host %s, shape %s, %s %d: %w", p.KeyType(), shape.Descriptor(), ParameterMaxFee, maxFee, err)
	}
	built = &program{descriptor: shape.Descriptor(), composer: composer, fingerprint: shapeFingerprint(shape, composer)}
	// Both locks, in SetAlgodClient's order, so a client set meanwhile reaches
	// either this program here or the stored one there.
	p.algodMu.Lock()
	defer p.algodMu.Unlock()
	p.customMu.Lock()
	defer p.customMu.Unlock()
	if kept, ok := p.custom[key]; ok {
		return kept, nil
	}
	if p.algod != nil {
		composer.SetAlgodClient(p.algod)
	}
	if p.custom == nil {
		p.custom = make(map[customShape]*program)
	}
	// Full: drop one entry, any one, so a store with more ceilings than the
	// cache holds rebuilds a few programs per pass, not all of them.
	if len(p.custom) >= customShapesMax {
		for stale := range p.custom {
			delete(p.custom, stale)
			break
		}
	}
	p.custom[key] = built
	return built, nil
}

// composerValues keeps only the parameters a program's composer declares: the
// selectors (rekey authority, transfer kinds, list encoding, scope) choose the
// composer and aren't its parameters.
func composerValues(selected *program, values map[string]string) map[string]string {
	declared := make(map[string]string)
	for _, def := range selected.composer.CreationParams() {
		if value, ok := values[def.Name]; ok {
			declared[def.Name] = value
		}
	}
	return declared
}

// resolveGenerated resolves a request and returns the composer's values, with
// the rekey-to list's root added when generation made one. The root is not a
// creation parameter, so the program is resolved without it.
func (p *Provider) resolveGenerated(params map[string]string) (*program, map[string]string, error) {
	params, err := present(params)
	if err != nil {
		return nil, nil, err
	}
	request, generated := composeddsa.SplitGeneratedParams(params)
	selected, values, err := p.resolve(request)
	if err != nil {
		return nil, nil, err
	}
	composer := composerValues(selected, values)
	maps.Copy(composer, generated)
	return selected, composer, nil
}

// BaseKeyType is the plain key type itself: every program verifies the same
// spending key the plain program does.
func (p *Provider) BaseKeyType() string { return p.KeyType() }

// BoundarySchema names the boundary file grammar this type's requests take.
func (p *Provider) BoundarySchema() string { return boundary.SchemaV1 }

// ValidRekeyTarget is the plain host's valid_rekey_target
// (lsigprovider.RekeyTargetDeclarer): its catalog entry, the one place a
// compiled key type declares it, which its arrangement and shape programs
// answer too.
func (p *Provider) ValidRekeyTarget() bool {
	entry, ok := keytypecatalog.Get(p.KeyType())
	return ok && entry.ValidRekeyTarget
}

// CreationParams returns the vocabulary.
func (p *Provider) CreationParams() []lsigprovider.ParameterDef { return p.params }

// ValidateCreationParams checks a request; no parameters is the plain program,
// which the plain provider validates.
func (p *Provider) ValidateCreationParams(params map[string]string) error {
	params, err := present(params)
	if err != nil {
		return err
	}
	if !hasContract(params) {
		if err := checkPlainProgram(params); err != nil {
			return err
		}
		return p.Plain.ValidateCreationParams(params)
	}
	selected, values, err := p.resolve(params)
	if err != nil {
		return err
	}
	return selected.composer.ValidateCreationParams(composerValues(selected, values))
}

// CosignerComponentKeyType names the cosigner a request asks for, so a cosigner
// reference is resolved before an instance is selected. A cosigner is optional,
// so a request naming none returns false.
func (p *Provider) CosignerComponentKeyType(params map[string]string) (string, bool) {
	_, hasName := params[ParameterCosigner]
	_, hasKey := params[composeddsa.BoundedCosignerPublicKeyParameter]
	if !hasName && !hasKey {
		return "", false
	}
	return p.cosignerComponent, true
}

// ResolveInstance selects the program for resolved parameters. No parameters
// select the plain program, which has no contract.
func (p *Provider) ResolveInstance(params map[string]string) (*lsigprovider.Instance, error) {
	params, err := present(params)
	if err != nil {
		return nil, err
	}
	if !hasContract(params) {
		if err := checkPlainProgram(params); err != nil {
			return nil, err
		}
		return &lsigprovider.Instance{Values: map[string]string{}}, nil
	}
	selected, values, err := p.resolve(params)
	if err != nil {
		return nil, err
	}
	// The review fingerprint is the whole grammar's.
	if err := p.loadShapes(); err != nil {
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

// StoredFingerprint returns the current fingerprint of a stored account's
// program, read from its durable metadata alone.
func (p *Provider) StoredFingerprint(_ map[string]string, metadata *boundedmeta.Metadata) (string, error) {
	if metadata == nil {
		return "", fmt.Errorf("stored account has no overlay contract")
	}
	switch metadata.Contract {
	case boundedmeta.PlainContract:
		stored := Arrangement{Rekey: storedRekey(metadata), Cosigner: metadata.Cosigner != nil}
		selected, ok := p.byArrangement[stored]
		if !ok {
			return "", fmt.Errorf("unsupported plain host arrangement %s", descriptor(stored))
		}
		return selected.fingerprint, nil
	case boundedmeta.Contract:
		shape, err := shapeFromMetadata(metadata)
		if err != nil {
			return "", err
		}
		if metadata.MaxFee == nil {
			return "", fmt.Errorf("stored account has no fee ceiling")
		}
		selected, err := p.shapeProgram(shape, *metadata.MaxFee)
		if err != nil {
			return "", err
		}
		return selected.fingerprint, nil
	default:
		return "", fmt.Errorf("stored account has contract %q", metadata.Contract)
	}
}

// storedRekey is a stored account's rekey option: only these is refused plus the
// list, plus cosigned a spending-key rekey plus the list.
func storedRekey(metadata *boundedmeta.Metadata) string {
	switch {
	case metadata.Rekey == boundedmeta.RekeySpendingKey && metadata.RekeyList != nil:
		return RekeyPlusCosigned
	case metadata.Rekey == boundedmeta.RekeySpendingKey:
		return RekeySpendingKey
	case metadata.RekeyList != nil:
		return RekeyOnlyThese
	default:
		return RekeyRefused
	}
}

// shapeFromMetadata reads a stored bounded account's shape.
func shapeFromMetadata(metadata *boundedmeta.Metadata) (Shape, error) {
	spend, err := canonicalSpend(strings.Join(metadata.SpendEffects, ","))
	if err != nil {
		return Shape{}, err
	}
	if err := boundedmeta.ValidateRekeySetting(metadata.Rekey); err != nil {
		return Shape{}, fmt.Errorf("stored account: %w", err)
	}
	shape := Shape{Spend: spend, Rekey: storedRekey(metadata), Cosigner: metadata.Cosigner != nil}
	switch metadata.Layer3Policy {
	case composeddsa.Layer3PolicyFixedAllowlist:
		shape.Encoding = EncodingInline
	case composeddsa.Layer3PolicyMerkleAllowlist:
		shape.Encoding = EncodingMerkle
	case composeddsa.Layer3PolicyNone:
		shape.AnyRecipient = true
	default:
		return Shape{}, fmt.Errorf("stored account has policy %q", metadata.Layer3Policy)
	}
	return shape, nil
}

// GrammarFingerprint identifies the arrangements and shapes an operator approves.
// A grammar whose shapes can't be built has no fingerprint, so a review against
// it never matches.
func (p *Provider) GrammarFingerprint() string {
	if err := p.loadShapes(); err != nil {
		return ""
	}
	return p.grammar
}

// GenerateTEAL renders the selected program.
func (p *Provider) GenerateTEAL(publicKey []byte, params map[string]string) (string, error) {
	if plain, err := plainRequest(params); err != nil {
		return "", err
	} else if plain {
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
	if plain, err := plainRequest(params); err != nil {
		return nil, "", err
	} else if plain {
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
	if plain, err := plainRequest(params); err != nil {
		return lsigsalt.FindResult{}, err
	} else if plain {
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
	if plain, err := plainRequest(params); err != nil {
		return nil, err
	} else if plain {
		return params, nil
	}
	request, err := present(params)
	if err != nil {
		return nil, err
	}
	selected, values, err := p.resolve(request)
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

// BuildBoundedAuthorizationMetadata snapshots a program's signing contract and
// refuses one the network could not run in one transaction, before the key is
// persisted. The plain program has none.
func (p *Provider) BuildBoundedAuthorizationMetadata(publicKey []byte, params map[string]string, bytecode []byte) (*boundedmeta.Metadata, error) {
	if plain, err := plainRequest(params); err != nil {
		return nil, err
	} else if plain {
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

// BoundedLogicSigOpcodeProfile is every program's path ceilings.
func (p *Provider) BoundedLogicSigOpcodeProfile() lsigresource.OpcodeProfile {
	return lsigresource.BoundedOpcodeProfile(opcodeCost, opcodeCost, opcodeCost)
}

// SetAlgodClient configures TEAL compilation for the plain program and every
// arrangement and shape.
func (p *Provider) SetAlgodClient(client *algod.Client) {
	p.Plain.SetAlgodClient(client)
	for _, selected := range p.arrangements {
		selected.composer.SetAlgodClient(client)
	}
	// Shapes built later take the client then.
	p.algodMu.Lock()
	defer p.algodMu.Unlock()
	p.algod = client
	for _, selected := range p.byShape {
		selected.composer.SetAlgodClient(client)
	}
	p.customMu.Lock()
	defer p.customMu.Unlock()
	for _, selected := range p.custom {
		selected.composer.SetAlgodClient(client)
	}
}

// checkResources is a generation backstop, not a promise about future networks:
// each path the program has must fit one transaction's resources. Signing still
// checks the selected path against the actual network rules. A fee ceiling below
// what a path costs is the user's choice, which the review warns about.
func checkResources(metadata *boundedmeta.Metadata, opcodes lsigresource.OpcodeProfile, programBytes int) error {
	_, err := pathFees(metadata, opcodes, programBytes)
	return err
}

// pathFee is what one of a program's paths costs the account when it pays alone.
type pathFee struct {
	name string
	fee  uint64
}

// pathFees solves each path the program has as a transaction on its own.
func pathFees(metadata *boundedmeta.Metadata, opcodes lsigresource.OpcodeProfile, programBytes int) ([]pathFee, error) {
	consensus, err := lsigresource.CurrentConsensus()
	if err != nil {
		return nil, fmt.Errorf("read consensus profile: %w", err)
	}
	type path struct {
		name   string
		opcode uint64
	}
	paths := []path{{boundedmeta.PathSpend, opcodes.Spend}}
	switch metadata.Rekey {
	case boundedmeta.RekeyRefused:
	case boundedmeta.RekeySpendingKey:
		paths = append(paths, path{boundedmeta.PathSpendingRekey, opcodes.SpendingRekey})
	default:
		return nil, fmt.Errorf("no resource path for rekey setting %q", metadata.Rekey)
	}
	if metadata.RekeyList != nil {
		paths = append(paths, path{boundedmeta.PathListedRekey, opcodes.ListedRekey})
	}
	fees := make([]pathFee, 0, len(paths))
	for _, path := range paths {
		plan, err := lsigresource.Solve(consensus, lsigresource.PlanInput{
			TransactionCount: 1,
			LogicSigs: []lsigresource.Usage{{
				ProgramBytes:  uint64(programBytes),
				ArgumentBytes: uint64(metadata.ArgumentBytesForPath(path.name)),
				MaxOpcodeCost: path.opcode,
			}},
			Dummy: lsigresource.Usage{ProgramBytes: uint64(len(txsigning.EmbeddedDummyTealTok)), MaxOpcodeCost: txsigning.DummyOpcodeCost},
		})
		if err != nil {
			return nil, fmt.Errorf("%s path does not fit the network's resource limits: %w", path.name, err)
		}
		fees = append(fees, pathFee{path.name, planFee(plan, consensus.MinTxnFee)})
	}
	return fees, nil
}

// CreationWarnings says when a bounded account can't pay for its own
// transactions. The program doesn't exist yet, so it is sized by what it must
// hold: the public keys it checks and an inline recipient list. The result is a
// lower bound, and a ceiling just above it may still fall short once the program
// is compiled; signing reports that case when it plans the group.
func (p *Provider) CreationWarnings(params map[string]string) ([]string, error) {
	request, err := present(params)
	if err != nil {
		return nil, err
	}
	if !hasBounds(request) {
		return nil, nil
	}
	selected, values, err := p.resolve(request)
	if err != nil {
		return nil, err
	}
	metadata := selected.composer.BoundedAuthorizationMetadata()
	if metadata == nil || metadata.MaxFee == nil {
		return nil, nil
	}
	programBytes := p.base.Ops.PublicKeySize()
	if metadata.Cosigner != nil {
		programBytes += boundedmeta.CosignerPublicKeySizeV1
	}
	if values[ParameterListEncoding] == EncodingInline {
		programBytes += addressBytes * (strings.Count(values[ParameterRecipients], ",") + 1)
	}
	fees, err := pathFees(metadata, p.BoundedLogicSigOpcodeProfile(), programBytes)
	if err != nil {
		return nil, err
	}
	var short []string
	for _, path := range fees {
		if path.fee > *metadata.MaxFee {
			short = append(short, fmt.Sprintf("%s (at least %d)", path.name, path.fee))
		}
	}
	if len(short) == 0 {
		return nil, nil
	}
	// The first sentence stands alone: a review with no room shows only it.
	return []string{fmt.Sprintf("Fee limit %d is too low to pay alone. "+
		"A transaction on its own costs more: %s. Batch it with others that share the cost, or have another account in the group pay its fees.",
		*metadata.MaxFee, strings.Join(short, ", "))}, nil
}

// addressBytes is what one inline recipient adds to a program.
const addressBytes = 32

// planFee is the plan's total fee, rounded up. Group size and the program fee
// factor are both small, so the product cannot overflow.
func planFee(plan lsigresource.Plan, minFee uint64) uint64 {
	const factorScale = 1_000_000
	usage := plan.GroupSize*factorScale + plan.ProgramFeeFactorUsage
	return (minFee*usage + factorScale - 1) / factorScale
}

// Compile-time interface checks.
var (
	_ logicsigdsa.LogicSigDSA                   = (*Provider)(nil)
	_ logicsigdsa.SaltedDeriver                 = (*Provider)(nil)
	_ logicsigdsa.TEALGenerator                 = (*Provider)(nil)
	_ lsigprovider.SigningProvider              = (*Provider)(nil)
	_ lsigprovider.AlgodConfigurable            = (*Provider)(nil)
	_ lsigprovider.InstanceResolver             = (*Provider)(nil)
	_ lsigprovider.CreationAdvisor              = (*Provider)(nil)
	_ lsigprovider.OpcodeProfileProvider        = (*Provider)(nil)
	_ lsigprovider.BoundedOpcodeProfileProvider = (*Provider)(nil)
)
