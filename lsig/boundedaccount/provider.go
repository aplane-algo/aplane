// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package boundedaccount

import (
	"context"
	"fmt"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	txsigning "github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	"github.com/aplane-algo/aplane/lsig/generictemplate"
)

const (
	derivationVersion = 3
	shapeOpcodeCost   = lsigresource.SingleTransactionOpcodeCeiling
	merkleProofArg    = "merkle_proof"
	merkleProofSize   = 512
)

// Definition is a compiled general bounded key type: its identity, the base that
// names its spending construction, and the shapes it offers. Listing a shape grants
// nothing: the bounded support policy still decides at generation, so a definition
// can't authorize a combination the policy refuses.
type Definition struct {
	Publisher   string
	Family      string
	Version     int
	BaseKeyType string
	DisplayName string
	Description string
	Shapes      []Shape
}

// falcon1024Definition is the production definition, aplane.falcon1024-b.v1.
func falcon1024Definition() Definition {
	return Definition{
		Publisher:   "aplane",
		Family:      "falcon1024-b",
		Version:     1,
		BaseKeyType: "aplane.falcon1024.v1",
		DisplayName: "Bounded Account",
		Description: "Falcon-1024 account limited to a fixed recipient list, chosen at generation.",
		Shapes:      Shapes(),
	}
}

// shapeDefinition is one shape with its composer and provenance.
type shapeDefinition struct {
	shape       Shape
	composer    *composeddsa.ComposedDSA
	fingerprint string
}

// Provider is the key type. It holds no per-account state: each request selects
// one of the shared composers, so concurrent requests cannot affect each other.
//
// It delegates method by method rather than embedding a composer. An embedded
// composer would answer every question with whichever shape it happened to be,
// including the definition-level bounded metadata this type does not have.
type Provider struct {
	definition Definition
	identity   *composeddsa.ComposedDSA
	params     []lsigprovider.ParameterDef
	byShape    map[string]*shapeDefinition
	ordered    []*shapeDefinition
	grammar    string
	// cosignerComponent is the component key type all cosigner shapes share.
	cosignerComponent string
}

// NewProvider builds the production key type.
func NewProvider() (*Provider, error) {
	return newProvider(falcon1024Definition())
}

// newProvider builds every shape of a definition. It fails if any cannot be built,
// because the grammar must not offer a shape that errors on first use. A shape can
// build and still be refused at generation: that is the support policy's decision,
// which this construction must not take, since inventory and durable load reach it.
// composeddsa's bounded_generation_support_test.go covers the policy's refusals at
// GenerateTEAL.
func newProvider(definition Definition) (*Provider, error) {
	if len(definition.Shapes) == 0 {
		return nil, fmt.Errorf("bounded definition %s.%s has no shapes", definition.Publisher, definition.Family)
	}
	provider := &Provider{definition: definition, params: creationParameters(), byShape: make(map[string]*shapeDefinition)}
	for _, shape := range definition.Shapes {
		// shapeSpec passes the rekey value straight to the template spec, so an
		// unknown value fails here, before anything is compiled.
		if err := boundedmeta.ValidateRekeySetting(boundedmeta.RekeySetting(shape.Rekey)); err != nil {
			return nil, fmt.Errorf("bounded definition %s.%s: shape %s has unknown rekey authority: %w", definition.Publisher, definition.Family, shape.Descriptor(), err)
		}
		composer, err := composeddsa.NewProviderFromTemplateSpec(shapeSpec(definition, shape))
		if err != nil {
			return nil, fmt.Errorf("build shape %s: %w", shape.Descriptor(), err)
		}
		built := &shapeDefinition{shape: shape, composer: composer, fingerprint: shapeFingerprint(shape, composer)}
		provider.byShape[shape.Descriptor()] = built
		provider.ordered = append(provider.ordered, built)
		if shape.Cosigner {
			provider.cosignerComponent = composer.BoundedAuthorizationMetadata().Cosigner.ComponentKeyType
		}
	}
	provider.identity = provider.ordered[0].composer
	provider.grammar = grammarFingerprint(provider.ordered)
	return provider, nil
}

// shapeSpec expresses a shape in the expert template schema, so a shape gets
// every check an imported template gets and cannot reach a composer state that a
// template could not.
func shapeSpec(definition Definition, shape Shape) *composeddsa.TemplateSpec {
	version := derivationVersion
	maxFee := MaxFee
	opcodeCost := uint64(shapeOpcodeCost)
	spend := make([]string, len(shape.Spend))
	for i, effect := range shape.Spend {
		spend[i] = string(effect)
	}
	bounded := &generictemplate.BoundedAuthorizationSpec{
		Contract:     composeddsa.BoundedContract,
		SpendEffects: spend,
		MaxFee:       &maxFee,
		Layer3:       &generictemplate.TransactionLayer3Spec{Policy: shape.Policy()},
	}
	// A shape that refuses rekeys has no rekey path in its program at all.
	bounded.Rekey = shape.Rekey
	if shape.Cosigner {
		bounded.Cosigner = &generictemplate.BoundedCosignerSpec{
			Contract:   boundedmeta.CosignerContractV1,
			RequiredOn: []string{boundedmeta.PathSpend},
		}
	}
	var parameters []generictemplate.ParameterSpec
	if shape.Encoding != "" {
		bounded.Layer3.RecipientsParameter = ParameterRecipients
		maxItems := InlineMax
		if shape.Encoding == EncodingMerkle {
			maxItems = RecipientsMax
		}
		parameters = append(parameters, generictemplate.ParameterSpec{
			Name:        ParameterRecipients,
			Label:       "Allowed Recipients",
			Description: "Addresses that may receive payments or asset transfers.",
			Type:        "address[]",
			Required:    true,
			MinItems:    1,
			MaxItems:    maxItems,
		})
	}
	if shape.Timelock {
		bounded.Layer3.UnlockRoundParameter = ParameterUnlockRound
		minRound := uint64(1)
		parameters = append(parameters, generictemplate.ParameterSpec{
			Name:        ParameterUnlockRound,
			Label:       "Unlock Round",
			Description: "First round the account can spend, on the network it runs on.",
			Type:        "uint64",
			Required:    true,
			Min:         &minRound,
		})
	}
	if shape.Encoding == EncodingMerkle {
		bounded.DerivedArgs = []generictemplate.BoundedDerivedArgSpec{{
			Name:      merkleProofArg,
			Kind:      boundedmeta.DerivedArgMerkleProof,
			Parameter: ParameterRecipients,
			MaxSize:   merkleProofSize,
		}}
	}
	return &composeddsa.TemplateSpec{
		SchemaVersion:     composeddsa.CurrentTemplateSchemaVersion,
		DerivationVersion: &version,
		TemplateType:      "composed",
		BaseKeyType:       definition.BaseKeyType,
		TemplateMode:      generictemplate.TemplateModeStrict,
		Publisher:         definition.Publisher,
		Family:            definition.Family,
		Version:           definition.Version,
		DisplayName:       definition.DisplayName,
		Description:       definition.Description,
		MaxOpcodeCost:     &opcodeCost,
		Bounded:           bounded,
		Parameters:        parameters,
	}
}

// creationParameters is the static vocabulary. It describes every field a shape
// might use, so the cosigner key is optional here and required by selectShape when
// the request selects a shape that uses it.
func creationParameters() []lsigprovider.ParameterDef {
	cosigner := composeddsa.BoundedCosignerParameterDef()
	cosigner.Required = false
	minimumRound := uint64(1)
	return []lsigprovider.ParameterDef{
		{
			Name:        ParameterSpendEffects,
			Label:       "Transfer Kinds",
			Description: "Comma-separated transfer kinds the account may make: pay, axfer, asset_opt_in.",
			Type:        "string",
			Required:    true,
			Example:     "pay,axfer,asset_opt_in",
		},
		{
			Name:        ParameterRecipients,
			Label:       "Allowed Recipients",
			Description: "Addresses that may receive payments or asset transfers. Optional only with an unlock round; absent with recipient scope any.",
			Type:        "address[]",
			MaxItems:    RecipientsMax,
		},
		{
			Name:        ParameterRecipientScope,
			Label:       "Recipient Scope",
			Description: "listed (default) limits transfers to the recipient list; any keeps only the fee ceiling and transfer kinds.",
			Type:        "string",
			Options:     []string{RecipientScopeListed, RecipientScopeAny},
		},
		{
			Name:        ParameterUnlockRound,
			Label:       "Unlock Round",
			Description: "First round the account can spend, on the network it runs on.",
			Type:        "uint64",
			Min:         &minimumRound,
		},
		{
			Name:        ParameterRekeyAuthority,
			Label:       "Rekey Authority",
			Description: "Who can rekey the account: the spending key alone, or no one (refused).",
			Type:        "string",
			Required:    true,
			Options:     []string{RekeySpendingKey, RekeyRefused},
		},
		{
			Name:        ParameterListEncoding,
			Label:       "List Encoding",
			Description: "How the program holds the list. Auto chooses inline through 10 recipients and Merkle above that.",
			Type:        "string",
			Options:     []string{EncodingAuto, EncodingInline, EncodingMerkle},
		},
		cosigner,
	}
}

func (p *Provider) resolve(params map[string]string) (*shapeDefinition, map[string]string, error) {
	selected, err := selectShape(params, p.params)
	if err != nil {
		return nil, nil, err
	}
	definition, ok := p.byShape[selected.shape.Descriptor()]
	if !ok {
		return nil, nil, fmt.Errorf("unsupported bounded shape %s", selected.shape.Descriptor())
	}
	return definition, selected.values, nil
}

// composerValues keeps only the parameters a shape's composer declares. The
// composer treats every value it receives as one of its own parameters, so
// selectors must not reach it.
func composerValues(definition *shapeDefinition, values map[string]string) map[string]string {
	declared := make(map[string]string)
	for _, def := range definition.composer.CreationParams() {
		if value, ok := values[def.Name]; ok {
			declared[def.Name] = value
		}
	}
	return declared
}

// CosignerComponentKeyType reports the cosigner a request asks for. A cosigner
// is optional in this type, so a request naming none returns false, and discovery
// cannot add one to every account.
func (p *Provider) CosignerComponentKeyType(params map[string]string) (string, bool) {
	_, hasName := params[ParameterCosigner]
	_, hasKey := params[composeddsa.BoundedCosignerPublicKeyParameter]
	if (!hasName && !hasKey) || p.cosignerComponent == "" {
		return "", false
	}
	return p.cosignerComponent, true
}

// ResolveInstance selects the shape for resolved parameters.
func (p *Provider) ResolveInstance(params map[string]string) (*lsigprovider.Instance, error) {
	definition, values, err := p.resolve(params)
	if err != nil {
		return nil, err
	}
	composer := definition.composer
	composerParams := composerValues(definition, values)
	if err := composer.ValidateCreationParams(composerParams); err != nil {
		return nil, err
	}
	digest, err := boundaryDigest(definition, composerParams)
	if err != nil {
		return nil, err
	}
	return &lsigprovider.Instance{
		Parameters:        composer.CreationParams(),
		Values:            values,
		Bounded:           composer.BoundedAuthorizationMetadata(),
		Fingerprint:       definition.fingerprint,
		ReviewFingerprint: p.grammar,
		BoundaryDigest:    digest,
	}, nil
}

// StoredFingerprint returns the current fingerprint of a stored account's shape,
// read from its durable metadata alone.
func (p *Provider) StoredFingerprint(_ map[string]string, metadata *boundedmeta.Metadata) (string, error) {
	if metadata == nil {
		return "", fmt.Errorf("stored account has no bounded metadata")
	}
	shape, err := shapeFromMetadata(metadata)
	if err != nil {
		return "", err
	}
	definition, ok := p.byShape[shape.Descriptor()]
	if !ok {
		return "", fmt.Errorf("unsupported bounded shape %s", shape.Descriptor())
	}
	return definition.fingerprint, nil
}

func shapeFromMetadata(metadata *boundedmeta.Metadata) (Shape, error) {
	spend, err := canonicalSpend(strings.Join(metadata.SpendEffects, ","))
	if err != nil {
		return Shape{}, err
	}
	shape := Shape{Spend: spend, Rekey: string(metadata.Rekey), Cosigner: metadata.Cosigner != nil}
	if err := boundedmeta.ValidateRekeySetting(metadata.Rekey); err != nil {
		return Shape{}, fmt.Errorf("stored account: %w", err)
	}
	switch metadata.Layer3Policy {
	case composeddsa.Layer3PolicyFixedAllowlist:
		shape.Encoding = EncodingInline
	case composeddsa.Layer3PolicyMerkleAllowlist:
		shape.Encoding = EncodingMerkle
	case composeddsa.Layer3PolicyTimelock:
		shape.Timelock = true
	case composeddsa.Layer3PolicyFixedAllowlistTimelock:
		shape.Encoding, shape.Timelock = EncodingInline, true
	case composeddsa.Layer3PolicyMerkleAllowlistTimelock:
		shape.Encoding, shape.Timelock = EncodingMerkle, true
	case composeddsa.Layer3PolicyNone:
		shape.AnyRecipient = true
	default:
		return Shape{}, fmt.Errorf("stored account has policy %q", metadata.Layer3Policy)
	}
	return shape, nil
}

// GrammarFingerprint identifies the whole grammar a review was made against.
func (p *Provider) GrammarFingerprint() string { return p.grammar }

// CompatibilityFingerprint is the type-wide fingerprint: the grammar. An account's
// own provenance is its shape's fingerprint, from ResolveInstance.
func (p *Provider) CompatibilityFingerprint() string { return p.grammar }

// KeyType returns the key type identifier.
func (p *Provider) KeyType() string { return p.identity.KeyType() }

// RoutingFamily returns the base family, which owns key generation and signing.
func (p *Provider) RoutingFamily() string { return p.identity.RoutingFamily() }

// Version returns the key type version.
func (p *Provider) Version() int { return p.identity.Version() }

// Category returns the LogicSig category.
func (p *Provider) Category() string { return lsigprovider.CategoryDSALsig }

// DisplayName returns the human-readable name.
func (p *Provider) DisplayName() string { return p.definition.DisplayName }

// Description returns a short description.
func (p *Provider) Description() string { return p.definition.Description }

// DisplayColor returns the base's display color.
func (p *Provider) DisplayColor() string { return p.identity.DisplayColor() }

// BaseKeyType returns the signing base of every shape.
func (p *Provider) BaseKeyType() string { return p.identity.BaseKeyType() }

// CryptoSignatureSize returns the base signature size.
func (p *Provider) CryptoSignatureSize() int { return p.identity.CryptoSignatureSize() }

// MnemonicScheme returns the base's scheme.
func (p *Provider) MnemonicScheme() string { return p.identity.MnemonicScheme() }

// MnemonicWordCount returns the base's word count.
func (p *Provider) MnemonicWordCount() int { return p.identity.MnemonicWordCount() }

// SupportsMnemonicImport is false: a LogicSig account recovers from its encrypted
// credential or backup, never from a mnemonic.
func (p *Provider) SupportsMnemonicImport() bool { return false }

// CreationParams returns the static vocabulary.
func (p *Provider) CreationParams() []lsigprovider.ParameterDef { return p.params }

// RuntimeArgs is empty: this grammar has no caller-supplied runtime arguments.
func (p *Provider) RuntimeArgs() []lsigprovider.RuntimeArgDef { return nil }

// LogicSigOpcodeProfile returns the path ceilings, which every shape shares.
func (p *Provider) LogicSigOpcodeProfile() lsigresource.OpcodeProfile {
	return p.identity.LogicSigOpcodeProfile()
}

// SetAlgodClient configures TEAL compilation on every shape.
func (p *Provider) SetAlgodClient(client *algod.Client) {
	for _, definition := range p.ordered {
		definition.composer.SetAlgodClient(client)
	}
}

// BuildArgs refuses: arguments depend on the transaction and the account's shape,
// so signing assembles them from the stored contract and packs the signature
// through the base key type.
func (p *Provider) BuildArgs([]byte, map[string][]byte) ([][]byte, error) {
	return nil, fmt.Errorf("%s arguments are assembled from the stored account contract", p.KeyType())
}

// ValidateCreationParams checks a request and the composer parameters it selects.
func (p *Provider) ValidateCreationParams(params map[string]string) error {
	definition, values, err := p.resolve(params)
	if err != nil {
		return err
	}
	return definition.composer.ValidateCreationParams(composerValues(definition, values))
}

// GenerateTEAL renders the selected shape's program.
func (p *Provider) GenerateTEAL(publicKey []byte, params map[string]string) (string, error) {
	definition, values, err := p.resolve(params)
	if err != nil {
		return "", err
	}
	return definition.composer.GenerateTEAL(publicKey, composerValues(definition, values))
}

// DeriveLsig derives the selected shape's program and address.
func (p *Provider) DeriveLsig(ctx context.Context, publicKey []byte, params map[string]string) ([]byte, string, error) {
	definition, values, err := p.resolve(params)
	if err != nil {
		return nil, "", err
	}
	return definition.composer.DeriveLsig(ctx, publicKey, composerValues(definition, values))
}

// DeriveLsigWithSalt derives the selected shape's program with salt metadata.
func (p *Provider) DeriveLsigWithSalt(ctx context.Context, publicKey []byte, params map[string]string) (lsigsalt.FindResult, error) {
	definition, values, err := p.resolve(params)
	if err != nil {
		return lsigsalt.FindResult{}, err
	}
	return definition.composer.DeriveLsigWithSalt(ctx, publicKey, composerValues(definition, values))
}

// BuildBoundedAuthorizationMetadata snapshots the account's signing contract and
// refuses a program the network could not run within its fee ceiling, before the
// key is persisted.
func (p *Provider) BuildBoundedAuthorizationMetadata(publicKey []byte, params map[string]string, bytecode []byte) (*boundedmeta.Metadata, error) {
	definition, values, err := p.resolve(params)
	if err != nil {
		return nil, err
	}
	metadata, err := definition.composer.BuildBoundedAuthorizationMetadata(publicKey, composerValues(definition, values), bytecode)
	if err != nil {
		return nil, err
	}
	if err := checkResources(metadata, p.LogicSigOpcodeProfile(), len(bytecode)); err != nil {
		return nil, err
	}
	return metadata, nil
}

// checkResources is a generation backstop, not a promise about future networks:
// signing still checks the selected path against the actual network rules.
func checkResources(metadata *boundedmeta.Metadata, opcodes lsigresource.OpcodeProfile, programBytes int) error {
	consensus, err := lsigresource.CurrentConsensus()
	if err != nil {
		return fmt.Errorf("read consensus profile: %w", err)
	}
	type path struct {
		name   string
		opcode uint64
	}
	// Every account has the spend path, and a spending-key rekey adds its own. A
	// setting this type does not offer has no path to solve, so it fails here.
	paths := []path{{boundedmeta.PathSpend, opcodes.Spend}}
	switch metadata.Rekey {
	case boundedmeta.RekeyRefused:
	case boundedmeta.RekeySpendingKey:
		paths = append(paths, path{boundedmeta.PathSpendingRekey, opcodes.SpendingRekey})
	default:
		return fmt.Errorf("no resource path for rekey setting %q", metadata.Rekey)
	}
	for _, path := range paths {
		plan, err := lsigresource.Solve(consensus, lsigresource.PlanInput{
			TransactionCount: 1,
			LogicSigs: []lsigresource.Usage{{
				ProgramBytes:  uint64(programBytes),
				ArgumentBytes: uint64(metadata.ArgumentBytesForPath(path.name)),
				MaxOpcodeCost: path.opcode,
			}},
			Dummy: lsigresource.Usage{ProgramBytes: uint64(len(txsigning.EmbeddedDummyTealTok)), MaxOpcodeCost: 1},
		})
		if err != nil {
			return fmt.Errorf("%s path does not fit the network's resource limits: %w", path.name, err)
		}
		if fee := planFee(plan, consensus.MinTxnFee); fee > metadata.MaxFee {
			return fmt.Errorf("%s path needs a fee of %d, above the account's ceiling of %d", path.name, fee, metadata.MaxFee)
		}
	}
	return nil
}

// planFee is the plan's total fee, rounded up. Group size and the program fee
// factor are both small, so the product cannot overflow.
func planFee(plan lsigresource.Plan, minFee uint64) uint64 {
	const factorScale = 1_000_000
	usage := plan.GroupSize*factorScale + plan.ProgramFeeFactorUsage
	return (minFee*usage + factorScale - 1) / factorScale
}

// Compile-time interface checks.
var (
	_ logicsigdsa.LogicSigDSA            = (*Provider)(nil)
	_ logicsigdsa.SaltedDeriver          = (*Provider)(nil)
	_ logicsigdsa.TEALGenerator          = (*Provider)(nil)
	_ lsigprovider.LSigProvider          = (*Provider)(nil)
	_ lsigprovider.SigningProvider       = (*Provider)(nil)
	_ lsigprovider.MnemonicProvider      = (*Provider)(nil)
	_ lsigprovider.AlgodConfigurable     = (*Provider)(nil)
	_ lsigprovider.InstanceResolver      = (*Provider)(nil)
	_ lsigprovider.OpcodeProfileProvider = (*Provider)(nil)
)
