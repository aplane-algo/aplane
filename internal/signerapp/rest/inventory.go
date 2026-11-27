// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rest

import (
	"errors"
	"sort"
	"strings"

	"github.com/aplane-algo/aplane/internal/algorithm"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/cosigner/cosignerrefs"
	"github.com/aplane-algo/aplane/internal/cosigner/keytypes"
	"github.com/aplane-algo/aplane/internal/genericlsig"
	"github.com/aplane-algo/aplane/internal/hostmeta"
	"github.com/aplane-algo/aplane/internal/keyclass"
	"github.com/aplane-algo/aplane/internal/keymgmt"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	"github.com/aplane-algo/aplane/internal/signerapp/keytypemeta"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	signersigning "github.com/aplane-algo/aplane/internal/signerapp/signing"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

func (s Service) BuildKeyInfoList(ir *productruntime.Runtime) []signerapi.KeyInfo {
	if ir == nil {
		return []signerapi.KeyInfo{}
	}

	// One snapshot of the published keys: a reload installs the keystore's own
	// maps first, so reading those too could pair a key with another revision's
	// metadata.
	snapshot := ir.KeyIndexSnapshot()
	keyList := make([]signerapi.KeyInfo, 0, len(snapshot.KeyFiles))
	for address := range snapshot.KeyFiles {
		keyType := snapshot.KeyTypes[address]
		metadata := snapshot.KeyMetadata[address]
		category := metadata.Category

		keyInfo := signerapi.KeyInfo{
			Address:           address,
			PublicKeyHex:      metadata.PublicKeyHex,
			KeyType:           keyType,
			AuthorizationKind: authorizationKindForCategory(category),
			IsGenericLsig:     keys.IsGenericKey(category),
			IsWitnessKey:      keys.IsWitnessKey(category),
			// The value the aplane key recorded at creation, not the key
			// type's current declaration (that is /keytypes').
			ValidRekeyTarget: metadata.ValidRekeyTarget,
		}
		keyInfo.LogicSigResources = publicLogicSigResourceProfile(metadata.LogicSigResources)
		if rotatingkey.IsRotatingKeyType(keyType) {
			// Stage keys never leave the signer; only the account address does.
			keyInfo.PublicKeyHex = ""
			keyInfo.SigningFlow = signerapi.SigningFlowRotating1
		}
		if metadata.Host != nil {
			keyInfo.Parameters = hostAccountParameters(metadata.Parameters)
			// Without a cosigner a bounded account signs through ordinary
			// /sign, so it advertises no flow.
			if cosigner := metadata.Host.Cosigner; cosigner != nil {
				keyInfo.SigningFlow = signerapi.SigningFlowCosigned1
				keyInfo.CosignerComponentKeyType = cosigner.ComponentKeyType
			}
			keyInfo.Host = hostInfo(metadata.Host)
		}
		keyInfo.TemplateProvenanceStatus, keyInfo.TemplateProvenanceNote = lsigprovider.CompareAccountProvenance(keyType, metadata.TemplateFingerprint, metadata.Parameters, metadata.Host)

		if len(metadata.SigningArgs) > 0 {
			keyInfo.SigningArgs = keytypemeta.RuntimeArgs(metadata.SigningArgs)
		}

		keyList = append(keyList, keyInfo)
	}

	return keyList
}

func authorizationKindForCategory(category string) string {
	switch category {
	case keys.CategoryEd25519:
		return string(algorithm.AuthorizationEd25519)
	case keys.CategoryNativePQ:
		return string(algorithm.AuthorizationNativePQ)
	case keys.CategoryDSALsig, keys.CategoryGenericLsig, keys.CategoryRotatingLsig:
		return string(algorithm.AuthorizationLogicSig)
	default:
		// Witness credentials are not transaction authorizers. Unknown durable
		// categories likewise must not be projected as an account envelope.
		return ""
	}
}

func publicLogicSigResourceProfile(profile *lsigresource.Profile) *signerapi.LogicSigResourceProfile {
	if profile == nil {
		return nil
	}
	usage := func(path *lsigresource.PathProfile) *signerapi.LogicSigResourceUsage {
		if path == nil {
			return nil
		}
		return &signerapi.LogicSigResourceUsage{
			ProgramBytes:  profile.ProgramBytes,
			ArgumentBytes: path.ArgumentBytes,
			MaxOpcodeCost: path.MaxOpcodeCost,
		}
	}
	return &signerapi.LogicSigResourceProfile{
		Default:       usage(profile.Default),
		Spend:         usage(profile.Spend),
		SpendingRekey: usage(profile.SpendingRekey),
		ListedRekey:   usage(profile.ListedRekey),
	}
}

// hostInventoryParameterNames is the explicit public projection of current
// bounded creation parameters. Adding a new stored parameter does not expose it
// through /keys unless its public status is reviewed here.
var hostInventoryParameterNames = []string{
	"recipients",
	hostmeta.CosignerPublicKeyParameter,
}

func hostAccountParameters(parameters map[string]string) map[string]string {
	var out map[string]string
	for _, name := range hostInventoryParameterNames {
		value, ok := parameters[name]
		if !ok {
			continue
		}
		if out == nil {
			out = make(map[string]string)
		}
		out[name] = value
	}
	return out
}

func (s Service) Keys(ir *productruntime.Runtime) (*signerapi.KeysResponse, *signersigning.ServiceError) {
	if err := ensureRuntimeUnlocked(ir); err != nil {
		return nil, err
	}

	lockGen := ir.LockGeneration()
	return keysAnswer(ir, lockGen, s.BuildKeyInfoList(ir))
}

// keysAnswer answers /keys with keyList, built after the runtime was seen
// unlocked at lockGen. A lock, or a maintenance pass, while it was built
// empties the published keys, so the list may be empty or partial and would
// read as the whole of an unlocked signer's keys: the signer answers as
// locked instead, as it does when it is locked from the start.
func keysAnswer(ir *productruntime.Runtime, lockGen uint64, keyList []signerapi.KeyInfo) (*signerapi.KeysResponse, *signersigning.ServiceError) {
	if !ir.IsUnlocked() || ir.LockGeneration() != lockGen {
		return nil, lockedError()
	}
	return &signerapi.KeysResponse{Keys: keyList}, nil
}

// BuildKeyTypes lists the key types the node offers for its role. While the
// store is locked its activation records cannot be read, so the list holds
// the built-in key types only: those enabled by default. A library key type
// the store enables, and every template-backed type, appears after unlock.
func (s Service) BuildKeyTypes(ir *productruntime.Runtime) ([]signerapi.KeyTypeInfo, error) {
	enabled, err := storeEnabledKeyTypes(ir)
	if err != nil {
		return nil, err
	}
	validTypes := filterKeyTypesForNodeRole(keymgmt.GetValidKeyTypesWithActivated(enabled), ir.NodeRole())
	infos := s.buildKeyTypes(validTypes, enabled)
	if err := s.applyCosignerReferenceParams(ir, infos); err != nil {
		return nil, err
	}
	return infos, nil
}

// storeEnabledKeyTypes returns the key types the store's activation records
// enable, or none while the store is locked.
func storeEnabledKeyTypes(ir *productruntime.Runtime) ([]string, error) {
	activePaths, err := ir.ActiveKeyPaths()
	if errors.Is(err, keystore.ErrStoreLocked) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return keytypestate.ListEnabled(activePaths)
}

func filterKeyTypesForNodeRole(validTypes []string, role noderole.Role) []string {
	filtered := make([]string, 0, len(validTypes))
	for _, keyType := range validTypes {
		if keyclass.NodeRoleAllowsKeyType(role, keyType) {
			filtered = append(filtered, keyType)
		}
	}
	return filtered
}

func (s Service) buildKeyTypes(validTypes []string, enabledGeneric []string) []signerapi.KeyTypeInfo {
	keyTypes := make([]signerapi.KeyTypeInfo, 0, len(validTypes))

	for _, keyType := range validTypes {
		info := signerapi.KeyTypeInfo{
			KeyType:          keyType,
			ValidRekeyTarget: lsigprovider.ValidRekeyTarget(keyType),
			CreationParams:   []signerapi.CreationParamInfo{},
			RuntimeArgs:      []signerapi.RuntimeArgInfo{},
		}

		if witness.IsKeyType(keyType) {
			info.Family, info.DisplayName, info.Description = cosignerComponentKeyTypeMetadata(keyType)
			keyTypes = append(keyTypes, info)
			continue
		}
		if rotatingkey.IsRotatingKeyType(keyType) {
			keyTypes = append(keyTypes, rotatingKeyTypeInfo(info, s.networkNames()))
			continue
		}

		meta, err := algorithm.GetMetadata(keyType)
		if err == nil {
			info.Family = meta.RoutingFamily()
			info.AuthorizationKind = string(meta.AuthorizationKind())
			info.MnemonicWordCount = meta.MnemonicWordCount()
			info.MnemonicImport = keymgmt.SupportsMnemonicImport(keyType)
			info.MnemonicScheme = meta.MnemonicScheme()
		} else {
			info.Family = keyType
		}

		if provider := lsigprovider.Get(keyType); provider != nil {
			describeProvider(&info, provider)
		} else {
			switch keyType {
			case nativefalcon.KeyType:
				info.DisplayName = "Native Falcon-1024"
			case keys.CategoryEd25519:
				info.DisplayName = "Native Ed25519"
			default:
				info.DisplayName = strings.ToUpper(keyType[:1]) + keyType[1:]
			}
			if info.AuthorizationKind == string(algorithm.AuthorizationNativePQ) {
				info.Description = "Native Algorand Falcon-1024 signing key"
			} else {
				info.Description = "Native Algorand signing key"
			}
		}

		keyTypes = append(keyTypes, info)
	}

	enabledGenericSet := make(map[string]bool, len(enabledGeneric))
	for _, keyType := range enabledGeneric {
		enabledGenericSet[strings.ToLower(strings.TrimSpace(keyType))] = true
	}
	for _, tmpl := range genericlsig.GetAll() {
		// Generic template providers are process-global once registered, but
		// identity inventory is gated by the product-store installed/enabled set.
		if !enabledGenericSet[strings.ToLower(strings.TrimSpace(tmpl.KeyType()))] {
			continue
		}
		info := signerapi.KeyTypeInfo{
			KeyType:           tmpl.KeyType(),
			Family:            tmpl.RoutingFamily(),
			AuthorizationKind: string(algorithm.AuthorizationLogicSig),
			ValidRekeyTarget:  lsigprovider.ValidRekeyTarget(tmpl.KeyType()),
		}
		// A generic template is a provider like any other, described alike.
		describeProvider(&info, tmpl)
		keyTypes = append(keyTypes, info)
	}

	return keyTypes
}

// describeProvider fills in what a LogicSig provider says of its key type:
// its names, its bounded authorization or per-key contract, and the
// parameters and arguments it takes.
func describeProvider(info *signerapi.KeyTypeInfo, provider lsigprovider.LSigProvider) {
	info.DisplayName = provider.DisplayName()
	info.Description = lsigprovider.DescriptionText(provider.Description())
	if hostProvider, ok := provider.(hostInventoryProvider); ok {
		if metadata := hostProvider.HostMetadata(); metadata != nil {
			if metadata.Cosigner != nil {
				info.SigningFlow = signerapi.SigningFlowCosigned1
				info.CosignerComponentKeyTypes = []string{metadata.Cosigner.ComponentKeyType}
			}
			info.Host = hostInfo(metadata)
		}
	}

	// A per-key type has no fixed contract to report. Its cosigner is
	// optional, so this names the capability without asking for one.
	if resolver, ok := provider.(lsigprovider.InstanceResolver); ok {
		info.PerKeyContract = true
		info.CosignerComponentKeyTypes, _ = resolver.CosignerComponentKeyTypes(map[string]string{cosignerrefs.ParamCosignerName: ""})
		if grammar, ok := provider.(boundaryGrammarProvider); ok {
			info.BoundarySchema = grammar.BoundarySchema()
		}
	}

	info.CreationParams = keytypemeta.CreationParams(provider.CreationParams())
	info.RuntimeArgs = keytypemeta.RuntimeArgs(provider.RuntimeArgs())
}

// boundaryGrammarProvider is a per-key type whose requests a boundary file
// grammar describes.
type boundaryGrammarProvider interface {
	BoundarySchema() string
}

type hostInventoryProvider interface {
	HostMetadata() *hostmeta.Metadata
}

func hostInfo(metadata *hostmeta.Metadata) *signerapi.HostInfo {
	if metadata == nil {
		return nil
	}
	info := &signerapi.HostInfo{
		Contract: metadata.Contract,
		BaseSignatureArgLayout: signerapi.HostSignatureArgLayout{
			Count:    metadata.BaseSignatureArgLayout.Count,
			MaxSizes: append([]int(nil), metadata.BaseSignatureArgLayout.MaxSizes...),
		},
		RuntimeArgs: keytypemeta.HostRuntimeArgs(metadata.RuntimeArgs),
	}
	if bounds := metadata.Bounds; bounds != nil {
		info.Bounds = &signerapi.HostBoundsInfo{
			SpendEffects: append([]string{}, bounds.SpendEffects...),
			Layer3Policy: bounds.Layer3Policy,
		}
		// Valid metadata always has a ceiling; without one this publishes 0,
		// the tightest ceiling.
		if bounds.MaxFee != nil {
			info.Bounds.MaxFee = *bounds.MaxFee
		}
	}
	if metadata.Cosigner != nil {
		info.Cosigner = &signerapi.HostCosignerInfo{
			Contract: metadata.Cosigner.Contract, ComponentKeyType: metadata.Cosigner.ComponentKeyType,
			PublicKeyHex: metadata.Cosigner.PublicKeyHex, ComponentKeyID: metadata.Cosigner.ComponentKeyID,
			SignatureMaxSize: metadata.Cosigner.SignatureMaxSize,
			RequiredOn:       append([]string(nil), metadata.Cosigner.RequiredOn...),
		}
	}
	if metadata.RekeyList != nil {
		info.RekeyList = &signerapi.HostRekeyListInfo{
			Contract: metadata.RekeyList.Contract, Depth: metadata.RekeyList.Depth, RootHex: metadata.RekeyList.RootHex,
		}
	}
	for _, arg := range metadata.DerivedArgs {
		info.DerivedArgs = append(info.DerivedArgs, signerapi.HostDerivedArgInfo{
			Name: arg.Name, Kind: arg.Kind, Parameter: arg.Parameter, MaxSize: arg.MaxSize,
		})
	}
	for _, slot := range metadata.ArgumentLayout {
		info.ArgumentLayout = append(info.ArgumentLayout, signerapi.HostArgumentSlotInfo{
			Index: slot.Index, Name: slot.Name, Source: slot.Source, MaxSize: slot.MaxSize,
			Paths: signerapi.HostArgumentPathMask{
				Spend: slot.Paths.Spend, SpendingRekey: slot.Paths.SpendingRekey, ListedRekey: slot.Paths.ListedRekey,
			},
		})
	}
	if info.DerivedArgs == nil {
		info.DerivedArgs = []signerapi.HostDerivedArgInfo{}
	}
	if info.ArgumentLayout == nil {
		info.ArgumentLayout = []signerapi.HostArgumentSlotInfo{}
	}
	info.Rekey = string(metadata.Rekey)
	return info
}

// applyCosignerReferenceParams offers the imported cosigner references as the
// cosigner choice. A reference file that is not valid is left out and logged:
// it can only remove a choice, never change one.
func (s Service) applyCosignerReferenceParams(ir *productruntime.Runtime, infos []signerapi.KeyTypeInfo) error {
	if ir == nil {
		return nil
	}
	refs, invalid, err := cosignerrefs.List(ir.KeyPaths())
	if err != nil {
		return err
	}
	if s.Deps.ReportInvalidCosignerReferences != nil {
		s.Deps.ReportInvalidCosignerReferences(invalid)
	}
	if len(refs) == 0 {
		return nil
	}

	componentIDsByComponentType := make(map[string]map[string]struct{})
	for _, ref := range refs {
		if componentIDsByComponentType[ref.KeyType] == nil {
			componentIDsByComponentType[ref.KeyType] = make(map[string]struct{})
		}
		componentIDsByComponentType[ref.KeyType][ref.ComponentKey] = struct{}{}
	}
	componentIDsByType := make(map[string][]string, len(componentIDsByComponentType))
	for componentType, componentIDs := range componentIDsByComponentType {
		ids := make([]string, 0, len(componentIDs))
		for id := range componentIDs {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		componentIDsByType[componentType] = ids
	}

	for i := range infos {
		// Replacing the field with a required selector would add a cosigner to
		// every account of a type where one is optional. A fixed type takes
		// one cosigner type.
		if len(infos[i].CosignerComponentKeyTypes) != 1 || infos[i].PerKeyContract {
			continue
		}
		componentIDs := componentIDsByType[infos[i].CosignerComponentKeyTypes[0]]
		if len(componentIDs) == 0 {
			continue
		}
		cosignerParam := keytypemeta.CreationParam(lsigprovider.ParameterDef{
			Name:        cosignerrefs.ParamCosignerName,
			Label:       "Witness Key ID",
			Description: "Imported Witness Key ID to embed in the cosigned account",
			Type:        "select",
			Required:    true,
			Options:     componentIDs,
			Default:     componentIDs[0],
		})
		infos[i].CreationParams = replaceCosignerPublicKeyParam(infos[i].CreationParams, cosignerParam)
	}
	return nil
}

func replaceCosignerPublicKeyParam(params []signerapi.CreationParamInfo, replacement signerapi.CreationParamInfo) []signerapi.CreationParamInfo {
	out := make([]signerapi.CreationParamInfo, 0, len(params))
	replaced := false
	for _, param := range params {
		if param.Name == keytypes.ParameterCosignerPublicKey {
			out = append(out, replacement)
			replaced = true
			continue
		}
		out = append(out, param)
	}
	if !replaced {
		return []signerapi.CreationParamInfo{replacement}
	}
	return out
}

func cosignerComponentKeyTypeMetadata(keyType string) (family, displayName, description string) {
	switch keyType {
	case witness.Falcon1024V1:
		return "cosigner-falcon1024", "Cosigner Falcon-1024 key", "Raw Falcon-1024 cosigner signing key for cosigner-role component signatures"
	case witness.Ed25519V1:
		return "cosigner-ed25519", "Cosigner Ed25519 key", "Raw Ed25519 cosigner signing key for cosigner-role component signatures"
	default:
		return keyType, keyType, "Raw cosigner signing key for cosigner-role component signatures"
	}
}

func (s Service) KeyTypes(ir *productruntime.Runtime) (*signerapi.KeyTypesResponse, *signersigning.ServiceError) {
	if ir == nil {
		return nil, &signersigning.ServiceError{Kind: signersigning.ErrorInternal, Message: "product runtime is nil"}
	}
	keyTypes, err := s.BuildKeyTypes(ir)
	if err != nil {
		s.warnf("key type list failed: %v", err)
		return nil, &signersigning.ServiceError{Kind: signersigning.ErrorInternal, Message: "failed to read key type activations or cosigner references"}
	}
	return &signerapi.KeyTypesResponse{KeyTypes: keyTypes}, nil
}

// networkNames returns the networks the signer knows, sorted, for the
// rotating key type's network choice.
func (s Service) networkNames() []string {
	if s.Deps.NetworkGenesisHashes == nil {
		return nil
	}
	names := make([]string, 0)
	for name := range s.Deps.NetworkGenesisHashes() {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// rotatingKeyTypeInfo describes the rotating account key type. It has no
// LogicSig provider: its program changes on every spend, so the signer owns
// its derivation and signing through the rotating1 flow.
func rotatingKeyTypeInfo(info signerapi.KeyTypeInfo, networks []string) signerapi.KeyTypeInfo {
	profile, _ := rotatingkey.Lookup(info.KeyType)
	info.Family = profile.Family
	info.DisplayName = profile.DisplayName
	info.Description = profile.Description
	info.AuthorizationKind = string(algorithm.AuthorizationLogicSig)
	info.MnemonicWordCount = 24
	info.SigningFlow = signerapi.SigningFlowRotating1
	info.CreationParams = keytypemeta.CreationParams([]lsigprovider.ParameterDef{{
		Name:        rotatingkey.RotatingNetworkParameter,
		Label:       rotatingkey.RotatingNetworkParameterLabel,
		Description: rotatingkey.RotatingNetworkParameterDescription,
		Type:        "string",
		Required:    true,
		Options:     networks,
		Default:     defaultRotatingNetwork(networks),
		Example:     rotatingkey.RotatingNetworkParameterExample,
	}})
	return info
}

// defaultRotatingNetwork pre-selects the network for a new rotating account:
// the signer's only configured custom network when there is exactly one,
// such as localnet, and otherwise testnet. It never defaults to mainnet, so
// an operator who accepts the default without reading binds at most a test
// account to the wrong network.
func defaultRotatingNetwork(networks []string) string {
	builtin := make(map[string]bool)
	for _, name := range apconfig.BuiltinGenesisHashNetworks() {
		builtin[name] = true
	}
	var custom []string
	hasTestnet := false
	for _, name := range networks {
		switch {
		case name == "testnet":
			hasTestnet = true
		case !builtin[name]:
			custom = append(custom, name)
		}
	}
	if len(custom) == 1 {
		return custom[0]
	}
	if hasTestnet {
		return "testnet"
	}
	return ""
}
