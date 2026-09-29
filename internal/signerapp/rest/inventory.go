// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rest

import (
	"sort"
	"strings"

	"github.com/aplane-algo/aplane/internal/algorithm"
	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/cosigner/cosignerrefs"
	"github.com/aplane-algo/aplane/internal/cosigner/keytypes"
	"github.com/aplane-algo/aplane/internal/genericlsig"
	"github.com/aplane-algo/aplane/internal/keyclass"
	"github.com/aplane-algo/aplane/internal/keymgmt"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	signersigning "github.com/aplane-algo/aplane/internal/signerapp/signing"
	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
)

func (s Service) BuildKeyInfoList(ir *productruntime.Runtime) []signerapi.KeyInfo {
	if ir == nil {
		return []signerapi.KeyInfo{}
	}
	ks := ir.KeyStore()
	if ks == nil {
		return []signerapi.KeyInfo{}
	}

	// KeySnapshot skips the per-key metadata deep-clone; the metadata this
	// listing needs comes from GetSigningSummary below.
	keysCopy, keyTypesCopy := ir.KeySnapshot()
	publicKeyHexMap := ks.GetPublicKeyHexMap()
	signingSummary := ks.GetSigningSummary()

	keyList := make([]signerapi.KeyInfo, 0, len(keysCopy))
	for address := range keysCopy {
		keyType := keyTypesCopy[address]
		summary := signingSummary[address]
		category := summary.Category
		isGeneric := keys.IsGenericKey(category)
		isComponent := keys.IsWitnessKey(category)

		keyInfo := signerapi.KeyInfo{
			Address:           address,
			PublicKeyHex:      publicKeyHexMap[address],
			KeyType:           keyType,
			AuthorizationKind: authorizationKindForCategory(category),
			IsGenericLsig:     isGeneric,
		}
		keyInfo.LogicSigResources = publicLogicSigResourceProfile(summary.LogicSigResources)
		if isComponent {
			spending := false
			keyInfo.IsWitnessKey = true
			keyInfo.IsSpendingAccount = &spending
		}
		if keytypes.IsGuardedAccountKeyType(keyType) {
			keyInfo.SigningFlow = signerapi.SigningFlowCosigner1
			keyInfo.CosignerComponentKeyType, _ = keytypes.CosignerComponentKeyTypeForGuardedAccount(keyType)
			keyInfo.Parameters = guardedAccountParameters(keyType, summary.Parameters)
		}
		if summary.BoundedAuthorization != nil {
			keyInfo.Parameters = boundedAccountParameters(summary.Parameters)
			keyInfo.SigningFlow = boundedSigningFlow(summary.BoundedAuthorization)
			if summary.BoundedAuthorization.Cosigner != nil {
				keyInfo.CosignerComponentKeyType = summary.BoundedAuthorization.Cosigner.ComponentKeyType
			}
			keyInfo.BoundedAuthorization = boundedInfo(summary.BoundedAuthorization)
		}
		keyInfo.TemplateProvenanceStatus, keyInfo.TemplateProvenanceNote = keys.CompareTemplateFingerprint(keyType, summary.TemplateFingerprint)

		if summary.SigningMetadataVersion > 0 {
			keyInfo.SigningArgs = signingArgInfos(summary.SigningArgs)
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
	case keys.CategoryDSALsig, keys.CategoryGenericLsig:
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
		AdminRekey:    usage(profile.AdminRekey),
	}
}

func guardedAccountParameters(_ string, parameters map[string]string) map[string]string {
	cosignerPublicKey := parameters[keytypes.ParameterCosignerPublicKey]
	if cosignerPublicKey == "" {
		return nil
	}
	out := map[string]string{
		keytypes.ParameterCosignerPublicKey: cosignerPublicKey,
	}
	return out
}

// boundedInventoryParameterNames is the explicit public projection of current
// bounded creation parameters. Adding a new stored parameter does not expose it
// through /keys unless its public status is reviewed here.
var boundedInventoryParameterNames = []string{
	"recipients",
	"asset_ids",
	"max_payment_amount",
	"max_asset_amount",
	"unlock_round",
	composeddsa.BoundedCosignerPublicKeyParameter,
	composeddsa.BoundedAdminPublicKeyParameter,
}

func boundedAccountParameters(parameters map[string]string) map[string]string {
	var out map[string]string
	for _, name := range boundedInventoryParameterNames {
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

func restInputModeInfos(modes []lsigprovider.InputMode) []signerapi.InputModeInfo {
	if len(modes) == 0 {
		return nil
	}
	out := make([]signerapi.InputModeInfo, len(modes))
	for i, mode := range modes {
		out[i] = signerapi.InputModeInfo{
			Name:       mode.Name,
			Label:      mode.Label,
			Transform:  mode.Transform,
			ByteLength: mode.ByteLength,
			InputType:  mode.InputType,
		}
	}
	return out
}

func signingArgInfos(args []lsigprovider.RuntimeArgDef) []signerapi.SigningArgInfo {
	if len(args) == 0 {
		return nil
	}
	out := make([]signerapi.SigningArgInfo, len(args))
	for i, arg := range args {
		out[i] = signerapi.SigningArgInfo{
			Name:        arg.Name,
			Label:       arg.Label,
			Description: arg.Description,
			Type:        arg.Type,
			Required:    arg.Required,
			ByteLength:  arg.ByteLength,
			MaxSize:     arg.MaxSize,
		}
	}
	return out
}

func (s Service) Keys(ir *productruntime.Runtime) (*signerapi.KeysResponse, *signersigning.ServiceError) {
	if err := ensureRuntimeUnlocked(ir); err != nil {
		return nil, err
	}

	keyList := s.BuildKeyInfoList(ir)
	return &signerapi.KeysResponse{
		Count: len(keyList),
		Keys:  keyList,
	}, nil
}

func (s Service) BuildKeyTypes(ir *productruntime.Runtime) ([]signerapi.KeyTypeInfo, error) {
	activePaths, err := ir.ActiveKeyPaths()
	if err != nil {
		activePaths = ir.KeyPaths()
		if _, ok := activePaths.BoundActiveGeneration(); !ok {
			return nil, err
		}
	}
	validTypes, err := keymgmt.GetAvailableKeyTypes(activePaths)
	if err != nil {
		return nil, err
	}
	validTypes = filterKeyTypesForNodeRole(validTypes, ir.NodeRole())
	enabled, err := keytypestate.ListEnabled(activePaths)
	if err != nil {
		return nil, err
	}
	infos := s.buildKeyTypes(validTypes, enabled)
	applyCosignerReferenceParams(ir, infos)
	return infos, nil
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
			KeyType:        keyType,
			CreationParams: []signerapi.CreationParamInfo{},
			RuntimeArgs:    []signerapi.RuntimeArgInfo{},
		}

		if witness.IsKeyType(keyType) {
			info.Family, info.DisplayName, info.Description = cosignerComponentKeyTypeMetadata(keyType)
			keyTypes = append(keyTypes, info)
			continue
		}
		if componentType, ok := keytypes.CosignerComponentKeyTypeForGuardedAccount(keyType); ok {
			info.SigningFlow = signerapi.SigningFlowCosigner1
			info.CosignerComponentKeyType = componentType
		}

		meta, err := algorithm.GetMetadata(keyType)
		if err == nil {
			info.Family = meta.RoutingFamily()
			info.AuthorizationKind = string(meta.AuthorizationKind())
			info.RequiresLogicSig = meta.RequiresLogicSig()
			info.MnemonicWordCount = meta.MnemonicWordCount()
			info.MnemonicImport = keymgmt.SupportsMnemonicImport(keyType)
			info.MnemonicScheme = meta.MnemonicScheme()
		} else {
			info.Family = keyType
		}

		if provider := lsigprovider.Get(keyType); provider != nil {
			info.DisplayName = provider.DisplayName()
			info.Description = provider.Description()
			if boundedProvider, ok := provider.(boundedInventoryProvider); ok {
				if metadata := boundedProvider.BoundedAuthorizationMetadata(); metadata != nil {
					info.SigningFlow = boundedSigningFlow(metadata)
					if metadata.Cosigner != nil {
						info.CosignerComponentKeyType = metadata.Cosigner.ComponentKeyType
					}
					info.BoundedAuthorization = boundedInfo(metadata)
				}
			}

			for _, p := range provider.CreationParams() {
				info.CreationParams = append(info.CreationParams, signerapi.CreationParamInfo{
					Name:        p.Name,
					Label:       p.Label,
					Description: p.Description,
					Type:        p.Type,
					Required:    p.Required,
					MaxLength:   p.MaxLength,
					InputModes:  restInputModeInfos(p.InputModes),
					Options:     append([]string(nil), p.Options...),
					MinItems:    p.MinItems,
					MaxItems:    p.MaxItems,
					Example:     p.Example,
					Placeholder: p.Placeholder,
					Min:         p.Min,
					Max:         p.Max,
					Default:     p.Default,
				})
			}

			for _, a := range provider.RuntimeArgs() {
				info.RuntimeArgs = append(info.RuntimeArgs, signerapi.RuntimeArgInfo{
					Name:        a.Name,
					Label:       a.Label,
					Description: a.Description,
					Type:        a.Type,
					Required:    a.Required,
					ByteLength:  a.ByteLength,
					MaxSize:     a.MaxSize,
				})
			}
		} else {
			if info.AuthorizationKind == string(algorithm.AuthorizationNativePQ) {
				info.DisplayName = keyType
				info.Description = "Native Algorand Falcon-1024 signing key"
			} else {
				info.DisplayName = strings.ToUpper(keyType[:1]) + keyType[1:]
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
		if enabledGeneric != nil && !enabledGenericSet[strings.ToLower(strings.TrimSpace(tmpl.KeyType()))] {
			continue
		}
		info := signerapi.KeyTypeInfo{
			KeyType:           tmpl.KeyType(),
			Family:            tmpl.RoutingFamily(),
			DisplayName:       tmpl.DisplayName(),
			Description:       tmpl.Description(),
			AuthorizationKind: string(algorithm.AuthorizationLogicSig),
			RequiresLogicSig:  true,
			CreationParams:    []signerapi.CreationParamInfo{},
			RuntimeArgs:       []signerapi.RuntimeArgInfo{},
		}

		for _, p := range tmpl.CreationParams() {
			info.CreationParams = append(info.CreationParams, signerapi.CreationParamInfo{
				Name:        p.Name,
				Label:       p.Label,
				Description: p.Description,
				Type:        p.Type,
				Required:    p.Required,
				MaxLength:   p.MaxLength,
				InputModes:  restInputModeInfos(p.InputModes),
				MinItems:    p.MinItems,
				MaxItems:    p.MaxItems,
				Example:     p.Example,
				Placeholder: p.Placeholder,
				Min:         p.Min,
				Max:         p.Max,
				Default:     p.Default,
			})
		}

		for _, a := range tmpl.RuntimeArgs() {
			info.RuntimeArgs = append(info.RuntimeArgs, signerapi.RuntimeArgInfo{
				Name:        a.Name,
				Label:       a.Label,
				Description: a.Description,
				Type:        a.Type,
				Required:    a.Required,
				ByteLength:  a.ByteLength,
				MaxSize:     a.MaxSize,
			})
		}

		keyTypes = append(keyTypes, info)
	}

	return keyTypes
}

type boundedInventoryProvider interface {
	BoundedAuthorizationMetadata() *boundedmeta.Metadata
}

func boundedSigningFlow(metadata *boundedmeta.Metadata) string {
	if metadata != nil && metadata.Cosigner != nil {
		return signerapi.SigningFlowBoundedCosigner1
	}
	return signerapi.SigningFlowBounded1
}

func boundedInfo(metadata *boundedmeta.Metadata) *signerapi.BoundedAuthorizationInfo {
	if metadata == nil {
		return nil
	}
	info := &signerapi.BoundedAuthorizationInfo{
		Contract: metadata.Contract,
		BaseSignatureArgLayout: signerapi.BoundedSignatureArgLayout{
			Count:    metadata.BaseSignatureArgLayout.Count,
			MaxSizes: append([]int(nil), metadata.BaseSignatureArgLayout.MaxSizes...),
		},
		SpendEffects:      append([]string(nil), metadata.SpendEffects...),
		MaxFee:            metadata.MaxFee,
		Layer3Policy:      metadata.Layer3Policy,
		AdminKeyID:        metadata.AdminKeyID,
		ProgramBindingHex: metadata.ProgramBindingHex,
	}
	if metadata.Cosigner != nil {
		info.Cosigner = &signerapi.BoundedCosignerAuthorizationInfo{
			Contract: metadata.Cosigner.Contract, ComponentKeyType: metadata.Cosigner.ComponentKeyType,
			PublicKeyHex: metadata.Cosigner.PublicKeyHex, ComponentKeyID: metadata.Cosigner.ComponentKeyID,
			SignatureMaxSize: metadata.Cosigner.SignatureMaxSize,
			RequiredOn:       append([]string(nil), metadata.Cosigner.RequiredOn...),
		}
	}
	for _, arg := range metadata.DerivedArgs {
		info.DerivedArgs = append(info.DerivedArgs, signerapi.BoundedDerivedArgInfo{
			Name: arg.Name, Kind: arg.Kind, Parameter: arg.Parameter, MaxSize: arg.MaxSize,
		})
	}
	for _, arg := range metadata.RuntimeArgs {
		info.RuntimeArgs = append(info.RuntimeArgs, signerapi.RuntimeArgInfo{
			Name: arg.Name, Label: arg.Label, Description: arg.Description, Type: arg.Type,
			Required: arg.Required, ByteLength: arg.ByteLength, MaxSize: arg.MaxSize,
		})
	}
	for _, slot := range metadata.ArgumentLayout {
		info.ArgumentLayout = append(info.ArgumentLayout, signerapi.BoundedArgumentSlotInfo{
			Index: slot.Index, Name: slot.Name, Source: slot.Source, MaxSize: slot.MaxSize,
			Paths: signerapi.BoundedArgumentPathMask{
				Spend: slot.Paths.Spend, SpendingRekey: slot.Paths.SpendingRekey, AdminRekey: slot.Paths.AdminRekey,
			},
		})
	}
	if info.DerivedArgs == nil {
		info.DerivedArgs = []signerapi.BoundedDerivedArgInfo{}
	}
	if info.RuntimeArgs == nil {
		info.RuntimeArgs = []signerapi.RuntimeArgInfo{}
	}
	if info.ArgumentLayout == nil {
		info.ArgumentLayout = []signerapi.BoundedArgumentSlotInfo{}
	}
	for _, operation := range metadata.AdminOperations {
		info.AdminOperations = append(info.AdminOperations, signerapi.BoundedAdminOperationInfo{
			Kind: operation.Kind, Authorization: operation.Authorization, PolicyGate: operation.PolicyGate,
		})
	}
	if info.AdminOperations == nil {
		info.AdminOperations = []signerapi.BoundedAdminOperationInfo{}
	}
	return info
}

func applyCosignerReferenceParams(ir *productruntime.Runtime, infos []signerapi.KeyTypeInfo) {
	if ir == nil {
		return
	}
	refs, err := cosignerrefs.List(ir.KeyPaths())
	if err != nil || len(refs) == 0 {
		return
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
		componentType := infos[i].CosignerComponentKeyType
		if componentType == "" {
			continue
		}
		componentIDs := componentIDsByType[componentType]
		if len(componentIDs) == 0 {
			continue
		}
		cosignerParam := signerapi.CreationParamInfo{
			Name:        cosignerrefs.ParamCosignerName,
			Label:       "Witness Key ID",
			Description: "Imported Witness Key ID to embed in the guarded account",
			Type:        "select",
			Required:    true,
			Options:     append([]string(nil), componentIDs...),
			Default:     componentIDs[0],
		}
		infos[i].CreationParams = replaceCosignerPublicKeyParam(infos[i].CreationParams, cosignerParam)
	}
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
		return nil, &signersigning.ServiceError{Kind: signersigning.ErrorInternal, Message: "failed to read key type activations"}
	}
	return &signerapi.KeyTypesResponse{KeyTypes: keyTypes}, nil
}
