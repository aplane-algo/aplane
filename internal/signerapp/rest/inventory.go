// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rest

import (
	"sort"
	"strings"

	"github.com/aplane-algo/aplane/internal/algorithm"
	"github.com/aplane-algo/aplane/internal/attestor/attrefs"
	"github.com/aplane-algo/aplane/internal/attestor/keytypes"
	"github.com/aplane-algo/aplane/internal/genericlsig"
	"github.com/aplane-algo/aplane/internal/keyclass"
	"github.com/aplane-algo/aplane/internal/keymgmt"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	signersigning "github.com/aplane-algo/aplane/internal/signerapp/signing"
)

func (s Service) BuildKeyInfoList(ir *identity.Runtime) []signerapi.KeyInfo {
	if ir == nil {
		return []signerapi.KeyInfo{}
	}
	ks := ir.KeyStore()
	if ks == nil {
		return []signerapi.KeyInfo{}
	}

	keysCopy, keyTypesCopy, lsigSizesCopy := ir.KeySnapshot()
	publicKeyHexMap := ks.GetPublicKeyHexMap()
	signingSummary := ks.GetSigningSummary()

	keyList := make([]signerapi.KeyInfo, 0, len(keysCopy))
	for address := range keysCopy {
		keyType := keyTypesCopy[address]
		summary := signingSummary[address]
		category := summary.Category
		isGeneric := category == keys.CategoryGenericLsig || (category == "" && keys.IsGenericLSigType(keyType))
		isComponent := keys.IsComponentKey(category, keyType)

		keyInfo := signerapi.KeyInfo{
			Address:       address,
			PublicKeyHex:  publicKeyHexMap[address],
			KeyType:       keyType,
			LsigSize:      lsigSizesCopy[address],
			IsGenericLsig: isGeneric,
		}
		if isComponent {
			spending := false
			keyInfo.IsComponentKey = true
			keyInfo.IsSpendingAccount = &spending
		}
		if keytypes.IsAttestedAccountKeyType(keyType) {
			keyInfo.Parameters = attestedAccountParameters(summary.Parameters)
		}
		keyInfo.TemplateProvenanceStatus, keyInfo.TemplateProvenanceNote = keys.CompareTemplateFingerprint(keyType, summary.TemplateFingerprint)

		if summary.SigningMetadataVersion > 0 {
			keyInfo.SigningArgs = signingArgInfos(summary.SigningArgs)
		}

		keyList = append(keyList, keyInfo)
	}

	return keyList
}

func attestedAccountParameters(parameters map[string]string) map[string]string {
	attestorPublicKey := parameters[keytypes.ParameterAttestorPublicKey]
	if attestorPublicKey == "" {
		return nil
	}
	return map[string]string{
		keytypes.ParameterAttestorPublicKey: attestorPublicKey,
	}
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
		}
	}
	return out
}

func (s Service) Keys(ir *identity.Runtime) (*signerapi.KeysResponse, *signersigning.ServiceError) {
	if ir == nil {
		return nil, &signersigning.ServiceError{Kind: signersigning.ErrorInternal, Message: "identity runtime is nil"}
	}
	if !ir.IsUnlocked() {
		return nil, &signersigning.ServiceError{Kind: signersigning.ErrorForbidden, Message: "signer is locked"}
	}

	keyList := s.BuildKeyInfoList(ir)
	return &signerapi.KeysResponse{
		Count: len(keyList),
		Keys:  keyList,
	}, nil
}

func (s Service) BuildKeyTypes() []signerapi.KeyTypeInfo {
	return s.buildKeyTypes(keymgmt.GetValidKeyTypes(), nil)
}

func (s Service) BuildKeyTypesForIdentity(ir *identity.Runtime) ([]signerapi.KeyTypeInfo, error) {
	validTypes, err := keymgmt.GetValidKeyTypesForIdentity(ir.KeyPaths(), ir.ID())
	if err != nil {
		return nil, err
	}
	validTypes = filterKeyTypesForNodeRole(validTypes, ir.NodeRole())
	enabled, err := keytypestate.ListEnabled(ir.KeyPaths(), ir.ID())
	if err != nil {
		return nil, err
	}
	infos := s.buildKeyTypes(validTypes, enabled)
	applyAttestorReferenceParams(ir, infos)
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

		if keytypes.IsAttestorComponentKeyType(keyType) {
			info.Family, info.DisplayName, info.Description = attestorComponentKeyTypeMetadata(keyType)
			keyTypes = append(keyTypes, info)
			continue
		}

		meta, err := algorithm.GetMetadata(keyType)
		if err == nil {
			info.Family = meta.Family()
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
				})
			}
		} else {
			info.DisplayName = strings.ToUpper(keyType[:1]) + keyType[1:]
			info.Description = "Native Algorand signing keys"
		}

		keyTypes = append(keyTypes, info)
	}

	enabledGenericSet := make(map[string]bool, len(enabledGeneric))
	for _, keyType := range enabledGeneric {
		enabledGenericSet[strings.ToLower(strings.TrimSpace(keyType))] = true
	}
	for _, tmpl := range genericlsig.GetAll() {
		// Generic template providers are process-global once registered, but
		// identity inventory is gated by the identity-local installed/enabled set.
		if enabledGeneric != nil && !enabledGenericSet[strings.ToLower(strings.TrimSpace(tmpl.KeyType()))] {
			continue
		}
		info := signerapi.KeyTypeInfo{
			KeyType:          tmpl.KeyType(),
			Family:           tmpl.Family(),
			DisplayName:      tmpl.DisplayName(),
			Description:      tmpl.Description(),
			RequiresLogicSig: true,
			CreationParams:   []signerapi.CreationParamInfo{},
			RuntimeArgs:      []signerapi.RuntimeArgInfo{},
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
			})
		}

		keyTypes = append(keyTypes, info)
	}

	return keyTypes
}

func applyAttestorReferenceParams(ir *identity.Runtime, infos []signerapi.KeyTypeInfo) {
	if ir == nil {
		return
	}
	refs, err := attrefs.List(ir.KeyPaths(), ir.ID())
	if err != nil || len(refs) == 0 {
		return
	}

	namesByComponentType := make(map[string][]string)
	for _, ref := range refs {
		namesByComponentType[ref.KeyType] = append(namesByComponentType[ref.KeyType], ref.Name)
	}
	for componentType := range namesByComponentType {
		names := namesByComponentType[componentType]
		sort.Strings(names)
		namesByComponentType[componentType] = names
	}

	for i := range infos {
		componentType, ok := keytypes.AttestorComponentKeyTypeForAttestedAccount(infos[i].KeyType)
		if !ok {
			continue
		}
		names := namesByComponentType[componentType]
		if len(names) == 0 {
			continue
		}
		infos[i].CreationParams = []signerapi.CreationParamInfo{{
			Name:        attrefs.ParamAttestorName,
			Label:       "Attestor",
			Description: "Imported attestor public-key reference to embed in the attested account",
			Type:        "select",
			Required:    true,
			Options:     append([]string(nil), names...),
			Default:     names[0],
		}}
	}
}

func attestorComponentKeyTypeMetadata(keyType string) (family, displayName, description string) {
	switch keyType {
	case keytypes.AttestorComponentEd25519V1:
		return "sentry-ed25519", "Attestor Ed25519 component key", "Raw Ed25519 attestor component signing key"
	case keytypes.AttestorComponentFalcon1024V1:
		return "sentry-falcon1024", "Attestor Falcon-1024 component key", "Raw Falcon-1024 attestor component signing key"
	default:
		return keyType, keyType, "Raw attestor component signing key"
	}
}

func (s Service) KeyTypes() *signerapi.KeyTypesResponse {
	return &signerapi.KeyTypesResponse{KeyTypes: s.BuildKeyTypes()}
}

func (s Service) KeyTypesForIdentity(ir *identity.Runtime) (*signerapi.KeyTypesResponse, *signersigning.ServiceError) {
	if ir == nil {
		return nil, &signersigning.ServiceError{Kind: signersigning.ErrorInternal, Message: "identity runtime is nil"}
	}
	keyTypes, err := s.BuildKeyTypesForIdentity(ir)
	if err != nil {
		return nil, &signersigning.ServiceError{Kind: signersigning.ErrorInternal, Message: "failed to read key type activations"}
	}
	return &signerapi.KeyTypesResponse{KeyTypes: keyTypes}, nil
}
