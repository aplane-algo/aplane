// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/aplane-algo/aplane/internal/appresult"
	"github.com/aplane-algo/aplane/internal/cmdspec"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/keytypefmt"
	"github.com/aplane-algo/aplane/internal/signerapi"
)

// GenerateKeyRequest captures parsed generate-command inputs.
type GenerateKeyRequest struct {
	KeyType string
	Params  map[string]string
}

// DeleteKeyRequest captures parsed delete-command inputs.
type DeleteKeyRequest struct {
	Address string
}

// DeleteKeyTarget describes the resolved key targeted for deletion.
type DeleteKeyTarget struct {
	Address string
}

// Signers refreshes signer state and returns all signable accounts.
func (a *App) Signers(ctx context.Context) (*SignersCommandResult, error) {
	refreshedKeys, err := a.eng.RefreshKeysWithContext(ctx)
	if err != nil {
		return nil, err
	}
	refreshedByAddress := make(map[string]engine.KeyInfo, len(refreshedKeys))
	for _, key := range refreshedKeys {
		refreshedByAddress[key.Address] = key
	}

	addresses := a.eng.GetSignableAddresses()
	keys := make([]appresult.KeyInfo, len(addresses))
	for i, addr := range addresses {
		refreshed := refreshedByAddress[addr]
		keys[i] = appresult.KeyInfo{
			Address:                  addr,
			KeyType:                  a.eng.GetKeyType(addr),
			TemplateProvenanceStatus: refreshed.TemplateProvenanceStatus,
			TemplateProvenanceNote:   refreshed.TemplateProvenanceNote,
		}
	}

	return &SignersCommandResult{
		Keys: appresult.Keys{Keys: keys},
	}, nil
}

// KeyTypes returns the available signer key types.
func (a *App) KeyTypes(ctx context.Context) (*KeyTypesCommandResult, error) {
	keyTypes, err := a.eng.ListKeyTypesWithContext(ctx)
	if err != nil {
		return nil, err
	}
	return &KeyTypesCommandResult{KeyTypes: keyTypes}, nil
}

// GenerateKey resolves address-list creation params and generates a signer key.
func (a *App) GenerateKey(ctx context.Context, req GenerateKeyRequest) (*GenerateKeyCommandResult, error) {
	// Resolve an elided default-publisher key type (e.g. "falcon1024-whitelist.v1")
	// to its canonical form before any lookup or storage.
	req.KeyType = keytypefmt.Canonicalize(req.KeyType)

	keyTypes, err := a.eng.ListKeyTypesWithContext(ctx)
	if err != nil {
		return nil, err
	}

	params, err := ExpandGenerateAddressListParams(req.KeyType, req.Params, keyTypes, a.eng.NewAddressResolver())
	if err != nil {
		return nil, err
	}

	result, err := a.eng.GenerateKeyWithContext(ctx, req.KeyType, params)
	if err != nil {
		return nil, err
	}
	return generateKeyCommandResultFromEngine(result), nil
}

// DeleteKey resolves the provided address or alias and deletes the corresponding key.
func (a *App) DeleteKey(ctx context.Context, req DeleteKeyRequest) error {
	address, _, err := a.eng.ResolveAddress(req.Address)
	if err != nil {
		return err
	}
	return a.eng.DeleteKeyWithContext(ctx, address)
}

// ResolveDeleteKeyTarget resolves the provided address or alias for prompt/display use.
func (a *App) ResolveDeleteKeyTarget(_ context.Context, req DeleteKeyRequest) (*DeleteKeyTarget, error) {
	address, _, err := a.eng.ResolveAddress(req.Address)
	if err != nil {
		return nil, err
	}
	return &DeleteKeyTarget{Address: address}, nil
}

// ExpandGenerateAddressListParams resolves address[] creation params through the address resolver.
func ExpandGenerateAddressListParams(
	keyType string,
	params map[string]string,
	keyTypes []signerapi.KeyTypeInfo,
	resolver cmdspec.AddressListResolver,
) (map[string]string, error) {
	if len(params) == 0 {
		return params, nil
	}

	addressListParams, err := addressListCreationParams(keyType, keyTypes)
	if err != nil {
		return nil, err
	}
	if len(addressListParams) == 0 {
		return params, nil
	}

	expanded := make(map[string]string, len(params))
	for name, value := range params {
		if slices.Contains(addressListParams, name) {
			parts := splitAddressListParam(value)
			addresses, err := resolver.ResolveList(parts)
			if err != nil {
				return nil, fmt.Errorf("failed to resolve %s %q: %w", name, value, err)
			}
			sort.Strings(addresses)
			expanded[name] = strings.Join(addresses, ",")
			continue
		}
		expanded[name] = value
	}

	return expanded, nil
}

func splitAddressListParam(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item == "" {
			continue
		}
		out = append(out, item)
	}
	return out
}

func addressListCreationParams(keyType string, keyTypes []signerapi.KeyTypeInfo) ([]string, error) {
	for _, kt := range keyTypes {
		if kt.KeyType != keyType {
			continue
		}
		var names []string
		for _, param := range kt.CreationParams {
			if param.Type == "address[]" {
				names = append(names, param.Name)
			}
		}
		return names, nil
	}
	return nil, fmt.Errorf("unknown key type: %s", keyType)
}
