// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"fmt"
	"slices"

	"github.com/aplane-algo/aplane/internal/appresult"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/keytypecatalog"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// GenerateKeyRequest captures parsed generate-command inputs.
type GenerateKeyRequest struct {
	KeyType string
	Params  map[string]string
}

// Generation options apshell reads itself for the general bounded type.
const (
	GenerateOptionBoundaryFile = "boundary"
	GenerateOptionResultFile   = "result"
)

// GenerateOptions are the apshell-side choices taken out of generate's parameters.
type GenerateOptions struct {
	BoundaryFile    string
	HasBoundaryFile bool
	ResultFile      string
}

// TakeGenerateOptions removes apshell's own options from params, for a key type the
// signer reports as per-key. Such a type's closed parameter list contains neither
// name. Any other type's parameters are the signer's, and a template can legally
// declare a parameter called boundary or result, so they pass through untouched.
//
// Telling those apart takes the signer's inventory. A failed or incomplete lookup is
// not an answer that the type is ordinary, so it stops here, before either name is
// interpreted or forwarded and before any generation request. A request with neither
// name has nothing to tell apart, so it needs no lookup and can't fail on one.
func (a *App) TakeGenerateOptions(ctx context.Context, keyType string, params map[string]string) (GenerateOptions, error) {
	return takeGenerateOptions(keyType, params, func() ([]signerapi.KeyTypeInfo, error) {
		return a.eng.ListKeyTypes(ctx)
	})
}

func takeGenerateOptions(keyType string, params map[string]string, inventory func() ([]signerapi.KeyTypeInfo, error)) (GenerateOptions, error) {
	boundaryFile, hasBoundaryFile := params[GenerateOptionBoundaryFile]
	resultFile, hasResultFile := params[GenerateOptionResultFile]
	if !hasBoundaryFile && !hasResultFile {
		return GenerateOptions{}, nil
	}
	keyTypes, err := inventory()
	if err != nil {
		return GenerateOptions{}, fmt.Errorf("read the signer's key types to interpret %s and %s: %w", GenerateOptionBoundaryFile, GenerateOptionResultFile, err)
	}
	canonical := keytypecatalog.Canonicalize(keyType)
	index := slices.IndexFunc(keyTypes, func(info signerapi.KeyTypeInfo) bool { return info.KeyType == canonical })
	if index < 0 {
		return GenerateOptions{}, fmt.Errorf("the signer does not report key type %q, so %s and %s cannot be interpreted", canonical, GenerateOptionBoundaryFile, GenerateOptionResultFile)
	}
	if !keyTypes[index].PerKeyContract {
		return GenerateOptions{}, nil
	}
	delete(params, GenerateOptionBoundaryFile)
	delete(params, GenerateOptionResultFile)
	return GenerateOptions{BoundaryFile: boundaryFile, HasBoundaryFile: hasBoundaryFile, ResultFile: resultFile}, nil
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
	refreshedKeys, err := a.eng.RefreshKeys(ctx)
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
			PolicyLabel:              refreshed.PolicyLabel,
		}
	}

	return &SignersCommandResult{
		Keys: appresult.Keys{Keys: keys},
	}, nil
}

// KeyTypes returns the available signer key types.
func (a *App) KeyTypes(ctx context.Context) (*KeyTypesCommandResult, error) {
	keyTypes, err := a.eng.ListKeyTypes(ctx)
	if err != nil {
		return nil, err
	}
	return &KeyTypesCommandResult{KeyTypes: keyTypes}, nil
}

// GenerateKey generates a signer key. Key-type canonicalization and address-list
// creation-param resolution (e.g. an allowlist's "recipients") are performed by
// the engine (engine.GenerateKey) so every entry point — REPL, JS, MCP —
// behaves identically.
func (a *App) GenerateKey(ctx context.Context, req GenerateKeyRequest) (*GenerateKeyCommandResult, error) {
	result, err := a.eng.GenerateKey(ctx, req.KeyType, req.Params)
	if err != nil {
		return nil, err
	}
	return generateResultFromEngine(result), nil
}

// DeleteKey resolves the provided address or alias and deletes the corresponding key.
func (a *App) DeleteKey(ctx context.Context, req DeleteKeyRequest) error {
	address, _, err := a.eng.ResolveAddress(req.Address)
	if err != nil {
		return err
	}
	return a.eng.DeleteKey(ctx, address)
}

// ResolveDeleteKeyTarget resolves the provided address or alias for prompt/display use.
func (a *App) ResolveDeleteKeyTarget(_ context.Context, req DeleteKeyRequest) (*DeleteKeyTarget, error) {
	address, _, err := a.eng.ResolveAddress(req.Address)
	if err != nil {
		return nil, err
	}
	return &DeleteKeyTarget{Address: address}, nil
}
