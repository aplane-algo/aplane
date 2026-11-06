// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"

	"github.com/aplane-algo/aplane/internal/appresult"
	"github.com/aplane-algo/aplane/internal/boundary"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/keytypecatalog"
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

// TakeGenerateOptions removes apshell's own options from params. It applies only
// to aplane.falcon1024-b.v1, whose closed parameter list contains neither name. Any
// other type's parameters are the signer's, and a template can legally declare a
// parameter called boundary or result, so they must pass through untouched.
func TakeGenerateOptions(keyType string, params map[string]string) GenerateOptions {
	if keytypecatalog.Canonicalize(keyType) != boundary.KeyTypeV1 {
		return GenerateOptions{}
	}
	options := GenerateOptions{ResultFile: params[GenerateOptionResultFile]}
	options.BoundaryFile, options.HasBoundaryFile = params[GenerateOptionBoundaryFile]
	delete(params, GenerateOptionBoundaryFile)
	delete(params, GenerateOptionResultFile)
	return options
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
