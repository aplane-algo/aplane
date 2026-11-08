// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/appresult"
	"github.com/aplane-algo/aplane/internal/engine"
)

// GenerateKeyRequest captures parsed generate-command inputs.
type GenerateKeyRequest struct {
	KeyType string
	Params  map[string]string
}

// Generation flags apshell reads itself. They are flags, not key=value
// parameters, so they never collide with a signer parameter of the same name
// and need no lookup to tell apart.
const (
	GenerateFlagBoundaryFile = "--boundary"
	GenerateFlagResultFile   = "--result"
)

// GenerateOptions are the apshell-side choices taken out of generate's arguments.
type GenerateOptions struct {
	BoundaryFile    string
	HasBoundaryFile bool
	ResultFile      string
}

// SplitGenerateOptions takes apshell's own flags out of generate's arguments,
// as --flag=value or --flag value, and returns the rest. Any other argument
// starting with -- is refused, so a mistyped flag is not sent to the signer.
func SplitGenerateOptions(args []string) (GenerateOptions, []string, error) {
	var options GenerateOptions
	rest := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "--") {
			rest = append(rest, arg)
			continue
		}
		name, value, hasValue := strings.Cut(arg, "=")
		if name != GenerateFlagBoundaryFile && name != GenerateFlagResultFile {
			return GenerateOptions{}, nil, fmt.Errorf("unknown flag %s (generate takes %s and %s)", name, GenerateFlagBoundaryFile, GenerateFlagResultFile)
		}
		if !hasValue {
			if i+1 >= len(args) {
				return GenerateOptions{}, nil, fmt.Errorf("%s needs a file", name)
			}
			i++
			value = args[i]
		}
		if strings.TrimSpace(value) == "" {
			return GenerateOptions{}, nil, fmt.Errorf("%s needs a file", name)
		}
		switch name {
		case GenerateFlagBoundaryFile:
			if options.HasBoundaryFile {
				return GenerateOptions{}, nil, fmt.Errorf("%s is given twice", name)
			}
			options.BoundaryFile, options.HasBoundaryFile = value, true
		case GenerateFlagResultFile:
			if options.ResultFile != "" {
				return GenerateOptions{}, nil, fmt.Errorf("%s is given twice", name)
			}
			options.ResultFile = value
		}
	}
	return options, rest, nil
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
