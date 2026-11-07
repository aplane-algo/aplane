// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

// Key management commands: generate, delete

import (
	"fmt"
	"io"
	"strings"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/boundary"
	"github.com/aplane-algo/aplane/internal/cmdspec"
	"github.com/aplane-algo/aplane/internal/command"
	"github.com/aplane-algo/aplane/internal/keytypefmt"
)

func (r *REPLState) cmdGenerate(args []string, _ interface{}) (command.Result, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("usage: generate <key_type> [param=value ...]")
	}

	keyType := args[0]
	positional, params, err := cmdspec.ParseKeyValueArgs(args[1:])
	if err != nil {
		return nil, err
	}
	if len(positional) > 0 {
		return nil, fmt.Errorf("invalid parameter %q (expected param=value)", positional[0])
	}

	options, err := r.app().TakeGenerateOptions(r.commandContext(), keyType, params)
	if err != nil {
		return nil, err
	}

	var result *apshellapp.GenerateKeyCommandResult
	if options.HasBoundaryFile {
		if len(params) != 0 {
			return nil, fmt.Errorf("a boundary file sets every parameter; remove the others")
		}
		var cancelled bool
		result, cancelled, err = r.generateFromBoundary(keyType, options.BoundaryFile)
		if err != nil {
			return nil, err
		}
		if cancelled {
			return newShellCommandResult(func(w io.Writer) error {
				_, err := fmt.Fprintln(w, "Cancelled.")
				return err
			}, generatedKeyProjection{KeyType: keyType})
		}
	} else {
		result, err = r.app().GenerateKey(r.commandContext(), apshellapp.GenerateKeyRequest{KeyType: keyType, Params: params})
		if err != nil {
			return nil, err
		}
	}
	if options.ResultFile != "" {
		if err := apshellapp.WriteGenerationResult(options.ResultFile, result); err != nil {
			return nil, fmt.Errorf("generated %s, but %w", result.Address, err)
		}
	}
	return newShellCommandResult(func(w io.Writer) error {
		return r.withOutput(w, func() {
			r.printf("Generated %s key: %s\n", keytypefmt.Display(result.KeyType), result.Address)
			renderResolvedGeneration(r, result)
		})
	}, generatedKeyProjection{
		KeyType: result.KeyType, Address: result.Address, Parameters: result.Parameters,
		AdminKeyID: result.AdminKeyID, CosignerKeyID: result.CosignerKeyID,
	})
}

// generateFromBoundary shows the local summary and creates the account. Interactive
// review is not an authorization: the signer checks every request regardless, so
// unattended callers skip the prompt.
func (r *REPLState) generateFromBoundary(keyType, path string) (*apshellapp.GenerateKeyCommandResult, bool, error) {
	preview, err := r.app().PreviewBoundaryFile(keyType, path)
	if err != nil {
		return nil, false, err
	}
	if !r.AutoConfirm {
		renderBoundaryPreview(r, preview)
		response, err := r.readPromptResponse("Create this account? (y/N): ")
		if err != nil {
			return nil, false, err
		}
		if response != "y" && response != "yes" {
			return nil, true, nil
		}
	}
	result, err := r.app().GenerateFromBoundary(r.commandContext(), preview)
	return result, false, err
}

// renderBoundaryPreview labels itself as local, because the guarantee differs from
// apadmin's review: the signer has not confirmed any of this yet.
func renderBoundaryPreview(r *REPLState, preview *apshellapp.BoundaryPreview) {
	r.println("Local summary. The signer has not confirmed this.")
	r.printf("  Transfers:  %s\n", strings.Join(preview.Transfers, ", "))
	if preview.Recipients > 0 {
		r.printf("  Recipients: %d, encoding %s, list %s\n", preview.Recipients, preview.Encoding, preview.ListDigest[:12])
	} else {
		r.println("  Recipients: any, once unlocked")
	}
	if preview.UnlockRound != "" {
		r.printf("  Unlocks at: round %s, on the network this signer uses\n", preview.UnlockRound)
	}
	switch {
	case preview.AdminKeyID != "":
		r.printf("  Rekey:      spending key plus contract admin %s\n", preview.AdminKeyID)
	case preview.UnlockRound != "":
		r.println("  Rekey:      spending key alone, after the unlock round")
	default:
		r.println("  Rekey:      spending key alone, which can rekey out of this boundary")
	}
	switch {
	case preview.Cosigner == "":
		r.println("  Cosigner:   none")
	case preview.CosignerIsKey:
		r.printf("  Cosigner:   Witness Key ID %s\n", preview.Cosigner)
	default:
		r.printf("  Cosigner:   %q is unresolved. The signer resolves this name during creation,\n", preview.Cosigner)
		r.println("              so an edited reference changes the authority. Prefer a Witness Key ID.")
	}
}

// renderResolvedGeneration shows what the signer actually created. It comes after
// creation, so it is a record and not an approval.
func renderResolvedGeneration(r *REPLState, result *apshellapp.GenerateKeyCommandResult) {
	if result.AdminKeyID != "" {
		r.printf("  Contract admin: %s\n", result.AdminKeyID)
	}
	if result.CosignerKeyID != "" {
		r.printf("  Cosigner:       %s\n", result.CosignerKeyID)
	}
	if encoding := result.Parameters[boundary.ParameterListEncoding]; encoding != "" {
		r.printf("  List encoding:  %s\n", encoding)
	}
	if round := result.Parameters[boundary.ParameterUnlockRound]; round != "" {
		r.printf("  Unlock round:   %s\n", round)
	}
}

func (r *REPLState) cmdDelete(args []string, _ interface{}) (command.Result, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("usage: delete <address>")
	}

	target, err := r.app().ResolveDeleteKeyTarget(r.commandContext(), apshellapp.DeleteKeyRequest{Address: args[0]})
	if err != nil {
		return nil, err
	}

	if !r.AutoConfirm {
		response, err := r.readDeleteKeyResponse(target.Address)
		if err != nil {
			return nil, err
		}
		if response != "y" && response != "yes" {
			return newShellCommandResult(func(w io.Writer) error {
				_, err := fmt.Fprintln(w, "Cancelled.")
				return err
			}, deletedKeyProjection{Address: target.Address, Cancelled: true})
		}
	}

	if err := r.app().DeleteKey(r.commandContext(), apshellapp.DeleteKeyRequest{Address: args[0]}); err != nil {
		return nil, err
	}
	return newShellCommandResult(func(w io.Writer) error {
		_, err := fmt.Fprintln(w, "Key deleted.")
		return err
	}, deletedKeyProjection{Address: target.Address, Deleted: true})
}
