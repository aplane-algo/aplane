// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/aplane-algo/aplane/internal/boundary"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/witness"
)

// BoundaryPreview is what a boundary file asks for, read on this machine. It is a
// local summary and not a review: the signer has not seen it, so a cosigner name
// here is only a name until the signer resolves it during creation.
type BoundaryPreview struct {
	Parameters    map[string]string
	Transfers     []string
	Recipients    int
	ListDigest    string
	Encoding      string
	UnlockRound   string
	Rekey         string
	AdminKeyID    string
	Cosigner      string
	CosignerIsKey bool
}

// PreviewBoundaryFile reads a boundary file and summarizes it locally.
func (a *App) PreviewBoundaryFile(path string) (*BoundaryPreview, error) {
	parameters, err := boundary.LoadFile(path)
	if err != nil {
		return nil, err
	}
	preview := &BoundaryPreview{
		Parameters:  parameters,
		Transfers:   strings.Split(parameters[boundary.ParameterSpendEffects], ","),
		UnlockRound: parameters[boundary.ParameterUnlockRound],
		Rekey:       parameters[boundary.ParameterRekeyAuthority],
		Cosigner:    parameters[boundary.ParameterCosigner],
	}
	if list := parameters[boundary.ParameterRecipients]; list != "" {
		preview.Recipients = len(strings.Split(list, ","))
		preview.ListDigest = boundary.RecipientListDigest(list)
		preview.Encoding = parameters[boundary.ParameterListEncoding]
		if preview.Encoding == "" {
			preview.Encoding = boundary.EncodingAuto
		}
	}
	if preview.AdminKeyID, err = boundary.AdminKeyID(parameters); err != nil {
		return nil, fmt.Errorf("identify contract admin key: %w", err)
	}
	if preview.Cosigner != "" {
		if normalized, err := witness.NormalizeID(preview.Cosigner); err == nil {
			preview.Cosigner, preview.CosignerIsKey = normalized, true
			preview.Parameters[boundary.ParameterCosigner] = normalized
		}
	}
	return preview, nil
}

// GenerateFromBoundary creates the previewed account. The values are already
// literal, so they skip this client's alias expansion. A stable Witness Key ID can
// only select that authority, and the signer's answer is checked against it.
func (a *App) GenerateFromBoundary(ctx context.Context, preview *BoundaryPreview) (*GenerateKeyCommandResult, error) {
	result, err := a.eng.GenerateKeyFromLiterals(ctx, boundary.KeyTypeV1, preview.Parameters)
	if err != nil {
		return nil, err
	}
	if preview.CosignerIsKey {
		if err := confirmCosigner(result, preview.Cosigner); err != nil {
			return nil, err
		}
	}
	return generateResultFromEngine(result), nil
}

// confirmCosigner checks the account against the requested Witness Key ID. An ID
// that cannot be read back is reported rather than passed: the point of asking for a
// stable ID is to know which authority was used.
func confirmCosigner(result *engine.GenerateKeyResult, requested string) error {
	if !result.InventoryRead {
		return fmt.Errorf("generated %s, but could not read it back to confirm its cosigner is %s; check with keys before funding it", result.Address, requested)
	}
	if result.CosignerKeyID != requested {
		return fmt.Errorf("generated %s, but its cosigner is %q, not the requested %s; do not fund this account", result.Address, result.CosignerKeyID, requested)
	}
	return nil
}

// generateResultFromEngine carries the signer's own authority IDs. apshell does not
// derive them: it would need to know each key type's identity rules, and the daemon
// that resolved the request is the better witness to what it resolved.
func generateResultFromEngine(result *engine.GenerateKeyResult) *GenerateKeyCommandResult {
	return &GenerateKeyCommandResult{
		KeyType: result.KeyType, Address: result.Address, Parameters: result.Parameters,
		AdminKeyID: result.AdminKeyID, CosignerKeyID: result.CosignerKeyID,
	}
}

// GenerationResultSchemaV1 identifies an apshell generation result. It is deliberately
// not a receipt: HTTP generation returns no grammar fingerprint or boundary digest,
// so this holds only what the signer returned and what can be computed from it.
const GenerationResultSchemaV1 = "aplane.generation-result.v1"

// WriteGenerationResult saves a result as public JSON. It refuses to overwrite, so
// a file on disk always names the account it was written for.
func WriteGenerationResult(path string, result *GenerateKeyCommandResult) error {
	encoded, err := json.MarshalIndent(struct {
		Schema        string            `json:"schema"`
		Address       string            `json:"address"`
		KeyType       string            `json:"key_type"`
		Parameters    map[string]string `json:"parameters"`
		AdminKeyID    string            `json:"admin_key_id,omitempty"`
		CosignerKeyID string            `json:"cosigner_key_id,omitempty"`
	}{GenerationResultSchemaV1, result.Address, result.KeyType, result.Parameters, result.AdminKeyID, result.CosignerKeyID}, "", "  ")
	if err != nil {
		return fmt.Errorf("encode generation result: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("save generation result: %w", err)
	}
	_, writeErr := file.Write(append(encoded, '\n'))
	if closeErr := file.Close(); writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		return fmt.Errorf("save generation result: %w", writeErr)
	}
	return nil
}
