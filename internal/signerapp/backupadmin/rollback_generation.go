// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backupadmin

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/templatestore"
)

// rollbackGenerationSource holds the exact authenticated manifest and seal
// buffers whose inventory is reconstructed. Member reads are checked against
// this seal before their bytes are copied or opened.
type rollbackGenerationSource struct {
	gen           storepaths.GenPaths
	seal          *genstore.Seal
	anchor        *crypto.HistoricalGenerationAnchor
	sealBytes     []byte
	manifestBytes []byte
}

func loadRollbackGenerationSource(
	gen storepaths.GenPaths,
	kr *crypto.Keyring,
) (*rollbackGenerationSource, error) {
	sealBytes, _, err := fsutil.ReadRegularFile(gen.SealPath())
	if err != nil {
		return nil, fmt.Errorf("read rollback source seal: %w", err)
	}
	manifestBytes, _, err := fsutil.ReadRegularFile(gen.ManifestPath())
	if err != nil {
		return nil, fmt.Errorf("read rollback source manifest: %w", err)
	}
	source := &rollbackGenerationSource{
		gen:           gen,
		sealBytes:     sealBytes,
		manifestBytes: manifestBytes,
	}
	if anchor, ok := kr.HistoricalGenerationAnchor(gen.GenerationID()); ok {
		seal, err := genstore.ParseAnchoredSealBytes(
			gen,
			anchor,
			sealBytes,
			manifestBytes,
			kr,
		)
		if err != nil {
			return nil, fmt.Errorf("authenticate anchored rollback source: %w", err)
		}
		source.seal = seal
		source.anchor = &anchor
		return source, nil
	}
	seal, err := genstore.ParseSealBytes(gen, sealBytes, manifestBytes, kr)
	if err != nil {
		return nil, fmt.Errorf("authenticate rollback source: %w", err)
	}
	source.seal = seal
	return source, nil
}

// populateRollbackGeneration reconstructs exactly the authenticated source
// inventory into an empty staging generation. Plaintext members are copied
// from seal-verified buffers. Envelopes are opened through ordinary current
// authority or the root-anchor-gated historical path, then freshly sealed
// under the current term.
func populateRollbackGeneration(
	source *rollbackGenerationSource,
	staged storepaths.GenPaths,
	kr *crypto.Keyring,
) error {
	if source == nil || source.seal == nil {
		return fmt.Errorf("rollback source is not authenticated")
	}
	for _, entry := range source.seal.Inventory {
		memberPath := filepath.Join(
			source.gen.Dir(),
			filepath.FromSlash(entry.Path),
		)
		memberBytes, _, err := fsutil.ReadRegularFile(memberPath)
		if err != nil {
			return fmt.Errorf("read rollback source %s: %w", entry.Path, err)
		}
		if err := genstore.VerifyBytesAgainstSeal(
			source.seal,
			entry.Path,
			memberBytes,
		); err != nil {
			return fmt.Errorf("verify rollback source %s: %w", entry.Path, err)
		}

		ctx, encrypted, err := rollbackMemberContext(entry)
		if err != nil {
			return err
		}
		output := memberBytes
		zeroOutput := false
		var plaintext []byte
		if encrypted {
			if source.anchor != nil {
				plaintext, err = genstore.OpenAnchoredEnvelopeBytes(
					source.gen,
					*source.anchor,
					source.sealBytes,
					source.manifestBytes,
					entry.Path,
					memberBytes,
					ctx,
					kr,
				)
			} else {
				plaintext, err = kr.Open(memberBytes, ctx)
			}
			if err != nil {
				return fmt.Errorf("open rollback source %s: %w", entry.Path, err)
			}
			output, err = kr.Seal(plaintext, ctx)
			crypto.ZeroBytes(plaintext)
			if err != nil {
				return fmt.Errorf("seal rollback source %s: %w", entry.Path, err)
			}
			zeroOutput = true
		}
		target := filepath.Join(staged.Dir(), filepath.FromSlash(entry.Path))
		if err := fsutil.WriteFile(target, output); err != nil {
			if zeroOutput {
				crypto.ZeroBytes(output)
			}
			return fmt.Errorf("write rollback member %s: %w", entry.Path, err)
		}
		if zeroOutput {
			crypto.ZeroBytes(output)
		}
	}
	return nil
}

func rollbackMemberContext(
	entry genstore.InventoryEntry,
) (crypto.ObjectContext, bool, error) {
	namespace, name, ok := strings.Cut(entry.Path, "/")
	if !ok {
		return crypto.ObjectContext{}, false, fmt.Errorf(
			"rollback source has invalid inventory path %q",
			entry.Path,
		)
	}
	switch namespace {
	case "keys":
		if strings.HasSuffix(name, keys.WitnessPublicMetadataSuffix) {
			if entry.Term != 0 {
				return crypto.ObjectContext{}, false, fmt.Errorf(
					"rollback plaintext member %s carries term %d",
					entry.Path,
					entry.Term,
				)
			}
			return crypto.ObjectContext{}, false, nil
		}
		selector, class, ok := keys.ParseManagedCredentialFilename(name)
		if !ok || entry.Term <= 0 {
			return crypto.ObjectContext{}, false, fmt.Errorf(
				"rollback source has invalid managed credential %q",
				entry.Path,
			)
		}
		switch class {
		case keys.ManagedCredentialAccount:
			return crypto.AccountKeyContext(selector), true, nil
		case keys.ManagedCredentialSentry:
			return crypto.SentryCredentialContext(selector), true, nil
		default:
			return crypto.ObjectContext{}, false, fmt.Errorf(
				"rollback source has unsupported credential class %q",
				class,
			)
		}
	case "keytypes":
		switch {
		case strings.HasSuffix(name, templatestore.TemplateFileExtension):
			if entry.Term <= 0 {
				return crypto.ObjectContext{}, false, fmt.Errorf(
					"rollback template %s is not a term envelope",
					entry.Path,
				)
			}
			ctx, err := templatestore.TemplateContextForFile(name)
			return ctx, true, err
		case strings.HasSuffix(name, ".json"):
			keyType := strings.TrimSuffix(name, ".json")
			if err := storepaths.ValidateKeyTypeComponent(keyType); err != nil {
				return crypto.ObjectContext{}, false, err
			}
			if entry.Term != 0 {
				return crypto.ObjectContext{}, false, fmt.Errorf(
					"rollback plaintext member %s carries term %d",
					entry.Path,
					entry.Term,
				)
			}
			return crypto.ObjectContext{}, false, nil
		}
	}
	return crypto.ObjectContext{}, false, fmt.Errorf(
		"rollback source has unsupported inventory member %q",
		entry.Path,
	)
}
