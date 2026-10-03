// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backupadmin

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/policy"
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

// populateRollbackGeneration replaces active keys/, keytypes/, and the
// per-key cosigner policies/ in a staging copy of the outgoing generation:
// restore installs cosigner policies with their keys, so undoing a restore
// undoes those too. Deleted archives, the signer policy, and node role
// authority remain monotonic and therefore come from the outgoing state.
// Source members are consumed only from exact seal-verified buffers.
func populateRollbackGeneration(
	source *rollbackGenerationSource,
	staged storepaths.GenPaths,
	kr *crypto.Keyring,
) error {
	if source == nil || source.seal == nil {
		return fmt.Errorf("rollback source is not authenticated")
	}
	for _, dir := range []string{staged.KeysDir(), staged.KeyTypeRecordsDir(), staged.CosignerPoliciesDir()} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil {
				return fmt.Errorf("clear rollback target %s: %w", entry.Name(), err)
			}
		}
	}
	for _, entry := range source.seal.Inventory {
		if strings.HasPrefix(entry.Path, "policies/") {
			if err := restoreRollbackPolicy(source, entry, staged, kr); err != nil {
				return err
			}
			continue
		}
		if !strings.HasPrefix(entry.Path, "keys/") && !strings.HasPrefix(entry.Path, "keytypes/") {
			continue
		}
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

// restoreRollbackPolicy copies one seal-verified cosigner policy document
// into the staged generation with a sidecar signed by the current keyring. The
// source sidecar is skipped: it may be signed by an older term, and the seal
// already authenticates the document's exact bytes.
func restoreRollbackPolicy(source *rollbackGenerationSource, entry genstore.InventoryEntry, staged storepaths.GenPaths, kr *crypto.Keyring) error {
	name := strings.TrimPrefix(entry.Path, "policies/")
	if strings.HasSuffix(name, ".hmac") {
		return nil
	}
	if _, _, err := rollbackPolicyContext(entry.Path, name, entry.Term); err != nil {
		return err
	}
	data, _, err := fsutil.ReadRegularFile(filepath.Join(source.gen.Dir(), filepath.FromSlash(entry.Path)))
	if err != nil {
		return fmt.Errorf("read rollback source %s: %w", entry.Path, err)
	}
	if err := genstore.VerifyBytesAgainstSeal(source.seal, entry.Path, data); err != nil {
		return fmt.Errorf("verify rollback source %s: %w", entry.Path, err)
	}
	key := strings.TrimSuffix(name, ".json")
	if err := policy.WriteCosignerPolicy(staged, key, data, kr, time.Now()); err != nil {
		return fmt.Errorf("restore rollback source %s: %w", entry.Path, err)
	}
	return nil
}

func rollbackMemberContext(
	entry genstore.InventoryEntry,
) (crypto.ObjectContext, bool, error) {
	switch entry.Path {
	case storepaths.SignerPolicyFileName, storepaths.SignerPolicyFileName + ".hmac", "node.yaml.hmac":
		if entry.Term != 0 {
			return crypto.ObjectContext{}, false, fmt.Errorf(
				"rollback plaintext authority member %s carries term %d",
				entry.Path,
				entry.Term,
			)
		}
		return crypto.ObjectContext{}, false, nil
	}
	namespace, name, ok := strings.Cut(entry.Path, "/")
	if !ok {
		return crypto.ObjectContext{}, false, fmt.Errorf(
			"rollback source has invalid inventory path %q",
			entry.Path,
		)
	}
	switch namespace {
	case "keys":
		return rollbackCredentialContext(entry.Path, name, entry.Term)
	case "policies":
		return rollbackPolicyContext(entry.Path, name, entry.Term)
	case "deleted":
		deletedNamespace, deletedName, ok := strings.Cut(name, "/")
		if !ok {
			return crypto.ObjectContext{}, false, fmt.Errorf(
				"rollback source has invalid deleted archive path %q",
				entry.Path,
			)
		}
		switch deletedNamespace {
		case "keys":
			return rollbackCredentialContext(entry.Path, deletedName, entry.Term)
		case "keytypes":
			return rollbackTemplateContext(entry.Path, deletedName, entry.Term)
		case "policies":
			return rollbackPolicyContext(entry.Path, deletedName, entry.Term)
		}
		return crypto.ObjectContext{}, false, fmt.Errorf(
			"rollback source has unsupported deleted archive member %q",
			entry.Path,
		)
	case "keytypes":
		switch {
		case strings.HasSuffix(name, templatestore.TemplateFileExtension):
			return rollbackTemplateContext(entry.Path, name, entry.Term)
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

// rollbackPolicyContext accepts a plaintext cosigner policy document or
// sidecar. Rollback keeps the outgoing policy, so these members are only
// recognized, never copied.
func rollbackPolicyContext(path, name string, term int64) (crypto.ObjectContext, bool, error) {
	key, ok := strings.CutSuffix(strings.TrimSuffix(name, ".hmac"), ".json")
	if !ok || storepaths.ValidateWitnessKeyIDComponent(key) != nil {
		return crypto.ObjectContext{}, false, fmt.Errorf("rollback source has invalid policy member %q", path)
	}
	if term != 0 {
		return crypto.ObjectContext{}, false, fmt.Errorf("rollback plaintext member %s carries term %d", path, term)
	}
	return crypto.ObjectContext{}, false, nil
}

func rollbackCredentialContext(path, name string, term int64) (crypto.ObjectContext, bool, error) {
	if strings.HasSuffix(name, keys.WitnessPublicMetadataSuffix) {
		if term != 0 {
			return crypto.ObjectContext{}, false, fmt.Errorf(
				"rollback plaintext member %s carries term %d",
				path,
				term,
			)
		}
		return crypto.ObjectContext{}, false, nil
	}
	selector, class, ok := keys.ParseManagedCredentialFilename(name)
	if !ok || term <= 0 {
		return crypto.ObjectContext{}, false, fmt.Errorf(
			"rollback source has invalid managed credential %q",
			path,
		)
	}
	switch class {
	case keys.ManagedCredentialAccount:
		return crypto.AccountKeyContext(selector), true, nil
	case keys.ManagedCredentialCosigner:
		return crypto.CosignerCredentialContext(selector), true, nil
	default:
		return crypto.ObjectContext{}, false, fmt.Errorf(
			"rollback source has unsupported credential class %q",
			class,
		)
	}
}

func rollbackTemplateContext(path, name string, term int64) (crypto.ObjectContext, bool, error) {
	if !strings.HasSuffix(name, templatestore.TemplateFileExtension) || term <= 0 {
		return crypto.ObjectContext{}, false, fmt.Errorf(
			"rollback template %s is not a term envelope",
			path,
		)
	}
	ctx, err := templatestore.TemplateContextForFile(name)
	return ctx, true, err
}
