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
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/sourcetokens"
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

// populateRollbackGeneration replaces active keys/, keytypes/, the per-key
// policies/ and the per-key source_tokens/ in a staging copy of the
// outgoing generation: restore installs key policies and source tokens with
// their keys, so undoing a restore undoes those too. Deleted archives, the
// node default policy and its source tokens, the ASA set, and node role
// authority remain monotonic and therefore come from the outgoing state.
// Source members are consumed only from exact seal-verified buffers; each
// encrypted one is opened under its own term and sealed again under the
// current one.
func populateRollbackGeneration(
	source *rollbackGenerationSource,
	role noderole.Role,
	staged storepaths.GenPaths,
	kr *crypto.Keyring,
) error {
	if source == nil || source.seal == nil {
		return fmt.Errorf("rollback source is not authenticated")
	}
	for _, dir := range []string{staged.KeysDir(), staged.KeyTypeRecordsDir(), staged.PoliciesDir(), staged.SourceTokensDir()} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if dir == staged.SourceTokensDir() && entry.Name() == rollbackKeptSourceTokens {
				continue
			}
			if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil {
				return fmt.Errorf("clear rollback target %s: %w", entry.Name(), err)
			}
		}
	}
	for _, entry := range source.seal.Inventory {
		if strings.HasPrefix(entry.Path, "policies/") {
			if err := restoreRollbackPolicy(source, role, entry, staged, kr); err != nil {
				return err
			}
			continue
		}
		if entry.Path == "source_tokens/"+rollbackKeptSourceTokens {
			continue
		}
		if !strings.HasPrefix(entry.Path, "keys/") && !strings.HasPrefix(entry.Path, "keytypes/") &&
			!strings.HasPrefix(entry.Path, "source_tokens/") {
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
		if err := fsutil.WriteFileDurable(target, output); err != nil {
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

// restoreRollbackPolicy copies one seal-verified key policy document into
// the staged generation with a sidecar signed by the current keyring. The
// source sidecar is skipped: it may be signed by an older term, and the seal
// already authenticates the document's exact bytes.
func restoreRollbackPolicy(source *rollbackGenerationSource, role noderole.Role, entry genstore.InventoryEntry, staged storepaths.GenPaths, kr *crypto.Keyring) error {
	name := strings.TrimPrefix(entry.Path, "policies/")
	if strings.HasSuffix(name, ".hmac") {
		return nil
	}
	if err := checkRollbackPolicyMember(entry.Path, name, entry.Term); err != nil {
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
	if err := policy.WriteKeyPolicy(staged, role, key, data, kr, time.Now()); err != nil {
		return fmt.Errorf("restore rollback source %s: %w", entry.Path, err)
	}
	return nil
}

// rollbackKeptSourceTokens is the node default's token file, which rollback
// keeps from the outgoing generation with the node default policy: restore
// never writes it.
const rollbackKeptSourceTokens = sourcetokens.DefaultSelector + storepaths.SourceTokenFileExtension

// rollbackMemberContext classifies one keys/, keytypes/ or per-key
// source_tokens/ source member; populateRollbackGeneration routes policies/
// to restoreRollbackPolicy and keeps everything else from the outgoing
// generation, so any other member is refused.
func rollbackMemberContext(
	entry genstore.InventoryEntry,
) (crypto.ObjectContext, bool, error) {
	namespace, name, _ := strings.Cut(entry.Path, "/")
	switch namespace {
	case "keys":
		return rollbackCredentialContext(entry.Path, name, entry.Term)
	case "source_tokens":
		return rollbackSourceTokensContext(entry.Path, name, entry.Term)
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

// checkRollbackPolicyMember accepts a plaintext key policy document; its
// caller has already skipped the sidecars.
func checkRollbackPolicyMember(path, name string, term int64) error {
	key, ok := strings.CutSuffix(name, ".json")
	if !ok || storepaths.ValidatePolicySelector(key) != nil {
		return fmt.Errorf("rollback source has invalid policy member %q", path)
	}
	if term != 0 {
		return fmt.Errorf("rollback plaintext member %s carries term %d", path, term)
	}
	return nil
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

// rollbackSourceTokensContext accepts a cosigner key's token file: a term
// envelope named for its Witness Key ID.
func rollbackSourceTokensContext(path, name string, term int64) (crypto.ObjectContext, bool, error) {
	selector, ok := strings.CutSuffix(name, storepaths.SourceTokenFileExtension)
	if !ok || selector == sourcetokens.DefaultSelector || sourcetokens.ValidateSelector(selector) != nil || term <= 0 {
		return crypto.ObjectContext{}, false, fmt.Errorf("rollback source has invalid source token file %q", path)
	}
	return crypto.SourceTokensContext(selector), true, nil
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
