// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rotationinventory

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/aplane-algo/aplane/internal/backup/recovered"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/templatestore"
)

// Scan builds the canonical K8 inventory. The caller holds the store and
// identity mutation locks. Recovered-batch phase-2 swap residue is reconciled
// before its canonical files are read; unpublished generation staging residue
// must already have been reconciled and is rejected.
func Scan(paths storepaths.Paths, identityID string, kr *crypto.Keyring) (*Report, error) {
	return scan(paths, identityID, kr, false)
}

// ScanForSnapshot builds the cutover input inventory. The snapshot file is
// deliberately excluded so a pending root never recursively inventories the
// record that contains the inventory. A pre-existing baseline remains an
// input and is classified normally.
func ScanForSnapshot(paths storepaths.Paths, identityID string, kr *crypto.Keyring) (*Report, error) {
	return scan(paths, identityID, kr, true)
}

func scan(
	paths storepaths.Paths,
	identityID string,
	kr *crypto.Keyring,
	excludeSnapshot bool,
) (*Report, error) {
	if kr == nil {
		return nil, fmt.Errorf("rotation inventory requires an open keyring")
	}
	current, err := genstore.ReadCurrent(paths, identityID)
	if err != nil {
		return nil, fmt.Errorf("rotation inventory CURRENT: %w", err)
	}
	scanner := inventoryScanner{
		paths:           paths,
		identityID:      identityID,
		kr:              kr,
		excludeSnapshot: excludeSnapshot,
	}
	if err := scanner.scanGenerations(current); err != nil {
		return nil, err
	}
	if err := scanner.scanIntegrityDocuments(); err != nil {
		return nil, err
	}
	if err := scanner.scanRecovered(); err != nil {
		return nil, err
	}
	if err := scanner.scanDeleted(); err != nil {
		return nil, err
	}
	if err := scanner.scanOptionalRotationRecords(); err != nil {
		return nil, err
	}
	slices.SortFunc(scanner.entries, func(a, b Entry) int {
		return strings.Compare(a.Path, b.Path)
	})
	if err := ValidateEntries(scanner.entries); err != nil {
		return nil, fmt.Errorf("rotation inventory: %w", err)
	}
	return &Report{
		CurrentGeneration: current,
		Entries:           scanner.entries,
	}, nil
}

type inventoryScanner struct {
	paths           storepaths.Paths
	identityID      string
	kr              *crypto.Keyring
	excludeSnapshot bool
	entries         []Entry
}

func (s *inventoryScanner) scanGenerations(current string) error {
	root := s.paths.GenerationsDir(s.identityID)
	if err := requireDirectory(root); err != nil {
		return fmt.Errorf("rotation inventory generations: %w", err)
	}
	dirEntries, err := os.ReadDir(root)
	if err != nil {
		return fmt.Errorf("rotation inventory generations: %w", err)
	}
	names := make([]string, 0, len(dirEntries))
	for _, dirEntry := range dirEntries {
		name := dirEntry.Name()
		if strings.HasPrefix(name, storepaths.GenerationStagingPrefix) {
			return fmt.Errorf("rotation inventory found unreconciled generation staging residue %q", name)
		}
		if err := storepaths.ValidateGenerationID(name); err != nil {
			return fmt.Errorf("rotation inventory unexpected generations entry %q: %w", name, err)
		}
		if !dirEntry.IsDir() {
			return fmt.Errorf("rotation inventory generation is not a directory: %s", name)
		}
		names = append(names, name)
	}
	slices.Sort(names)
	if !slices.Contains(names, current) {
		return fmt.Errorf("rotation inventory CURRENT generation %s is missing", current)
	}
	for _, name := range names {
		gen := s.paths.GenerationPaths(s.identityID, name)
		var contentSeal *genstore.Seal
		manifestBytes, _, err := fsutil.ReadRegularFile(gen.ManifestPath())
		if err != nil {
			return fmt.Errorf("rotation inventory generation %s manifest: %w", name, err)
		}
		if _, err := genstore.ParseManifestBytes(gen, manifestBytes); err != nil {
			return fmt.Errorf("rotation inventory generation %s manifest: %w", name, err)
		}
		if name == current {
			if err := genstore.ValidateCurrent(gen); err != nil {
				return fmt.Errorf("rotation inventory current generation %s: %w", name, err)
			}
		} else if err := genstore.ValidateSealed(gen, s.kr); err != nil {
			return fmt.Errorf("rotation inventory retained generation %s: %w", name, err)
		}
		if err := s.addBytes(gen.ManifestPath(), KindGenerationManifest, manifestBytes, 0, crypto.ObjectContext{}); err != nil {
			return err
		}
		if present, err := regularFileExists(gen.SealPath()); err != nil {
			return err
		} else if present {
			sealBytes, _, err := fsutil.ReadRegularFile(gen.SealPath())
			if err != nil {
				return fmt.Errorf("rotation inventory generation %s seal: %w", name, err)
			}
			seal, err := genstore.ParseSealBytes(gen, sealBytes, manifestBytes, s.kr)
			if err != nil {
				return fmt.Errorf("rotation inventory generation %s seal: %w", name, err)
			}
			if name != current {
				contentSeal = seal
			}
			if err := s.addBytes(gen.SealPath(), KindGenerationSeal, sealBytes, 0, crypto.ObjectContext{}); err != nil {
				return err
			}
		}
		if err := s.scanGenerationNamespace(gen.KeysDir(), "keys", contentSeal); err != nil {
			return fmt.Errorf("rotation inventory generation %s: %w", name, err)
		}
		if err := s.scanGenerationNamespace(gen.KeyTypeRecordsDir(), "keytypes", contentSeal); err != nil {
			return fmt.Errorf("rotation inventory generation %s: %w", name, err)
		}
	}
	return nil
}

func (s *inventoryScanner) scanGenerationNamespace(dir, namespace string, seal *genstore.Seal) error {
	if err := requireDirectory(dir); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			return fmt.Errorf("unsupported directory in %s namespace: %s", namespace, entry.Name())
		}
		path := filepath.Join(dir, entry.Name())
		inventoryPath := namespace + "/" + entry.Name()
		switch namespace {
		case "keys":
			switch {
			case strings.HasSuffix(entry.Name(), keys.WitnessPublicMetadataSuffix):
				if err := s.addPlaintextFromSeal(path, KindWitnessPublicMetadata, seal, inventoryPath); err != nil {
					return err
				}
			default:
				selector, class, ok := keys.ParseManagedCredentialFilename(entry.Name())
				if !ok {
					return fmt.Errorf("unsupported keys artifact %q", entry.Name())
				}
				switch class {
				case keys.ManagedCredentialAccount:
					if err := s.addEnvelopeFromSeal(path, KindAccountKey, crypto.AccountKeyContext(selector), seal, inventoryPath); err != nil {
						return err
					}
				case keys.ManagedCredentialSentry:
					if err := s.addEnvelopeFromSeal(path, KindSentryCredential, crypto.SentryCredentialContext(selector), seal, inventoryPath); err != nil {
						return err
					}
				default:
					return fmt.Errorf("unsupported managed credential class %q", class)
				}
			}
		case "keytypes":
			switch {
			case strings.HasSuffix(entry.Name(), templatestore.TemplateFileExtension):
				ctx, err := templatestore.TemplateContextForFile(path)
				if err != nil {
					return err
				}
				if err := s.addEnvelopeFromSeal(path, KindKeyTypeTemplate, ctx, seal, inventoryPath); err != nil {
					return err
				}
			case strings.HasSuffix(entry.Name(), ".json"):
				keyType := strings.TrimSuffix(entry.Name(), ".json")
				if err := storepaths.ValidateKeyTypeComponent(keyType); err != nil {
					return err
				}
				if err := s.addPlaintextFromSeal(path, KindKeyTypeState, seal, inventoryPath); err != nil {
					return err
				}
			default:
				return fmt.Errorf("unsupported keytypes artifact %q", entry.Name())
			}
		default:
			return fmt.Errorf("unsupported generation namespace %q", namespace)
		}
	}
	return nil
}

func (s *inventoryScanner) scanIntegrityDocuments() error {
	nodeBytes, _, err := fsutil.ReadRegularFile(s.paths.NodeRolePath())
	if err != nil {
		return fmt.Errorf("rotation inventory node role: %w", err)
	}
	nodeDoc, err := noderole.ParseDocument(nodeBytes)
	if err != nil {
		return err
	}
	nodeSidecarPath := s.paths.NodeRoleIntegritySidecar(s.identityID)
	nodeSidecarBytes, _, err := fsutil.ReadRegularFile(nodeSidecarPath)
	if err != nil {
		return fmt.Errorf("rotation inventory node role sidecar: %w", err)
	}
	nodeSidecar, err := noderole.ParseSidecar(nodeSidecarBytes)
	if err != nil {
		return err
	}
	if err := noderole.Verify(nodeBytes, nodeSidecar, s.kr); err != nil {
		return err
	}
	if err := s.addBytes(s.paths.NodeRolePath(), KindNodeRoleDocument, nodeBytes, 0, crypto.ObjectContext{}); err != nil {
		return err
	}
	if err := s.addBytes(nodeSidecarPath, KindNodeRoleSidecar, nodeSidecarBytes, nodeSidecar.IntegrityTerm, crypto.ObjectContext{}); err != nil {
		return err
	}

	policyPath := policy.PolicyPath(s.paths.Root(), s.identityID)
	policyBytes, _, err := fsutil.ReadRegularFile(policyPath)
	if err != nil {
		return fmt.Errorf("rotation inventory policy: %w", err)
	}
	switch nodeDoc.Role {
	case noderole.RoleSigner:
		_, err = policy.ParseStoredConfig(policyBytes)
	case noderole.RoleSentry:
		_, err = policy.ParseStoredSentryConfig(policyBytes)
	default:
		err = fmt.Errorf("unsupported node role %q", nodeDoc.Role)
	}
	if err != nil {
		return fmt.Errorf("rotation inventory policy: %w", err)
	}
	policySidecarPath := policy.PolicyIntegritySidecarPath(policyPath)
	policySidecarBytes, _, err := fsutil.ReadRegularFile(policySidecarPath)
	if err != nil {
		return fmt.Errorf("rotation inventory policy sidecar: %w", err)
	}
	policySidecar, err := policy.ParsePolicyIntegritySidecar(policySidecarBytes)
	if err != nil {
		return err
	}
	if err := policy.VerifyPolicyIntegrity(policyBytes, policySidecar, s.kr); err != nil {
		return err
	}
	if err := s.addBytes(policyPath, KindPolicyDocument, policyBytes, 0, crypto.ObjectContext{}); err != nil {
		return err
	}
	return s.addBytes(
		policySidecarPath,
		KindPolicySidecar,
		policySidecarBytes,
		policySidecar.IntegrityTerm,
		crypto.ObjectContext{},
	)
}

func (s *inventoryScanner) scanRecovered() error {
	targets, err := recovered.RotationTargets(s.paths, s.identityID, s.kr)
	if err != nil {
		return fmt.Errorf("rotation inventory recovered batches: %w", err)
	}
	for _, target := range targets {
		var kind ArtifactKind
		switch target.Context.Class {
		case crypto.ClassRecoveredBatch:
			kind = KindRecoveredBatch
		case crypto.ClassRecoveredEntry:
			kind = KindRecoveredEntry
		default:
			return fmt.Errorf("rotation inventory recovered target has unsupported context %s", target.Context)
		}
		if err := s.addEnvelope(target.Path, kind, target.Context); err != nil {
			return err
		}
	}
	return nil
}

func (s *inventoryScanner) scanDeleted() error {
	root := s.paths.DeletedDir(s.identityID)
	present, err := directoryExists(root)
	if err != nil || !present {
		return err
	}
	children, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, child := range children {
		switch child.Name() {
		case "keys":
			if err := s.scanDeletedKeys(filepath.Join(root, child.Name())); err != nil {
				return err
			}
		case "keytypes":
			if err := s.scanDeletedTemplates(filepath.Join(root, child.Name())); err != nil {
				return err
			}
		default:
			return fmt.Errorf("rotation inventory deleted archive contains unsupported entry %q", child.Name())
		}
	}
	return nil
}

func (s *inventoryScanner) scanDeletedKeys(dir string) error {
	if err := requireDirectory(dir); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		selector, class, ok := keys.ParseManagedCredentialFilename(entry.Name())
		if !ok || entry.IsDir() {
			return fmt.Errorf("unsupported deleted credential artifact %q", entry.Name())
		}
		path := filepath.Join(dir, entry.Name())
		switch class {
		case keys.ManagedCredentialAccount:
			if err := s.addEnvelope(path, KindAccountKey, crypto.AccountKeyContext(selector)); err != nil {
				return err
			}
		case keys.ManagedCredentialSentry:
			if err := s.addEnvelope(path, KindSentryCredential, crypto.SentryCredentialContext(selector)); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported deleted credential class %q", class)
		}
	}
	return nil
}

func (s *inventoryScanner) scanDeletedTemplates(dir string) error {
	if err := requireDirectory(dir); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), templatestore.TemplateFileExtension) {
			return fmt.Errorf("unsupported deleted template artifact %q", entry.Name())
		}
		ctx, err := templatestore.TemplateContextForFile(path)
		if err != nil {
			return err
		}
		if err := s.addEnvelope(path, KindKeyTypeTemplate, ctx); err != nil {
			return err
		}
	}
	return nil
}

func (s *inventoryScanner) scanOptionalRotationRecords() error {
	for _, record := range []struct {
		path string
		kind ArtifactKind
		ctx  crypto.ObjectContext
	}{
		{s.paths.RotationSnapshotPath(s.identityID), KindRotationSnapshot, crypto.RotationSnapshotContext()},
		{s.paths.RotationBaselinePath(s.identityID), KindRotationBaseline, crypto.RotationBaselineContext()},
	} {
		if s.excludeSnapshot && record.kind == KindRotationSnapshot {
			continue
		}
		present, err := regularFileExists(record.path)
		if err != nil {
			return err
		}
		if present {
			if err := s.addEnvelope(record.path, record.kind, record.ctx); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *inventoryScanner) addEnvelope(path string, kind ArtifactKind, ctx crypto.ObjectContext) error {
	return s.addEnvelopeFromSeal(path, kind, ctx, nil, "")
}

func (s *inventoryScanner) addEnvelopeFromSeal(
	path string,
	kind ArtifactKind,
	ctx crypto.ObjectContext,
	seal *genstore.Seal,
	inventoryPath string,
) error {
	data, err := readArtifactBytes(path, seal, inventoryPath)
	if err != nil {
		return fmt.Errorf("rotation inventory read %s: %w", path, err)
	}
	term, err := crypto.EnvelopeTerm(data)
	if err != nil {
		return fmt.Errorf("rotation inventory term %s: %w", path, err)
	}
	plaintext, err := s.kr.Open(data, ctx)
	if err != nil {
		return fmt.Errorf("rotation inventory open %s as %s: %w", path, ctx, err)
	}
	crypto.ZeroBytes(plaintext)
	return s.addBytes(path, kind, data, term, ctx)
}

func (s *inventoryScanner) addPlaintext(path string, kind ArtifactKind) error {
	return s.addPlaintextFromSeal(path, kind, nil, "")
}

func (s *inventoryScanner) addPlaintextFromSeal(
	path string,
	kind ArtifactKind,
	seal *genstore.Seal,
	inventoryPath string,
) error {
	data, err := readArtifactBytes(path, seal, inventoryPath)
	if err != nil {
		return fmt.Errorf("rotation inventory read %s: %w", path, err)
	}
	if term, present, err := crypto.InspectTermEnvelope(data); err != nil {
		return fmt.Errorf("rotation inventory plaintext %s: %w", path, err)
	} else if present {
		return fmt.Errorf(
			"rotation inventory plaintext %s unexpectedly carries term envelope %d",
			path,
			term,
		)
	}
	return s.addBytes(path, kind, data, 0, crypto.ObjectContext{})
}

func readArtifactBytes(path string, seal *genstore.Seal, inventoryPath string) ([]byte, error) {
	data, _, err := fsutil.ReadRegularFile(path)
	if err != nil {
		return nil, err
	}
	if seal != nil {
		if err := genstore.VerifyBytesAgainstSeal(seal, inventoryPath, data); err != nil {
			return nil, fmt.Errorf("exact bytes do not match retained generation seal: %w", err)
		}
	}
	return data, nil
}

func (s *inventoryScanner) addBytes(path string, kind ArtifactKind, data []byte, term int64, ctx crypto.ObjectContext) error {
	relative, err := filepath.Rel(s.paths.Root(), path)
	if err != nil {
		return err
	}
	relative = filepath.ToSlash(relative)
	if err := validateCanonicalPath(relative); err != nil {
		return fmt.Errorf("rotation inventory path %s: %w", path, err)
	}
	sum := sha256.Sum256(data)
	s.entries = append(s.entries, Entry{
		Path:           relative,
		Kind:           kind,
		Size:           int64(len(data)),
		SHA256:         hex.EncodeToString(sum[:]),
		Term:           term,
		ObjectClass:    ctx.Class,
		ObjectSelector: ctx.Selector,
	})
	return nil
}

func requireDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("path is not a regular directory: %s", path)
	}
	return nil
}

func directoryExists(path string) (bool, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return false, fmt.Errorf("path is not a regular directory: %s", path)
	}
	return true, nil
}

func regularFileExists(path string) (bool, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return false, fmt.Errorf("path is not a regular file: %s", path)
	}
	return true, nil
}
