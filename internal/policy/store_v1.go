// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// This file stores format-v1 policy documents in a generation: the node's
// default.json at the generation root, and one policies/<selector>.json per
// key that has a policy of its own. The layout is the same on both node
// roles. Each document has a .hmac sidecar over its exact bytes. Every load
// verifies the sidecar and then decodes and validates the document for the
// node role, so a loaded document is one the node may enforce.

// StoredDocument is one stored policy document's exact bytes.
type StoredDocument struct {
	// Key is DefaultKey for the node default, or the key's selector.
	Key   string
	Bytes []byte
	// SignedAtUnix is the sidecar's diagnostic signing time, zero when
	// unknown. It is not authenticated and is for display only.
	SignedAtUnix int64
}

// SHA256 returns the hex SHA-256 of the document's exact bytes.
func (d StoredDocument) SHA256() string { return PolicySHA256(d.Bytes) }

// PolicySetSHA256 digests a node's complete set of policy documents. It
// changes whenever any document is added, removed, or changed, so it serves as
// the optimistic-concurrency base for replacing a node's policy.
func PolicySetSHA256(docs []StoredDocument) string {
	lines := make([]string, 0, len(docs))
	for _, doc := range docs {
		lines = append(lines, doc.Key+" "+doc.SHA256()+"\n")
	}
	slices.Sort(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "")))
	return hex.EncodeToString(sum[:])
}

// KeyPolicy is one verified per-key document and its decoded policy.
type KeyPolicy struct {
	Document StoredDocument
	Policy   *PolicyV1
}

func unsupportedRole(role noderole.Role) error {
	return fmt.Errorf("unsupported node role %q", role)
}

// LoadVerifiedDefault verifies and decodes the node default in one
// already-resolved generation. A generation without one fails closed.
func LoadVerifiedDefault(active storepaths.ActivePaths, role noderole.Role, kr *crypto.Keyring) (StoredDocument, *PolicyV1, error) {
	data, signedAt, err := readVerifiedPolicyFile(active.DefaultPolicyPath(), kr)
	if err != nil {
		return StoredDocument{}, nil, err
	}
	doc, err := DecodePolicyV1(data, DefaultKey, role)
	if err != nil {
		return StoredDocument{}, nil, fmt.Errorf("%s: %w", storepaths.DefaultPolicyFileName, err)
	}
	return StoredDocument{Key: DefaultKey, Bytes: data, SignedAtUnix: signedAt}, doc, nil
}

// LoadVerifiedKeyPolicies verifies and decodes every per-key document in one
// already-resolved generation, sorted by key. The namespace may hold only
// <selector>.json documents and their sidecars; anything else fails closed.
func LoadVerifiedKeyPolicies(active storepaths.ActivePaths, role noderole.Role, kr *crypto.Keyring) ([]KeyPolicy, error) {
	keys, err := KeyPolicyKeys(active)
	if err != nil {
		return nil, err
	}
	out := make([]KeyPolicy, 0, len(keys))
	for _, key := range keys {
		data, signedAt, err := readVerifiedPolicyFile(active.PolicyPath(key), kr)
		if err != nil {
			return nil, err
		}
		doc, err := DecodePolicyV1(data, key, role)
		if err != nil {
			return nil, fmt.Errorf("policies/%s.json: %w", key, err)
		}
		out = append(out, KeyPolicy{Document: StoredDocument{Key: key, Bytes: data, SignedAtUnix: signedAt}, Policy: doc})
	}
	return out, nil
}

// LoadVerifiedKeyPolicy verifies and decodes one key's own policy document.
// ok is false only when neither the document nor its sidecar exists; a
// sidecar without its document fails, as it does for a full load.
func LoadVerifiedKeyPolicy(active storepaths.ActivePaths, role noderole.Role, key string, kr *crypto.Keyring) (doc StoredDocument, ok bool, err error) {
	if err := storepaths.ValidatePolicySelector(key); err != nil {
		return StoredDocument{}, false, err
	}
	path := active.PolicyPath(key)
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		if _, sidecarErr := os.Lstat(PolicyIntegritySidecarPath(path)); sidecarErr == nil {
			return StoredDocument{}, false, policyIntegrityError(ErrPolicyIntegrityMissingFile,
				"policy sidecar %s.json.hmac has no document", key)
		} else if !os.IsNotExist(sidecarErr) {
			return StoredDocument{}, false, sidecarErr
		}
		return StoredDocument{}, false, nil
	} else if err != nil {
		return StoredDocument{}, false, err
	}
	data, signedAt, err := readVerifiedPolicyFile(path, kr)
	if err != nil {
		return StoredDocument{}, false, err
	}
	if _, err := DecodePolicyV1(data, key, role); err != nil {
		return StoredDocument{}, false, fmt.Errorf("policies/%s.json: %w", key, err)
	}
	return StoredDocument{Key: key, Bytes: data, SignedAtUnix: signedAt}, true, nil
}

// KeyPolicyKeys lists the key selectors that have a policy document of their
// own, sorted, after checking that the namespace holds only complete document
// and sidecar pairs. It does not verify or decode the documents.
func KeyPolicyKeys(active storepaths.ActivePaths) ([]string, error) {
	entries, err := os.ReadDir(active.PoliciesDir())
	if err != nil {
		return nil, fmt.Errorf("read key policies: %w", err)
	}
	documents := map[string]bool{}
	sidecars := map[string]bool{}
	for _, entry := range entries {
		name := entry.Name()
		key, isSidecar := strings.CutSuffix(name, ".json.hmac")
		if !isSidecar {
			key = strings.TrimSuffix(name, ".json")
		}
		if key == name || storepaths.ValidatePolicySelector(key) != nil || !entry.Type().IsRegular() {
			return nil, fmt.Errorf("key policies contain unsupported entry %q", name)
		}
		if isSidecar {
			sidecars[key] = true
		} else {
			documents[key] = true
		}
	}
	keys := make([]string, 0, len(documents))
	for key := range documents {
		if !sidecars[key] {
			return nil, policyIntegrityError(ErrPolicyIntegrityMissingSidecar, "policy %s.json has no sidecar", key)
		}
		keys = append(keys, key)
	}
	for key := range sidecars {
		if !documents[key] {
			return nil, policyIntegrityError(ErrPolicyIntegrityMissingFile, "policy sidecar %s.json.hmac has no document", key)
		}
	}
	slices.Sort(keys)
	return keys, nil
}

// WriteEmbeddedDefault seeds a new generation's default.json from the
// shipped default for role.
func WriteEmbeddedDefault(active storepaths.ActivePaths, role noderole.Role, kr *crypto.Keyring, signedAt time.Time) error {
	data, err := EmbeddedDefault(role)
	if err != nil {
		return err
	}
	return WriteDefault(active, role, data, kr, signedAt)
}

// WriteDefault validates data as the node default for role and writes it
// with a fresh sidecar into one generation.
func WriteDefault(active storepaths.ActivePaths, role noderole.Role, data []byte, kr *crypto.Keyring, signedAt time.Time) error {
	if _, err := DecodePolicyV1(data, DefaultKey, role); err != nil {
		return err
	}
	return writePolicyFile(active.DefaultPolicyPath(), data, kr, signedAt)
}

// WriteKeyPolicy validates data as key's own document for role and writes
// it with a fresh sidecar into one generation.
func WriteKeyPolicy(active storepaths.ActivePaths, role noderole.Role, key string, data []byte, kr *crypto.Keyring, signedAt time.Time) error {
	if err := storepaths.ValidatePolicySelector(key); err != nil {
		return err
	}
	if _, err := DecodePolicyV1(data, key, role); err != nil {
		return err
	}
	return writePolicyFile(active.PolicyPath(key), data, kr, signedAt)
}

// RemoveKeyPolicy removes key's document and sidecar from one generation.
// Removing a document that does not exist is an error.
func RemoveKeyPolicy(active storepaths.ActivePaths, key string) error {
	if err := storepaths.ValidatePolicySelector(key); err != nil {
		return err
	}
	path := active.PolicyPath(key)
	if _, err := os.Lstat(path); err != nil {
		return fmt.Errorf("no policy for key %s: %w", key, err)
	}
	// Remove the document first: a crash in between leaves an orphan
	// sidecar, which loading rejects, never a document without a sidecar.
	if err := fsutil.RemoveDurable(path); err != nil {
		return err
	}
	return fsutil.RemoveDurable(PolicyIntegritySidecarPath(path))
}

// ArchiveKeyPolicy moves key's document and sidecar into the deleted
// archive, replacing an earlier archived pair for the same key. It is a no-op
// when key has no document.
func ArchiveKeyPolicy(active storepaths.ActivePaths, key string) error {
	if err := storepaths.ValidatePolicySelector(key); err != nil {
		return err
	}
	path := active.PolicyPath(key)
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	archiveDir := active.DeletedPoliciesDir()
	if err := fsutil.MkdirAllPrivate(archiveDir); err != nil {
		return fmt.Errorf("create deleted policies directory: %w", err)
	}
	for _, src := range []string{path, PolicyIntegritySidecarPath(path)} {
		if err := os.Rename(src, filepath.Join(archiveDir, filepath.Base(src))); err != nil {
			return fmt.Errorf("archive key policy: %w", err)
		}
	}
	if err := fsutil.SyncDir(active.PoliciesDir()); err != nil {
		return err
	}
	return fsutil.SyncDir(archiveDir)
}

// ResignDefault validates the node default as stored and replaces its
// sidecar. It is the offline path for a document placed by hand.
func ResignDefault(active storepaths.ActivePaths, role noderole.Role, kr *crypto.Keyring, signedAt time.Time) error {
	data, err := readPolicyFile(active.DefaultPolicyPath())
	if err != nil {
		return err
	}
	if _, err := DecodePolicyV1(data, DefaultKey, role); err != nil {
		return fmt.Errorf("%s: %w", storepaths.DefaultPolicyFileName, err)
	}
	return writePolicySidecar(active.DefaultPolicyPath(), data, kr, signedAt)
}

// ResignKeyPolicies validates every per-key document as stored and replaces
// its sidecar. A document may lack a sidecar; a sidecar without a document
// fails.
func ResignKeyPolicies(active storepaths.ActivePaths, role noderole.Role, kr *crypto.Keyring, signedAt time.Time) error {
	entries, err := os.ReadDir(active.PoliciesDir())
	if err != nil {
		return fmt.Errorf("read key policies: %w", err)
	}
	for _, entry := range entries {
		key, ok := strings.CutSuffix(entry.Name(), ".json")
		if !ok {
			continue
		}
		if storepaths.ValidatePolicySelector(key) != nil {
			return fmt.Errorf("key policies contain unsupported entry %q", entry.Name())
		}
		path := active.PolicyPath(key)
		data, err := readPolicyFile(path)
		if err != nil {
			return err
		}
		if _, err := DecodePolicyV1(data, key, role); err != nil {
			return fmt.Errorf("policies/%s: %w", entry.Name(), err)
		}
		if err := writePolicySidecar(path, data, kr, signedAt); err != nil {
			return err
		}
	}
	_, err = KeyPolicyKeys(active)
	return err
}

func readPolicyFile(path string) ([]byte, error) {
	data, _, err := fsutil.ReadRegularFileLimited(path, maxPolicyDocumentBytes+1)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, policyIntegrityWrap(ErrPolicyIntegrityMissingFile, err, "policy %s", path)
		}
		return nil, policyIntegrityWrap(ErrPolicyIntegrityUnreadable, err, "failed to read policy %s", path)
	}
	return data, nil
}

func readVerifiedPolicyFile(path string, kr *crypto.Keyring) ([]byte, int64, error) {
	data, err := readPolicyFile(path)
	if err != nil {
		return nil, 0, err
	}
	sidecar, err := LoadPolicyIntegritySidecar(PolicyIntegritySidecarPath(path))
	if err != nil {
		return nil, 0, err
	}
	if err := VerifyPolicyIntegrity(data, sidecar, kr); err != nil {
		return nil, 0, err
	}
	return data, sidecar.SignedAtUnix, nil
}

func writePolicyFile(path string, data []byte, kr *crypto.Keyring, signedAt time.Time) error {
	sidecarBytes, err := signedPolicySidecar(data, kr, signedAt)
	if err != nil {
		return err
	}
	if err := fsutil.WriteFileSetDurable(
		fsutil.DurableFileWrite{Path: path, Data: data, Profile: fsutil.PrivateStoreFileProfile},
		fsutil.DurableFileWrite{Path: PolicyIntegritySidecarPath(path), Data: sidecarBytes, Profile: fsutil.PrivateStoreFileProfile},
	); err != nil {
		return fmt.Errorf("write policy %s: %w", filepath.Base(path), err)
	}
	return nil
}

func writePolicySidecar(path string, data []byte, kr *crypto.Keyring, signedAt time.Time) error {
	sidecarBytes, err := signedPolicySidecar(data, kr, signedAt)
	if err != nil {
		return err
	}
	if err := fsutil.WriteFileDurableWithProfile(PolicyIntegritySidecarPath(path), sidecarBytes, fsutil.PrivateStoreFileProfile); err != nil {
		return fmt.Errorf("write policy sidecar for %s: %w", filepath.Base(path), err)
	}
	return nil
}

func signedPolicySidecar(data []byte, kr *crypto.Keyring, signedAt time.Time) ([]byte, error) {
	sidecar, err := SignPolicyIntegrity(data, kr, signedAt)
	if err != nil {
		return nil, err
	}
	return MarshalPolicyIntegritySidecar(sidecar)
}
