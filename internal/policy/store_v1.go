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
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// This file stores format-v1 policy documents in a generation: a signer
// node's policy.json at the generation root, or one policies/<WitnessKeyID>.json
// per cosigner key. Each document has a .hmac sidecar over its exact bytes.
// Every load verifies the sidecar and then decodes and validates the document,
// so a loaded document is one the node may enforce.

// StoredDocument is one stored policy document's exact bytes.
type StoredDocument struct {
	// Key is the Witness Key ID of a cosigner document and empty for the
	// signer document.
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

// CosignerPolicy is one verified cosigner document and its decoded policy.
type CosignerPolicy struct {
	Document StoredDocument
	Policy   *CosignerPolicyV1
}

// LoadVerifiedSignerPolicy verifies and decodes the signer policy document in
// one already-resolved generation.
func LoadVerifiedSignerPolicy(active storepaths.ActivePaths, kr *crypto.Keyring) (StoredDocument, *SignerPolicyV1, error) {
	data, signedAt, err := readVerifiedPolicyFile(active.PolicyPath(), kr)
	if err != nil {
		return StoredDocument{}, nil, err
	}
	doc, err := DecodeSignerPolicyV1(data)
	if err != nil {
		return StoredDocument{}, nil, fmt.Errorf("%s: %w", storepaths.SignerPolicyFileName, err)
	}
	return StoredDocument{Bytes: data, SignedAtUnix: signedAt}, doc, nil
}

// LoadVerifiedCosignerPolicies verifies and decodes every cosigner policy
// document in one already-resolved generation, sorted by Witness Key ID. The
// namespace may hold only <WitnessKeyID>.json documents and their sidecars;
// anything else fails closed.
func LoadVerifiedCosignerPolicies(active storepaths.ActivePaths, kr *crypto.Keyring) ([]CosignerPolicy, error) {
	keys, err := CosignerPolicyKeys(active)
	if err != nil {
		return nil, err
	}
	out := make([]CosignerPolicy, 0, len(keys))
	for _, key := range keys {
		data, signedAt, err := readVerifiedPolicyFile(active.CosignerPolicyPath(key), kr)
		if err != nil {
			return nil, err
		}
		doc, err := DecodeCosignerPolicyV1(data, key)
		if err != nil {
			return nil, fmt.Errorf("policies/%s.json: %w", key, err)
		}
		out = append(out, CosignerPolicy{Document: StoredDocument{Key: key, Bytes: data, SignedAtUnix: signedAt}, Policy: doc})
	}
	return out, nil
}

// LoadVerifiedCosignerPolicy verifies and decodes one cosigner key's policy
// document. ok is false only when neither the document nor its sidecar
// exists; a sidecar without its document fails, as it does for a full load.
func LoadVerifiedCosignerPolicy(active storepaths.ActivePaths, key string, kr *crypto.Keyring) (doc StoredDocument, ok bool, err error) {
	if err := storepaths.ValidateWitnessKeyIDComponent(key); err != nil {
		return StoredDocument{}, false, err
	}
	path := active.CosignerPolicyPath(key)
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		if _, sidecarErr := os.Lstat(PolicyIntegritySidecarPath(path)); sidecarErr == nil {
			return StoredDocument{}, false, policyIntegrityError(ErrPolicyIntegrityMissingFile,
				"cosigner policy sidecar %s.json.hmac has no document", key)
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
	if _, err := DecodeCosignerPolicyV1(data, key); err != nil {
		return StoredDocument{}, false, fmt.Errorf("policies/%s.json: %w", key, err)
	}
	return StoredDocument{Key: key, Bytes: data, SignedAtUnix: signedAt}, true, nil
}

// CosignerPolicyKeys lists the Witness Key IDs that have a policy document,
// sorted, after checking that the namespace holds only complete document and
// sidecar pairs. It does not verify or decode the documents.
func CosignerPolicyKeys(active storepaths.ActivePaths) ([]string, error) {
	entries, err := os.ReadDir(active.CosignerPoliciesDir())
	if err != nil {
		return nil, fmt.Errorf("read cosigner policies: %w", err)
	}
	documents := map[string]bool{}
	sidecars := map[string]bool{}
	for _, entry := range entries {
		name := entry.Name()
		key, isSidecar := strings.CutSuffix(name, ".json.hmac")
		if !isSidecar {
			key = strings.TrimSuffix(name, ".json")
		}
		if key == name || storepaths.ValidateWitnessKeyIDComponent(key) != nil || !entry.Type().IsRegular() {
			return nil, fmt.Errorf("cosigner policies contain unsupported entry %q", name)
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
			return nil, policyIntegrityError(ErrPolicyIntegrityMissingSidecar, "cosigner policy %s.json has no sidecar", key)
		}
		keys = append(keys, key)
	}
	for key := range sidecars {
		if !documents[key] {
			return nil, policyIntegrityError(ErrPolicyIntegrityMissingFile, "cosigner policy sidecar %s.json.hmac has no document", key)
		}
	}
	slices.Sort(keys)
	return keys, nil
}

// WriteInitialSignerPolicy writes InitialSignerPolicy (see starting.go) into
// a new signer generation. Cosigner generations start with no documents.
func WriteInitialSignerPolicy(active storepaths.ActivePaths, kr *crypto.Keyring, signedAt time.Time) error {
	return WriteSignerPolicy(active, InitialSignerPolicy, kr, signedAt)
}

// WriteSignerPolicy validates data as a signer document and writes it with a
// fresh sidecar into one generation.
func WriteSignerPolicy(active storepaths.ActivePaths, data []byte, kr *crypto.Keyring, signedAt time.Time) error {
	if _, err := DecodeSignerPolicyV1(data); err != nil {
		return err
	}
	return writePolicyFile(active.PolicyPath(), data, kr, signedAt)
}

// WriteCosignerPolicy validates data as the document for key and writes it
// with a fresh sidecar into one generation.
func WriteCosignerPolicy(active storepaths.ActivePaths, key string, data []byte, kr *crypto.Keyring, signedAt time.Time) error {
	if err := storepaths.ValidateWitnessKeyIDComponent(key); err != nil {
		return err
	}
	if _, err := DecodeCosignerPolicyV1(data, key); err != nil {
		return err
	}
	return writePolicyFile(active.CosignerPolicyPath(key), data, kr, signedAt)
}

// RemoveCosignerPolicy removes key's document and sidecar from one
// generation. Removing a document that does not exist is an error.
func RemoveCosignerPolicy(active storepaths.ActivePaths, key string) error {
	if err := storepaths.ValidateWitnessKeyIDComponent(key); err != nil {
		return err
	}
	path := active.CosignerPolicyPath(key)
	if _, err := os.Lstat(path); err != nil {
		return fmt.Errorf("no policy for cosigner key %s: %w", key, err)
	}
	// Remove the document first: a crash in between leaves an orphan
	// sidecar, which loading rejects, never a document without a sidecar.
	if err := fsutil.RemoveDurable(path); err != nil {
		return err
	}
	return fsutil.RemoveDurable(PolicyIntegritySidecarPath(path))
}

// ArchiveCosignerPolicy moves key's document and sidecar into the deleted
// archive, replacing an earlier archived pair for the same key. It is a no-op
// when key has no document.
func ArchiveCosignerPolicy(active storepaths.ActivePaths, key string) error {
	if err := storepaths.ValidateWitnessKeyIDComponent(key); err != nil {
		return err
	}
	path := active.CosignerPolicyPath(key)
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	archiveDir := active.DeletedCosignerPoliciesDir()
	if err := fsutil.MkdirAllPrivate(archiveDir); err != nil {
		return fmt.Errorf("create deleted policies directory: %w", err)
	}
	for _, src := range []string{path, PolicyIntegritySidecarPath(path)} {
		if err := os.Rename(src, filepath.Join(archiveDir, filepath.Base(src))); err != nil {
			return fmt.Errorf("archive cosigner policy: %w", err)
		}
	}
	if err := fsutil.SyncDir(active.CosignerPoliciesDir()); err != nil {
		return err
	}
	return fsutil.SyncDir(archiveDir)
}

// ResignSignerPolicy validates the signer document as stored and replaces its
// sidecar. It is the offline path for a document placed by hand.
func ResignSignerPolicy(active storepaths.ActivePaths, kr *crypto.Keyring, signedAt time.Time) error {
	data, err := readPolicyFile(active.PolicyPath())
	if err != nil {
		return err
	}
	if _, err := DecodeSignerPolicyV1(data); err != nil {
		return fmt.Errorf("%s: %w", storepaths.SignerPolicyFileName, err)
	}
	return writePolicySidecar(active.PolicyPath(), data, kr, signedAt)
}

// ResignCosignerPolicies validates every cosigner document as stored and
// replaces its sidecar. A document may lack a sidecar; a sidecar without a
// document fails.
func ResignCosignerPolicies(active storepaths.ActivePaths, kr *crypto.Keyring, signedAt time.Time) error {
	entries, err := os.ReadDir(active.CosignerPoliciesDir())
	if err != nil {
		return fmt.Errorf("read cosigner policies: %w", err)
	}
	for _, entry := range entries {
		key, ok := strings.CutSuffix(entry.Name(), ".json")
		if !ok {
			continue
		}
		if storepaths.ValidateWitnessKeyIDComponent(key) != nil {
			return fmt.Errorf("cosigner policies contain unsupported entry %q", entry.Name())
		}
		path := active.CosignerPolicyPath(key)
		data, err := readPolicyFile(path)
		if err != nil {
			return err
		}
		if _, err := DecodeCosignerPolicyV1(data, key); err != nil {
			return fmt.Errorf("policies/%s: %w", entry.Name(), err)
		}
		if err := writePolicySidecar(path, data, kr, signedAt); err != nil {
			return err
		}
	}
	_, err = CosignerPolicyKeys(active)
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
