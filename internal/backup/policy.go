// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// A cosigner key's policy travels with the key: a backup carries
// policies/<WitnessKeyID>.apb beside the key's credential, holding the exact v1
// policy document encrypted under the export passphrase, and restore installs
// it with a sidecar signed by the destination store. The signer's node-wide
// policy.json is not backed up.

// backupPoliciesDir is the archive directory of cosigner policy documents.
const backupPoliciesDir = "policies"

// maxBackupPolicyEnvelopeBytes bounds one archived policy envelope: a 1 MiB
// document grows by base64 and the envelope's JSON.
const maxBackupPolicyEnvelopeBytes = 2 << 20

// backupPoliciesDirFor returns the policies directory beside an extracted
// archive's credential directory.
func backupPoliciesDirFor(keysDir string) string {
	return filepath.Join(filepath.Dir(keysDir), backupPoliciesDir)
}

// exportCosignerPolicies writes the policy document of each selected cosigner
// credential that has one. It returns the keys whose policy was exported.
func exportCosignerPolicies(active storepaths.ActivePaths, stageDir string, selectors []string, kr *crypto.Keyring, exportPassphrase []byte) ([]string, error) {
	destDir := filepath.Join(stageDir, backupPoliciesDir)
	var exported []string
	for _, selector := range selectors {
		source, err := resolveManagedCredentialFile(active.KeysDir(), selector)
		if err != nil {
			return nil, err
		}
		if source.Class != keys.ManagedCredentialCosigner {
			continue
		}
		doc, ok, err := policy.LoadVerifiedCosignerPolicy(active, selector, kr)
		if err != nil {
			return nil, fmt.Errorf("export policy for %s: %w", selector, err)
		}
		if !ok {
			continue
		}
		sealed, err := crypto.EncryptStandalone(doc.Bytes, exportPassphrase)
		if err != nil {
			return nil, fmt.Errorf("encrypt policy for %s: %w", selector, err)
		}
		if err := fsutil.MkdirAllPrivate(destDir); err != nil {
			return nil, fmt.Errorf("create backup policies directory: %w", err)
		}
		if err := os.WriteFile(filepath.Join(destDir, selector+".apb"), sealed, 0o600); err != nil {
			return nil, fmt.Errorf("write policy for %s: %w", selector, err)
		}
		exported = append(exported, selector)
	}
	return exported, nil
}

// readBackupPolicy decrypts and validates the archived policy of one cosigner
// key. It returns nil when the archive carries none.
func readBackupPolicy(keysDir, selector string, exportPassphrase []byte) ([]byte, error) {
	path := filepath.Join(backupPoliciesDirFor(keysDir), selector+".apb")
	data, _, err := fsutil.ReadRegularFileLimited(path, maxBackupPolicyEnvelopeBytes)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read backup policy: %w", err)
	}
	document, err := crypto.DecryptStandaloneLimited(data, exportPassphrase, maxBackupPolicyEnvelopeBytes)
	if err != nil {
		return nil, fmt.Errorf("decrypt backup policy: %w", err)
	}
	if _, err := policy.DecodeCosignerPolicyV1(document, selector); err != nil {
		return nil, fmt.Errorf("backup policy for %s: %w", selector, err)
	}
	return document, nil
}

// scanBackupPolicies lists the keys an extracted archive carries policies for.
func scanBackupPolicies(keysDir string) ([]string, error) {
	entries, err := os.ReadDir(backupPoliciesDirFor(keysDir))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var keysWithPolicy []string
	for _, entry := range entries {
		key, ok := strings.CutSuffix(entry.Name(), ".apb")
		if !ok || storepaths.ValidateWitnessKeyIDComponent(key) != nil {
			return nil, fmt.Errorf("backup policies contain unsupported entry %q", entry.Name())
		}
		keysWithPolicy = append(keysWithPolicy, key)
	}
	return keysWithPolicy, nil
}

// ApplyPolicyEntry installs a restored credential's archived policy document
// with a sidecar signed by the destination keyring.
func ApplyPolicyEntry(active storepaths.ActivePaths, entry CredentialEntry, kr *crypto.Keyring) error {
	if entry.Policy == nil {
		return fmt.Errorf("restore entry %s carries no policy", entry.Selector)
	}
	return policy.WriteCosignerPolicy(active, entry.Selector, entry.Policy, kr, time.Now())
}

// destinationPolicy returns the destination's verified policy bytes for key,
// or nil when it has none.
func destinationPolicy(active storepaths.ActivePaths, key string, kr *crypto.Keyring) ([]byte, error) {
	doc, ok, err := policy.LoadVerifiedCosignerPolicy(active, key, kr)
	if err != nil || !ok {
		return nil, err
	}
	return doc.Bytes, nil
}
