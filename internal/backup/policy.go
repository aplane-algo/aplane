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
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// A key's own policy travels with the key: a backup carries
// policies/<selector>.apb beside the key's credential, holding the exact v1
// policy document encrypted under the export passphrase, and restore installs
// it with a sidecar signed by the destination store. The node default policy
// is not backed up; a restored key without a policy of its own follows the
// destination's default.

// backupPoliciesDir is the archive directory of per-key policy documents.
const backupPoliciesDir = "policies"

// maxBackupPolicyEnvelopeBytes bounds one archived policy envelope: a 1 MiB
// document grows by base64 and the envelope's JSON.
const maxBackupPolicyEnvelopeBytes = 2 << 20

// backupPoliciesDirFor returns the policies directory beside an extracted
// archive's credential directory.
func backupPoliciesDirFor(keysDir string) string {
	return filepath.Join(filepath.Dir(keysDir), backupPoliciesDir)
}

// exportKeyPolicies writes the policy document of each selected credential
// that has one of its own. It returns the keys whose policy was exported.
func exportKeyPolicies(active storepaths.ActivePaths, role noderole.Role, stageDir string, selectors []string, kr *crypto.Keyring, exportPassphrase []byte) ([]string, error) {
	destDir := filepath.Join(stageDir, backupPoliciesDir)
	var exported []string
	for _, selector := range selectors {
		if storepaths.ValidatePolicySelector(selector) != nil {
			continue
		}
		doc, ok, err := policy.LoadVerifiedKeyPolicy(active, role, selector, kr)
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

// readBackupPolicy decrypts and validates the archived policy of one key for
// role. It returns nil when the archive carries none.
func readBackupPolicy(keysDir, selector string, exportPassphrase []byte, role noderole.Role) ([]byte, error) {
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
	if _, err := policy.DecodePolicyV1(document, selector, role); err != nil {
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
		if !ok || storepaths.ValidatePolicySelector(key) != nil {
			return nil, fmt.Errorf("backup policies contain unsupported entry %q", entry.Name())
		}
		keysWithPolicy = append(keysWithPolicy, key)
	}
	return keysWithPolicy, nil
}

// ApplyPolicyEntry installs a restored credential's archived policy document
// with a sidecar signed by the destination keyring.
func ApplyPolicyEntry(active storepaths.ActivePaths, role noderole.Role, entry CredentialEntry, kr *crypto.Keyring) error {
	if entry.Policy == nil {
		return fmt.Errorf("restore entry %s carries no policy", entry.Selector)
	}
	return policy.WriteKeyPolicy(active, role, entry.Selector, entry.Policy, kr, time.Now())
}

// destinationPolicy returns the destination's verified policy bytes for key,
// or nil when it has none of its own.
func destinationPolicy(active storepaths.ActivePaths, role noderole.Role, key string, kr *crypto.Keyring) ([]byte, error) {
	doc, ok, err := policy.LoadVerifiedKeyPolicy(active, role, key, kr)
	if err != nil || !ok {
		return nil, err
	}
	return doc.Bytes, nil
}
