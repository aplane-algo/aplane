// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storepass

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/aplane-algo/aplane/internal/backup"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

type Logger func(format string, args ...any)

type RotateOptions struct {
	Logf      Logger
	AfterSwap func() error
}

type RotateResult struct {
	KeysMigrated             int
	TemplatesMigrated        int
	PolicySidecarsMigrated   int
	NodeRoleSidecarsMigrated int
}

type pendingFile struct {
	original string
	newPath  string
	oldPath  string
}

func VerifyCurrentPassphrase(paths storepaths.Paths, identityID string, passphrase []byte) error {
	masterKey, err := loadAndVerifyCurrentMasterKey(paths, identityID, passphrase)
	if err != nil {
		return err
	}
	crypto.ZeroBytes(masterKey)
	return nil
}

// Rotate re-encrypts the identity keystore metadata, keys, and installed
// templates under a new passphrase using a write-new, verify, swap pattern.
func Rotate(paths storepaths.Paths, identityID string, oldPassphrase, newPassphrase []byte, opts RotateOptions) (RotateResult, error) {
	var result RotateResult
	metaDir := paths.KeystoreMetadataDir(identityID)
	keystorePath := filepath.Join(metaDir, ".keystore")
	if _, err := os.Stat(keystorePath); os.IsNotExist(err) {
		return result, fmt.Errorf("no .keystore file found in %s - store not initialized", metaDir)
	}

	oldMasterKey, err := loadAndVerifyCurrentMasterKey(paths, identityID, oldPassphrase)
	if err != nil {
		return result, err
	}
	defer crypto.ZeroBytes(oldMasterKey)

	addresses, templateFiles, err := scanTargets(paths, identityID)
	if err != nil {
		return result, err
	}
	logTargets(opts.Logf, addresses, templateFiles)

	var pendingFiles []pendingFile
	newKeystorePath := keystorePath + ".new"
	oldKeystorePath := keystorePath + ".old"

	newMeta, newMasterKey, err := crypto.CreateKeystoreMetadataTemp(newPassphrase)
	if err != nil {
		return result, fmt.Errorf("failed to create new keystore metadata: %w", err)
	}
	defer crypto.ZeroBytes(newMasterKey)

	logf(opts.Logf, "phase 1: creating new encrypted files")
	for _, address := range addresses {
		keyPath := paths.KeyFilePath(identityID, address)
		pf, ok, err := createPendingEncryptedFile(keyPath, oldMasterKey, newMasterKey, address, opts.Logf)
		if err != nil {
			cleanupPendingNewFiles(pendingFiles)
			return result, err
		}
		if ok {
			pendingFiles = append(pendingFiles, *pf)
			result.KeysMigrated++
		}
	}

	for _, templatePath := range templateFiles {
		templateName := filepath.Base(templatePath)
		pf, ok, err := createPendingEncryptedFile(templatePath, oldMasterKey, newMasterKey, templateName, opts.Logf)
		if err != nil {
			cleanupPendingNewFiles(pendingFiles)
			return result, err
		}
		if ok {
			pendingFiles = append(pendingFiles, *pf)
			result.TemplatesMigrated++
		}
	}

	for _, doc := range policyDocumentsForRotation(paths.Root(), identityID) {
		policySidecar, ok, err := createPendingPolicySidecar(doc, oldMasterKey, newMasterKey, opts.Logf)
		if err != nil {
			cleanupPendingNewFiles(pendingFiles)
			return result, err
		}
		if ok {
			pendingFiles = append(pendingFiles, *policySidecar)
			result.PolicySidecarsMigrated++
		}
	}

	nodeRoleSidecar, ok, err := createPendingNodeRoleSidecar(paths, identityID, oldMasterKey, newMasterKey, opts.Logf)
	if err != nil {
		cleanupPendingNewFiles(pendingFiles)
		return result, err
	}
	if ok {
		pendingFiles = append(pendingFiles, *nodeRoleSidecar)
		result.NodeRoleSidecarsMigrated++
	}

	if err := writeVerifiedNewKeystore(keystorePath, newKeystorePath, newMeta, newPassphrase); err != nil {
		cleanupPendingNewFiles(pendingFiles)
		return result, err
	}
	pendingFiles = append(pendingFiles, pendingFile{keystorePath, newKeystorePath, oldKeystorePath})
	logf(opts.Logf, "created: .keystore.new (verified)")

	logf(opts.Logf, "phase 2: atomic file swap")
	if err := swapPendingFiles(pendingFiles, opts.Logf); err != nil {
		return result, err
	}

	if opts.AfterSwap != nil {
		if err := opts.AfterSwap(); err != nil {
			rollbackPendingFiles(pendingFiles, opts.Logf)
			return result, err
		}
	}

	cleanupPendingOldFiles(pendingFiles)
	return result, nil
}

func logf(log Logger, format string, args ...any) {
	if log != nil {
		log(format, args...)
	}
}

func loadAndVerifyCurrentMasterKey(paths storepaths.Paths, identityID string, oldPassphrase []byte) ([]byte, error) {
	oldMeta, err := crypto.LoadKeystoreMetadata(paths.KeystoreMetadataDir(identityID))
	if err != nil {
		return nil, fmt.Errorf("failed to load keystore metadata: %w", err)
	}
	oldMasterKey, err := oldMeta.VerifyAndDeriveMasterKey(oldPassphrase)
	if err != nil {
		return nil, fmt.Errorf("current passphrase verification failed: %w", err)
	}
	return oldMasterKey, nil
}

func scanTargets(paths storepaths.Paths, identityID string) ([]string, []string, error) {
	addresses, err := backup.ScanKeyFiles(paths.KeysDir(identityID))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to scan keystore: %w", err)
	}

	var templateFiles []string
	templatesRootDir := paths.KeyTypeRecordsDir(identityID)
	_ = filepath.WalkDir(templatesRootDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".template") {
			templateFiles = append(templateFiles, path)
		}
		return nil
	})
	return addresses, templateFiles, nil
}

func logTargets(log Logger, addresses []string, templateFiles []string) {
	if len(addresses) == 0 && len(templateFiles) == 0 {
		logf(log, "no key or template files found in keystore")
		return
	}
	if len(addresses) > 0 {
		logf(log, "found %d key file(s) to migrate", len(addresses))
	}
	if len(templateFiles) > 0 {
		logf(log, "found %d template file(s) to migrate", len(templateFiles))
	}
}

func cleanupPendingNewFiles(pendingFiles []pendingFile) {
	for _, pf := range pendingFiles {
		_ = os.Remove(pf.newPath)
	}
}

func rollbackPendingFiles(pendingFiles []pendingFile, log Logger) {
	logf(log, "rolling back changes")
	for _, pf := range pendingFiles {
		if _, err := os.Stat(pf.oldPath); err == nil {
			if err := os.Rename(pf.oldPath, pf.original); err != nil {
				logf(log, "failed to restore %s: %v", pf.original, err)
			} else {
				logf(log, "restored: %s", filepath.Base(pf.original))
			}
		}
		_ = os.Remove(pf.newPath)
	}
}

func cleanupPendingOldFiles(pendingFiles []pendingFile) {
	for _, pf := range pendingFiles {
		_ = os.Remove(pf.oldPath)
	}
}

func rewriteEncryptedFile(path string, oldMasterKey []byte, newMasterKey []byte) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", path, err)
	}
	if !crypto.IsEncrypted(data) {
		return nil
	}

	plaintext, err := crypto.DecryptWithMasterKey(data, oldMasterKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt %s: %w", path, err)
	}
	newData, err := crypto.EncryptWithMasterKey(plaintext, newMasterKey)
	crypto.ZeroBytes(plaintext)
	if err != nil {
		return fmt.Errorf("failed to re-encrypt %s: %w", path, err)
	}
	if err := fsutil.WriteFile(path+".new", newData); err != nil {
		return fmt.Errorf("failed to write %s.new: %w", path, err)
	}
	if err := ApplyFileMetadataFrom(path, path+".new"); err != nil {
		return fmt.Errorf("failed to set metadata on %s.new: %w", path, err)
	}

	verifyData, err := os.ReadFile(path + ".new")
	if err != nil {
		return fmt.Errorf("failed to verify %s.new: %w", path, err)
	}
	verifyPlaintext, err := crypto.DecryptWithMasterKey(verifyData, newMasterKey)
	if err != nil {
		return fmt.Errorf("verification failed for %s.new: %w", path, err)
	}
	crypto.ZeroBytes(verifyPlaintext)
	return nil
}

func createPendingEncryptedFile(path string, oldMasterKey []byte, newMasterKey []byte, label string, log Logger) (*pendingFile, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("failed to read %s: %w", label, err)
	}
	if !crypto.IsEncrypted(data) {
		logf(log, "skipping %s (not encrypted)", label)
		return nil, false, nil
	}
	if err := rewriteEncryptedFile(path, oldMasterKey, newMasterKey); err != nil {
		switch {
		case strings.Contains(err.Error(), "failed to read "):
			return nil, false, fmt.Errorf("failed to read %s: %w", label, err)
		case strings.Contains(err.Error(), "failed to decrypt "):
			return nil, false, fmt.Errorf("failed to decrypt %s: %w", label, err)
		case strings.Contains(err.Error(), "failed to re-encrypt "):
			return nil, false, fmt.Errorf("failed to re-encrypt %s: %w", label, err)
		case strings.Contains(err.Error(), "failed to write "):
			return nil, false, fmt.Errorf("failed to write %s.new: %w", label, err)
		case strings.Contains(err.Error(), "failed to set metadata "):
			return nil, false, fmt.Errorf("failed to set metadata on %s.new: %w", label, err)
		case strings.Contains(err.Error(), "failed to verify "):
			return nil, false, fmt.Errorf("failed to verify %s.new: %w", label, err)
		default:
			return nil, false, fmt.Errorf("verification failed for %s.new: %w", label, err)
		}
	}

	pf := &pendingFile{original: path, newPath: path + ".new", oldPath: path + ".old"}
	logf(log, "created: %s.new (verified)", label)
	return pf, true, nil
}

type policyRotationDocument struct {
	name       string
	path       string
	verifyFunc func(masterKey []byte) error
}

func policyDocumentsForRotation(dataRoot, identityID string) []policyRotationDocument {
	return []policyRotationDocument{
		{
			name: "policy.yaml",
			path: policy.PolicyPath(dataRoot, identityID),
			verifyFunc: func(masterKey []byte) error {
				_, err := policy.LoadVerifiedStoredConfigWithMasterKey(dataRoot, identityID, masterKey)
				return err
			},
		},
		{
			name: "attestation.yaml",
			path: policy.AttestationPath(dataRoot, identityID),
			verifyFunc: func(masterKey []byte) error {
				_, err := policy.LoadVerifiedAttestationConfigWithMasterKey(dataRoot, identityID, masterKey)
				return err
			},
		},
	}
}

func createPendingPolicySidecar(doc policyRotationDocument, oldMasterKey, newMasterKey []byte, log Logger) (*pendingFile, bool, error) {
	if err := doc.verifyFunc(oldMasterKey); err != nil {
		return nil, false, fmt.Errorf("failed to verify %s integrity before passphrase rotation: %w", doc.name, err)
	}

	policyPath := doc.path
	policyBytes, err := os.ReadFile(policyPath)
	if err != nil {
		return nil, false, fmt.Errorf("failed to read %s: %w", doc.name, err)
	}
	info, err := os.Stat(policyPath)
	if err != nil {
		return nil, false, fmt.Errorf("failed to stat %s: %w", doc.name, err)
	}

	newPolicyKey, err := crypto.DerivePolicyIntegrityKey(newMasterKey)
	if err != nil {
		return nil, false, err
	}
	defer crypto.ZeroBytes(newPolicyKey)

	sidecar, err := policy.SignPolicyIntegrity(policyBytes, newPolicyKey, time.Now(), info.ModTime().UnixNano())
	if err != nil {
		return nil, false, err
	}
	sidecarBytes, err := policy.MarshalPolicyIntegritySidecar(sidecar)
	if err != nil {
		return nil, false, err
	}

	sidecarPath := policy.PolicyIntegritySidecarPath(policyPath)
	newPath := sidecarPath + ".new"
	if err := fsutil.WriteFile(newPath, sidecarBytes); err != nil {
		return nil, false, fmt.Errorf("failed to write %s.hmac.new: %w", doc.name, err)
	}
	if err := ApplyFileMetadataFrom(sidecarPath, newPath); err != nil {
		return nil, false, fmt.Errorf("failed to set metadata on %s.hmac.new: %w", doc.name, err)
	}
	verifySidecar, err := policy.LoadPolicyIntegritySidecar(newPath)
	if err != nil {
		return nil, false, fmt.Errorf("failed to verify %s.hmac.new: %w", doc.name, err)
	}
	if err := policy.VerifyPolicyIntegrity(policyBytes, verifySidecar, newPolicyKey); err != nil {
		return nil, false, fmt.Errorf("verification failed for %s.hmac.new: %w", doc.name, err)
	}
	logf(log, "created: %s.hmac.new (verified)", doc.name)
	return &pendingFile{original: sidecarPath, newPath: newPath, oldPath: sidecarPath + ".old"}, true, nil
}

func createPendingNodeRoleSidecar(paths storepaths.Paths, identityID string, oldMasterKey, newMasterKey []byte, log Logger) (*pendingFile, bool, error) {
	if _, err := noderole.LoadAndVerifyWithMasterKey(paths, identityID, oldMasterKey); err != nil {
		return nil, false, fmt.Errorf("failed to verify node role integrity before passphrase rotation: %w", err)
	}

	_, roleBytes, err := noderole.Load(paths)
	if err != nil {
		return nil, false, err
	}
	info, err := os.Stat(paths.NodeRolePath())
	if err != nil {
		return nil, false, fmt.Errorf("failed to stat node.yaml: %w", err)
	}

	newNodeRoleKey, err := crypto.DeriveNodeRoleIntegrityKey(newMasterKey)
	if err != nil {
		return nil, false, err
	}
	defer crypto.ZeroBytes(newNodeRoleKey)

	sidecar, err := noderole.Sign(roleBytes, newNodeRoleKey, time.Now(), info.ModTime().UnixNano())
	if err != nil {
		return nil, false, err
	}
	sidecarBytes, err := noderole.MarshalSidecar(sidecar)
	if err != nil {
		return nil, false, err
	}

	sidecarPath := paths.NodeRoleIntegritySidecar(identityID)
	newPath := sidecarPath + ".new"
	if err := fsutil.WriteFile(newPath, sidecarBytes); err != nil {
		return nil, false, fmt.Errorf("failed to write node.yaml.hmac.new: %w", err)
	}
	if err := ApplyFileMetadataFrom(sidecarPath, newPath); err != nil {
		return nil, false, fmt.Errorf("failed to set metadata on node.yaml.hmac.new: %w", err)
	}
	verifySidecar, err := noderole.LoadSidecar(newPath)
	if err != nil {
		return nil, false, fmt.Errorf("failed to verify node.yaml.hmac.new: %w", err)
	}
	if err := noderole.Verify(roleBytes, verifySidecar, newNodeRoleKey); err != nil {
		return nil, false, fmt.Errorf("verification failed for node.yaml.hmac.new: %w", err)
	}
	logf(log, "created: node.yaml.hmac.new (verified)")
	return &pendingFile{original: sidecarPath, newPath: newPath, oldPath: sidecarPath + ".old"}, true, nil
}

func ApplyFileMetadataFrom(sourcePath, targetPath string) error {
	info, err := os.Stat(sourcePath)
	if err != nil {
		return err
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && os.Geteuid() == 0 {
		if err := os.Chown(targetPath, int(stat.Uid), int(stat.Gid)); err != nil {
			return err
		}
	}
	return os.Chmod(targetPath, info.Mode().Perm())
}

func writeVerifiedNewKeystore(
	keystorePath string,
	newKeystorePath string,
	newMeta *crypto.KeystoreMetadata,
	newPassphrase []byte,
) error {
	newMetaData, err := json.MarshalIndent(newMeta, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal new keystore metadata: %w", err)
	}
	if err := fsutil.WriteFile(newKeystorePath, newMetaData); err != nil {
		return fmt.Errorf("failed to write .keystore.new: %w", err)
	}
	if err := ApplyFileMetadataFrom(keystorePath, newKeystorePath); err != nil {
		return fmt.Errorf("failed to set metadata on .keystore.new: %w", err)
	}
	verifyMeta, err := crypto.LoadKeystoreMetadataFrom(newKeystorePath)
	if err != nil {
		return fmt.Errorf("failed to verify .keystore.new: %w", err)
	}
	if _, err := verifyMeta.VerifyAndDeriveMasterKey(newPassphrase); err != nil {
		return fmt.Errorf("verification failed for .keystore.new")
	}
	return nil
}

func swapPendingFiles(pendingFiles []pendingFile, log Logger) error {
	for i, pf := range pendingFiles {
		if _, err := os.Stat(pf.original); err == nil {
			if err := os.Rename(pf.original, pf.oldPath); err != nil {
				rollbackPendingFiles(pendingFiles[:i], log)
				return fmt.Errorf("failed to backup %s: %w", filepath.Base(pf.original), err)
			}
		}
		if err := os.Rename(pf.newPath, pf.original); err != nil {
			_ = os.Rename(pf.oldPath, pf.original)
			rollbackPendingFiles(pendingFiles[:i], log)
			return fmt.Errorf("failed to install %s: %w", filepath.Base(pf.original), err)
		}
		logf(log, "swapped: %s", filepath.Base(pf.original))
	}
	return nil
}
