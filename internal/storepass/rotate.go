// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storepass

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/aplane-algo/aplane/internal/backup/recovered"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keys"
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
	RecoveredFilesMigrated   int
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

// Rotate re-encrypts the identity keystore metadata, active keys, installed
// templates, and published recovered batches under a new passphrase using a
// write-new, verify, swap pattern.
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

	managedFiles, templateFiles, recoveredFiles, err := scanTargets(paths, identityID, oldMasterKey)
	if err != nil {
		return result, err
	}
	logTargets(opts.Logf, managedFiles, templateFiles, recoveredFiles)

	var pendingFiles []pendingFile
	newKeystorePath := keystorePath + ".new"
	oldKeystorePath := keystorePath + ".old"

	newMeta, newMasterKey, err := crypto.CreateKeystoreMetadataTemp(newPassphrase)
	if err != nil {
		return result, fmt.Errorf("failed to create new keystore metadata: %w", err)
	}
	defer crypto.ZeroBytes(newMasterKey)
	// The new metadata carries the generational layout gate by
	// construction (the only supported store format).

	logf(opts.Logf, "phase 1: creating new encrypted files")
	for _, managedFile := range managedFiles {
		pf, ok, err := createPendingEncryptedFile(managedFile.Path, oldMasterKey, newMasterKey, managedFile.Name, opts.Logf)
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

	for _, recoveredPath := range recoveredFiles {
		label := filepath.Base(filepath.Dir(recoveredPath)) + "/" + filepath.Base(recoveredPath)
		pf, ok, err := createPendingEncryptedFile(recoveredPath, oldMasterKey, newMasterKey, label, opts.Logf)
		if err != nil {
			cleanupPendingNewFiles(pendingFiles)
			return result, err
		}
		if ok {
			pendingFiles = append(pendingFiles, *pf)
			result.RecoveredFilesMigrated++
		}
	}

	policyDocs, err := policyDocumentsForRotation(paths, identityID)
	if err != nil {
		cleanupPendingNewFiles(pendingFiles)
		return result, err
	}
	for _, doc := range policyDocs {
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

func scanTargets(
	paths storepaths.Paths,
	identityID string,
	masterKey []byte,
) ([]keys.ManagedCredentialFile, []string, []string, error) {
	// Rotation requires generation quiescence: it rewrites only what it can
	// see through the resolved current namespaces, so a retained prior
	// generation would silently keep material encrypted under the old
	// master key and make generation rollback produce an unreadable store.
	if err := requireGenerationQuiescence(paths, identityID); err != nil {
		return nil, nil, nil, err
	}
	active, err := genstore.ResolveActive(paths, identityID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to resolve active key store layout: %w", err)
	}
	managedFiles, err := keys.ScanManagedCredentialFiles(active.KeysDir())
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to scan keystore: %w", err)
	}

	var templateFiles []string
	templatesRootDir := active.KeyTypeRecordsDir()
	_ = filepath.WalkDir(templatesRootDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".template") {
			templateFiles = append(templateFiles, path)
		}
		return nil
	})
	recoveredFiles, err := recovered.RotationTargets(paths, identityID, masterKey)
	if err != nil {
		return nil, nil, nil, err
	}
	return managedFiles, templateFiles, recoveredFiles, nil
}

// requireGenerationQuiescence refuses rotation on a generational store while
// any generation other than the current one exists (docs/ARCH_GENERATIONS.md
// §11). The operator prunes prior generations first; after a successful
// rotation the retention window restarts empty. Prior-generation retention
// and passphrase rotation never coexist.
func requireGenerationQuiescence(paths storepaths.Paths, identityID string) error {
	current, err := genstore.ReadCurrent(paths, identityID)
	if err != nil {
		return fmt.Errorf("passphrase rotation requires a valid CURRENT generation: %w", err)
	}
	entries, err := os.ReadDir(paths.GenerationsDir(identityID))
	if err != nil {
		return err
	}
	var extra []string
	for _, entry := range entries {
		if entry.Name() != current {
			extra = append(extra, entry.Name())
		}
	}
	if len(extra) > 0 {
		return fmt.Errorf(
			"passphrase rotation requires generation quiescence: %d other generation(s) exist (%s); reconcile and collect them first",
			len(extra), strings.Join(extra, ", "))
	}
	return nil
}

func logTargets(
	log Logger,
	managedFiles []keys.ManagedCredentialFile,
	templateFiles, recoveredFiles []string,
) {
	if len(managedFiles) == 0 && len(templateFiles) == 0 && len(recoveredFiles) == 0 {
		logf(log, "no key, template, or recovered batch files found in keystore")
		return
	}
	if len(managedFiles) > 0 {
		logf(log, "found %d managed credential file(s) to migrate", len(managedFiles))
	}
	if len(templateFiles) > 0 {
		logf(log, "found %d template file(s) to migrate", len(templateFiles))
	}
	if len(recoveredFiles) > 0 {
		logf(log, "found %d recovered batch file(s) to migrate", len(recoveredFiles))
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

// rewriteEncryptedFile re-encrypts path under the new master key, writing
// path.new. display is the human-readable name used in error messages (the
// path itself, or a caller-supplied label).
func rewriteEncryptedFile(path, display string, oldMasterKey []byte, newMasterKey []byte) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", display, err)
	}
	if !crypto.IsEncrypted(data) {
		return nil
	}

	plaintext, err := crypto.DecryptWithMasterKey(data, oldMasterKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt %s: %w", display, err)
	}
	newData, err := crypto.EncryptWithMasterKey(plaintext, newMasterKey)
	crypto.ZeroBytes(plaintext)
	if err != nil {
		return fmt.Errorf("failed to re-encrypt %s: %w", display, err)
	}
	if err := fsutil.WriteFile(path+".new", newData); err != nil {
		return fmt.Errorf("failed to write %s.new: %w", display, err)
	}
	if err := ApplyFileMetadataFrom(path, path+".new"); err != nil {
		return fmt.Errorf("failed to set metadata on %s.new: %w", display, err)
	}
	// The swap in phase 2 renames this file over the canonical one and then
	// removes the .old fallback. Its data blocks must be on disk before the
	// rename can ever become durable, or a power loss leaves a canonical
	// file that decrypts under neither key.
	if err := fsutil.SyncFile(path + ".new"); err != nil {
		return fmt.Errorf("failed to sync %s.new: %w", display, err)
	}

	verifyData, err := os.ReadFile(path + ".new")
	if err != nil {
		return fmt.Errorf("failed to verify %s.new: %w", display, err)
	}
	verifyPlaintext, err := crypto.DecryptWithMasterKey(verifyData, newMasterKey)
	if err != nil {
		return fmt.Errorf("verification failed for %s.new: %w", display, err)
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
	if err := rewriteEncryptedFile(path, label, oldMasterKey, newMasterKey); err != nil {
		return nil, false, err
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

func policyDocumentsForRotation(paths storepaths.Paths, identityID string) ([]policyRotationDocument, error) {
	nodeDoc, _, err := noderole.Load(paths)
	if err != nil {
		return nil, fmt.Errorf("failed to load node role: %w", err)
	}
	dataRoot := paths.Root()
	doc := policyRotationDocument{
		name: "policy.yaml",
		path: policy.PolicyPath(dataRoot, identityID),
	}
	switch nodeDoc.Role {
	case noderole.RoleSentry:
		doc.verifyFunc = func(masterKey []byte) error {
			_, err := policy.LoadVerifiedSentryConfigWithMasterKey(dataRoot, identityID, masterKey)
			return err
		}
	case noderole.RoleSigner:
		doc.verifyFunc = func(masterKey []byte) error {
			_, err := policy.LoadVerifiedStoredConfigWithMasterKey(dataRoot, identityID, masterKey)
			return err
		}
	default:
		return nil, fmt.Errorf("unsupported node role %q", nodeDoc.Role)
	}
	return []policyRotationDocument{doc}, nil
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
	if err := fsutil.SyncFile(newKeystorePath); err != nil {
		return fmt.Errorf("failed to sync .keystore.new: %w", err)
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
	// The renames above are metadata operations; without a directory fsync a
	// power loss can revert any subset of them after cleanup has removed the
	// .old fallbacks. Make the whole swap durable before cleanup may run.
	for _, dir := range uniqueParentDirs(pendingFiles) {
		if err := fsutil.SyncDir(dir); err != nil {
			return fmt.Errorf("failed to sync directory %s after swap: %w", dir, err)
		}
	}
	return nil
}

// uniqueParentDirs returns the sorted set of directories holding the
// canonical files of pendingFiles.
func uniqueParentDirs(pendingFiles []pendingFile) []string {
	seen := make(map[string]struct{}, len(pendingFiles))
	var dirs []string
	for _, pf := range pendingFiles {
		dir := filepath.Dir(pf.original)
		if _, ok := seen[dir]; ok {
			continue
		}
		seen[dir] = struct{}{}
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)
	return dirs
}
