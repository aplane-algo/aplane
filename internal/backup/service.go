// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

type ArchiveResult struct {
	ArchivePath     string
	ArchiveChecksum string
	ArchiveSize     int64
	Checksums       map[string]string
	KeyCount        int
	Addresses       []string
	Verified        bool
	// Skipped maps address -> reason for key files excluded from an all-keys
	// backup because their decrypted payload failed canonical validation.
	// Always empty for explicitly selected addresses, which fail closed.
	Skipped map[string]string
}

// CreateKeysArchiveRequest contains one managed backup creation snapshot.
// MasterKey and ExportPassphrase are borrowed for the duration of the call and
// are not cleared.
type CreateKeysArchiveRequest struct {
	Paths            storepaths.Paths
	IdentityID       string
	ArchivePath      string
	Addresses        []string
	MasterKey        []byte
	ExportPassphrase []byte
	SourceSettings   SourceSettingsSnapshot
}

// CreateKeysArchive exports selected active keys into one tar.gz/tgz archive.
// When Addresses is empty, all active keys are exported.
func CreateKeysArchive(req CreateKeysArchiveRequest) (*ArchiveResult, error) {
	if err := prepareManagedArchiveDestination(req.Paths, req.IdentityID, req.ArchivePath); err != nil {
		return nil, err
	}

	stageDir, err := os.MkdirTemp("", "aplane-backup-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create backup staging directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(stageDir) }()

	// Export sources resolve through the active layout once per archive.
	activeStore, err := genstore.ResolveActive(req.Paths, req.IdentityID)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve active key store layout: %w", err)
	}
	activeKeysDir := activeStore.KeysDir()

	keysDestDir := filepath.Join(stageDir, "apb")
	checksums := make(map[string]string)
	skipped := make(map[string]string)
	var exported []string
	if len(req.Addresses) == 0 {
		var err error
		checksums, skipped, err = ExportAllKeys(
			req.Paths,
			req.IdentityID,
			activeKeysDir,
			stageDir,
			req.MasterKey,
			req.ExportPassphrase,
		)
		if err != nil {
			return nil, err
		}
		exported, err = ScanBackupFiles(keysDestDir)
		if err != nil {
			return nil, err
		}
	} else {
		if err := os.MkdirAll(keysDestDir, 0750); err != nil {
			return nil, fmt.Errorf("failed to create backup keys directory: %w", err)
		}
		for _, address := range req.Addresses {
			if address == "" {
				continue
			}
			checksum, _, err := ExportKey(
				req.Paths,
				req.IdentityID,
				activeKeysDir,
				keysDestDir,
				address,
				req.MasterKey,
				req.ExportPassphrase,
			)
			if err != nil {
				return nil, fmt.Errorf("failed to export %s: %w", address, err)
			}
			checksums[address] = checksum
			exported = append(exported, address)
		}
		if len(exported) == 0 {
			return nil, fmt.Errorf("no addresses selected for backup")
		}
	}
	if err := WriteReadme(stageDir); err != nil {
		return nil, err
	}
	if err := copyPolicyFilesToArchive(req.Paths, req.IdentityID, stageDir, req.MasterKey); err != nil {
		return nil, err
	}
	nodeRole, _, err := noderole.Load(req.Paths)
	if err != nil {
		return nil, fmt.Errorf("failed to load source node role: %w", err)
	}
	if err := WriteManifest(stageDir, nodeRole.Role, time.Now()); err != nil {
		return nil, err
	}
	if err := writeSourceSettings(stageDir, nodeRole.Role, req.SourceSettings); err != nil {
		return nil, err
	}
	if err := CreateTarGzArchive(stageDir, req.ArchivePath); err != nil {
		return nil, err
	}
	if err := os.Chmod(req.ArchivePath, fsutil.StoreFilePerm); err != nil {
		return nil, fmt.Errorf("failed to set backup archive permissions: %w", err)
	}
	verifyReport, err := DeepVerifyBackupBytes(stageDir, req.ExportPassphrase, DeepVerifyOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to verify backup archive: %w", err)
	}
	if verifyReport.FailedFiles > 0 {
		return nil, fmt.Errorf("failed to verify backup archive: %d file(s) failed verification", verifyReport.FailedFiles)
	}
	archiveChecksum, archiveSize, err := FileSHA256(req.ArchivePath)
	if err != nil {
		return nil, fmt.Errorf("failed to checksum backup archive: %w", err)
	}

	return &ArchiveResult{
		ArchivePath:     req.ArchivePath,
		ArchiveChecksum: archiveChecksum,
		ArchiveSize:     archiveSize,
		Checksums:       checksums,
		KeyCount:        len(exported),
		Addresses:       exported,
		Verified:        true,
		Skipped:         skipped,
	}, nil
}

func copyPolicyFilesToArchive(paths storepaths.Paths, identityID, stageDir string, masterKey []byte) error {
	dstDir := filepath.Join(stageDir, "policy")
	if err := os.MkdirAll(dstDir, 0o750); err != nil {
		return fmt.Errorf("failed to create policy backup directory: %w", err)
	}
	nodeRole, _, err := noderole.Load(paths)
	if err != nil {
		return fmt.Errorf("failed to load source node role: %w", err)
	}
	switch nodeRole.Role {
	case noderole.RoleSentry:
		if _, err := policy.LoadVerifiedSentryConfigWithMasterKey(paths.Root(), identityID, masterKey); err != nil {
			return fmt.Errorf("failed to verify policy.yaml before backup: %w", err)
		}
	case noderole.RoleSigner:
		if _, err := policy.LoadVerifiedStoredConfigWithMasterKey(paths.Root(), identityID, masterKey); err != nil {
			return fmt.Errorf("failed to verify policy.yaml before backup: %w", err)
		}
	default:
		return fmt.Errorf("unsupported source node role %q", nodeRole.Role)
	}

	docPath := policy.PolicyPath(paths.Root(), identityID)
	docBytes, err := os.ReadFile(docPath)
	if err != nil {
		return fmt.Errorf("failed to read policy.yaml: %w", err)
	}
	sidecarPath := policy.PolicyIntegritySidecarPath(docPath)
	sidecarBytes, err := os.ReadFile(sidecarPath)
	if err != nil {
		return fmt.Errorf("failed to read policy.yaml.hmac: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dstDir, "policy.yaml"), docBytes, 0o600); err != nil {
		return fmt.Errorf("failed to stage policy.yaml: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dstDir, "policy.yaml.hmac"), sidecarBytes, 0o600); err != nil {
		return fmt.Errorf("failed to stage policy.yaml.hmac: %w", err)
	}
	return nil
}

// FileSHA256 returns the SHA-256 checksum and size of path.
func FileSHA256(path string) (string, int64, error) {
	return fsutil.RegularFileSHA256(path)
}

func prepareManagedArchiveDestination(paths storepaths.Paths, identityID, archivePath string) error {
	for _, dir := range []string{
		paths.BackupsRootDir(),
		paths.IdentityBackupsDir(identityID),
		filepath.Dir(archivePath),
	} {
		if err := ensureStoreDir(dir); err != nil {
			return err
		}
	}
	return nil
}

func ensureStoreDir(path string) error {
	if err := os.MkdirAll(path, 0770); err != nil {
		return fmt.Errorf("failed to create backup directory %s: %w", path, err)
	}
	if err := os.Chmod(path, fsutil.StoreDirPerm); err != nil {
		if os.IsPermission(err) {
			if fallbackErr := os.Chmod(path, 0770); fallbackErr != nil {
				return fmt.Errorf("failed to set backup directory permissions for %s: %w", path, fallbackErr)
			}
			return nil
		}
		return fmt.Errorf("failed to set backup directory permissions for %s: %w", path, err)
	}
	return nil
}

func BuildManagedArchivePath(paths storepaths.Paths, identityID string, ts string) string {
	fileName := fmt.Sprintf("aplane-backup-%s.tar.gz", ts)
	return filepath.Join(paths.IdentityBackupsDir(identityID), fileName)
}
