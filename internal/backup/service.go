// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/aplane-algo/aplane/internal/fsutil"
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
}

// CreateAllKeysArchive exports all active keys for identityID into a single
// tar.gz/tgz archive at archivePath. The archive contains README.md and
// apb/*.apb payloads; the .apb files remain the actual encrypted backup units.
func CreateAllKeysArchive(paths storepaths.Paths, identityID, archivePath string, masterKey, exportPassphrase []byte) (*ArchiveResult, error) {
	return CreateKeysArchive(paths, identityID, archivePath, nil, masterKey, exportPassphrase)
}

// CreateKeysArchive exports selected active keys for identityID into a single
// tar.gz/tgz archive at archivePath. When addresses is empty, all active keys
// are exported.
func CreateKeysArchive(paths storepaths.Paths, identityID, archivePath string, addresses []string, masterKey, exportPassphrase []byte) (*ArchiveResult, error) {
	if err := prepareManagedArchiveDestination(paths, identityID, archivePath); err != nil {
		return nil, err
	}

	stageDir, err := os.MkdirTemp("", "aplane-backup-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create backup staging directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(stageDir) }()

	keysDestDir := filepath.Join(stageDir, "apb")
	checksums := make(map[string]string)
	var exported []string
	if len(addresses) == 0 {
		var err error
		checksums, err = ExportAllKeys(paths, identityID, paths.KeysDir(identityID), stageDir, masterKey, exportPassphrase)
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
		for _, address := range addresses {
			if address == "" {
				continue
			}
			checksum, _, err := ExportKey(paths, identityID, paths.KeysDir(identityID), keysDestDir, address, masterKey, exportPassphrase)
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
	if err := copyPolicyFilesToArchive(paths, identityID, stageDir, masterKey); err != nil {
		return nil, err
	}
	nodeRole, _, err := noderole.Load(paths)
	if err != nil {
		return nil, fmt.Errorf("failed to load source node role: %w", err)
	}
	if err := WriteManifest(stageDir, nodeRole.Role, time.Now()); err != nil {
		return nil, err
	}
	if err := CreateTarGzArchive(stageDir, archivePath); err != nil {
		return nil, err
	}
	if err := os.Chmod(archivePath, fsutil.StoreFilePerm); err != nil {
		return nil, fmt.Errorf("failed to set backup archive permissions: %w", err)
	}
	verifyReport, err := DeepVerifyBackup(stageDir, string(exportPassphrase))
	if err != nil {
		return nil, fmt.Errorf("failed to verify backup archive: %w", err)
	}
	if verifyReport.FailedFiles > 0 {
		return nil, fmt.Errorf("failed to verify backup archive: %d file(s) failed verification", verifyReport.FailedFiles)
	}
	archiveChecksum, archiveSize, err := FileSHA256(archivePath)
	if err != nil {
		return nil, fmt.Errorf("failed to checksum backup archive: %w", err)
	}

	return &ArchiveResult{
		ArchivePath:     archivePath,
		ArchiveChecksum: archiveChecksum,
		ArchiveSize:     archiveSize,
		Checksums:       checksums,
		KeyCount:        len(exported),
		Addresses:       exported,
		Verified:        true,
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
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
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
