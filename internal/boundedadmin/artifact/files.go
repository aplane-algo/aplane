// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package artifact

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// BundleExtension identifies encrypted external contract-admin artifacts.
	BundleExtension = ".apbounded-admin-key"
	// ReferenceExtension identifies public contract-admin reference sidecars.
	ReferenceExtension = ".apbounded-admin-key.json"
)

// FileSet describes files created for one external contract-admin credential.
type FileSet struct {
	BundlePath    string
	ReferencePath string
	Reference     PublicReference
}

// GenerateFiles creates a new credential bundle and public reference without
// overwriting any existing directory entry.
func GenerateFiles(directory string, passphrase []byte, now time.Time) (FileSet, error) {
	if err := ValidateOutputDirectory(directory); err != nil {
		return FileSet{}, err
	}
	bundleBytes, referenceBytes, reference, err := Generate(passphrase, now)
	if err != nil {
		return FileSet{}, err
	}
	bundleBytes = append(bundleBytes, '\n')
	referenceBytes = append(referenceBytes, '\n')

	files := FileSet{
		BundlePath:    filepath.Join(directory, reference.ContractAdminKeyID+BundleExtension),
		ReferencePath: filepath.Join(directory, reference.ContractAdminKeyID+ReferenceExtension),
		Reference:     reference,
	}
	if err := requireAbsent(files.BundlePath); err != nil {
		return FileSet{}, err
	}
	if err := requireAbsent(files.ReferencePath); err != nil {
		return FileSet{}, err
	}
	if err := writeExclusiveAtomic(files.BundlePath, bundleBytes); err != nil {
		return FileSet{}, fmt.Errorf("write contract-admin artifact: %w", err)
	}
	if err := writeExclusiveAtomic(files.ReferencePath, referenceBytes); err != nil {
		cleanupErr := os.Remove(files.BundlePath)
		if cleanupErr != nil {
			return FileSet{}, fmt.Errorf("write public contract-admin reference: %w (also failed to remove incomplete artifact: %v)", err, cleanupErr)
		}
		return FileSet{}, fmt.Errorf("write public contract-admin reference: %w", err)
	}
	return files, nil
}

// LoadFile reads a regular .apbounded-admin-key file with a fixed upper bound. Symlinks and
// other file types are rejected.
func LoadFile(path string) ([]byte, error) {
	if filepath.Ext(path) != BundleExtension {
		return nil, fmt.Errorf("contract-admin artifact must use the %s extension", BundleExtension)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect contract-admin artifact: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("contract-admin artifact must be a regular file")
	}
	if info.Size() <= 0 || info.Size() > maxArtifactBytes {
		return nil, fmt.Errorf("contract-admin artifact size %d is invalid", info.Size())
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open contract-admin artifact: %w", err)
	}
	defer func() { _ = file.Close() }()

	data, err := io.ReadAll(io.LimitReader(file, maxArtifactBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read contract-admin artifact: %w", err)
	}
	if len(data) > maxArtifactBytes {
		return nil, fmt.Errorf("contract-admin artifact exceeds %d bytes", maxArtifactBytes)
	}
	return data, nil
}

// ValidateOutputDirectory requires an existing directory entry and rejects
// symlinks before passphrase handling or key generation.
func ValidateOutputDirectory(path string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("output directory is required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect output directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("output path must be an existing directory, not a symlink or file")
	}
	return nil
}

func requireAbsent(path string) error {
	_, err := os.Lstat(path)
	switch {
	case err == nil:
		return fmt.Errorf("refusing to overwrite existing path %q", path)
	case errors.Is(err, os.ErrNotExist):
		return nil
	default:
		return fmt.Errorf("inspect output path %q: %w", path, err)
	}
}

func writeExclusiveAtomic(path string, data []byte) error {
	directory := filepath.Dir(path)
	temp, err := os.CreateTemp(directory, ".apbounded-admin-key-tmp-")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer func() {
		_ = temp.Close()
		_ = os.Remove(tempPath)
	}()
	if err := temp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temp.Write(data); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Link(tempPath, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("refusing to overwrite existing path %q", path)
		}
		return err
	}
	if err := os.Remove(tempPath); err != nil {
		_ = os.Remove(path)
		return err
	}
	if err := syncDirectory(directory); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	return directory.Sync()
}
