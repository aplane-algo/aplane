// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// IsArchivePath reports whether the path looks like a supported backup archive.
func IsArchivePath(path string) bool {
	lower := strings.ToLower(path)
	return strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz")
}

// CreateTarGzArchive packages the contents of srcDir into a tar.gz archive.
func CreateTarGzArchive(srcDir, destPath string) (err error) {
	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return fmt.Errorf("failed to create archive parent directory: %w", err)
	}

	file, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("archive already exists: %s", destPath)
		}
		return fmt.Errorf("failed to create archive: %w", err)
	}
	defer func() {
		if cerr := file.Close(); err == nil && cerr != nil {
			err = cerr
		}
	}()

	gzw := gzip.NewWriter(file)
	defer func() {
		if cerr := gzw.Close(); err == nil && cerr != nil {
			err = cerr
		}
	}()

	tw := tar.NewWriter(gzw)
	defer func() {
		if cerr := tw.Close(); err == nil && cerr != nil {
			err = cerr
		}
	}()

	err = filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == srcDir {
			return nil
		}

		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)

		info, err := d.Info()
		if err != nil {
			return err
		}

		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = rel
		if d.IsDir() && !strings.HasSuffix(header.Name, "/") {
			header.Name += "/"
		}

		if err := tw.WriteHeader(header); err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()

		if _, err := io.Copy(tw, f); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to write archive: %w", err)
	}

	return nil
}

// ExtractTarGzArchive extracts a tar.gz archive into destDir.
func ExtractTarGzArchive(archivePath, destDir string) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("failed to open archive: %w", err)
	}
	defer func() { _ = file.Close() }()

	gzr, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("failed to open gzip stream: %w", err)
	}
	defer func() { _ = gzr.Close() }()

	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("failed to read archive entry: %w", err)
		}

		targetPath, err := safeArchivePath(destDir, header.Name)
		if err != nil {
			return err
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, 0o755); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", targetPath, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
				return fmt.Errorf("failed to create parent directory for %s: %w", targetPath, err)
			}
			out, err := os.OpenFile(targetPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, fs.FileMode(header.Mode)&0o777)
			if err != nil {
				return fmt.Errorf("failed to create file %s: %w", targetPath, err)
			}
			if _, err := io.Copy(out, tr); err != nil {
				_ = out.Close()
				return fmt.Errorf("failed to extract %s: %w", targetPath, err)
			}
			if err := out.Close(); err != nil {
				return fmt.Errorf("failed to close %s: %w", targetPath, err)
			}
		default:
			return fmt.Errorf("unsupported archive entry type %q for %s", string(header.Typeflag), header.Name)
		}
	}
}

func safeArchivePath(root, name string) (string, error) {
	cleanName := filepath.Clean(name)
	targetPath := filepath.Join(root, cleanName)
	rel, err := filepath.Rel(root, targetPath)
	if err != nil {
		return "", fmt.Errorf("failed to validate archive path %s: %w", name, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("archive entry escapes destination: %s", name)
	}
	return targetPath, nil
}
