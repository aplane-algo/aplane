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

// Decompression limits for backup archives. A backup holds encrypted
// credential payloads, a sealed manifest, and a README — all small; anything
// approaching these bounds is not a backup.
const (
	// Enough for a credential and a policy per key at the 8,192-key cosigner
	// cap, plus the README and manifest.
	maxArchiveEntries        = 16400
	maxArchiveExtractedBytes = 1 << 30 // 1 GiB across all entries
)

// ExtractTarGzArchive extracts a tar.gz archive into destDir. Extracted
// directories and files are owner-private regardless of archive mode bits so
// validation residue is safe inside a private signer store. The archive is
// opened with the same no-follow regular-file enforcement as the recover path,
// and extraction is bounded (entry count and total decompressed size) so a
// crafted archive cannot exhaust the disk.
// requireExtractableArchive refuses to package a staged archive that
// extraction would reject, so a backup is never written that cannot be
// restored.
func requireExtractableArchive(stageDir string) error {
	entries, total := 0, int64(0)
	err := filepath.WalkDir(stageDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || path == stageDir {
			return err
		}
		entries++
		if !d.IsDir() {
			info, err := d.Info()
			if err != nil {
				return err
			}
			total += info.Size()
		}
		return nil
	})
	if err != nil {
		return err
	}
	if entries > maxArchiveEntries {
		return fmt.Errorf("backup would hold %d entries; an archive allows %d; back up fewer keys per archive", entries, maxArchiveEntries)
	}
	if total > maxArchiveExtractedBytes {
		return fmt.Errorf("backup would hold %d bytes; an archive allows %d; back up fewer keys per archive", total, int64(maxArchiveExtractedBytes))
	}
	return nil
}

func ExtractTarGzArchive(archivePath, destDir string) error {
	file, err := openManagedBackupArchive(archivePath)
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
	entries := 0
	var extracted int64
	for {
		header, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("failed to read archive entry: %w", err)
		}
		entries++
		if entries > maxArchiveEntries {
			return fmt.Errorf("archive has more than %d entries; refusing to extract", maxArchiveEntries)
		}

		targetPath, err := safeArchivePath(destDir, header.Name)
		if err != nil {
			return err
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, 0o700); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", targetPath, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(targetPath), 0o700); err != nil {
				return fmt.Errorf("failed to create parent directory for %s: %w", targetPath, err)
			}
			out, err := os.OpenFile(targetPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
			if err != nil {
				return fmt.Errorf("failed to create file %s: %w", targetPath, err)
			}
			remaining := maxArchiveExtractedBytes - extracted
			written, err := io.Copy(out, io.LimitReader(tr, remaining+1))
			if err != nil {
				_ = out.Close()
				return fmt.Errorf("failed to extract %s: %w", targetPath, err)
			}
			extracted += written
			if extracted > maxArchiveExtractedBytes {
				_ = out.Close()
				return fmt.Errorf("archive decompresses past %d bytes; refusing to extract", int64(maxArchiveExtractedBytes))
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
