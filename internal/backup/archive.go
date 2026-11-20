// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// IsArchivePath reports whether the path looks like a supported backup archive.
func IsArchivePath(path string) bool {
	lower := strings.ToLower(path)
	return strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz")
}

// CreateTarGzArchive packages the contents of srcDir into a tar.gz archive at
// destPath, which must not exist, and syncs the file.
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
		// The writers above flushed into file by now; its bytes reach the
		// disk before it is closed.
		if err == nil {
			err = file.Sync()
		}
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

// ExtractTarGzArchive extracts a tar.gz archive into destDir. Extracted
// directories and files are owner-private regardless of archive mode bits so
// validation residue is safe inside a private signer store. The archive is
// opened with the same no-follow regular-file enforcement as the recover path,
// and extraction is bounded (entry count and total decompressed size) so a
// crafted archive cannot exhaust the disk. Its errors name each entry by its
// path in the archive, never by destDir, which is the daemon's.
func ExtractTarGzArchive(archivePath, destDir string) error {
	return withArchivePaths(destDir, extractTarGzArchive(archivePath, destDir))
}

func extractTarGzArchive(archivePath, destDir string) error {
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
				return entryError("failed to create directory", header.Name, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(targetPath), 0o700); err != nil {
				return entryError("failed to create parent directory for", header.Name, err)
			}
			out, err := os.OpenFile(targetPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
			if err != nil {
				return entryError("failed to create file", header.Name, err)
			}
			remaining := maxArchiveExtractedBytes - extracted
			written, err := io.Copy(out, io.LimitReader(tr, remaining+1))
			if err != nil {
				_ = out.Close()
				return entryError("failed to extract", header.Name, err)
			}
			extracted += written
			if extracted > maxArchiveExtractedBytes {
				_ = out.Close()
				return fmt.Errorf("archive decompresses past %d bytes; refusing to extract", int64(maxArchiveExtractedBytes))
			}
			if err := out.Close(); err != nil {
				return entryError("failed to close", header.Name, err)
			}
		default:
			return fmt.Errorf("unsupported archive entry type %q for %s", string(header.Typeflag), quotedEntryName(header.Name))
		}
	}
}

func safeArchivePath(root, name string) (string, error) {
	cleanName := filepath.Clean(name)
	targetPath := filepath.Join(root, cleanName)
	rel, err := filepath.Rel(root, targetPath)
	if err != nil {
		return "", fmt.Errorf("failed to validate archive path %s", quotedEntryName(name))
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("archive entry escapes destination: %s", quotedEntryName(name))
	}
	return targetPath, nil
}

// maxQuotedEntryName bounds an archive entry name an error quotes: a tar
// name can be close to 1 MiB, and an error reaches the operator in one admin
// frame.
const maxQuotedEntryName = 512

// quotedEntryName is an archive entry's name as an error quotes it.
func quotedEntryName(name string) string {
	return BoundText(name, maxQuotedEntryName)
}

// entryError reports err about the archive entry named name, as the archive
// names it: the name bounded, and without the extraction path an os error
// repeats.
func entryError(action, name string, err error) error {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		err = pathErr.Err
	}
	return fmt.Errorf("%s %s: %w", action, quotedEntryName(name), err)
}

// BoundText cuts s to at most limit bytes at a character boundary, saying
// how long it was.
func BoundText(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	note := fmt.Sprintf("…(%d bytes)", len(s))
	cut := max(0, limit-len(note))
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + note
}
