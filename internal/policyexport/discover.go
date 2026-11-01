// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyexport

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/policycontext"
)

// Selected is the context chosen for a set of policy files, and the file it
// was read from.
type Selected struct {
	Path   string
	Export *policycontext.Export
}

// Discover selects the node context for policy files and directories. A
// file's context is the export it sits in: .appolicy/node.json beside it; a
// directory's is the export it is, even with no policy files in it yet.
// override, when set, names a context file to use for every path instead.
//
// It returns nil when no file has a context: the files are not from an
// export (or come from stdin, named "-"). A .appolicy directory without a
// context is not an export; appolicy keeps its saved cases there too.
// Everything else that is not one complete, readable context for all the
// files is an error, never a quiet fallback to no context: an unfinished or
// damaged export, or files from different exports, or some files from an
// export and some not.
func Discover(files []string, override string) (*Selected, error) {
	if override != "" {
		return Read(override)
	}
	var selected *Selected
	var bare []string
	for _, file := range files {
		if file == "-" {
			bare = append(bare, "stdin")
			continue
		}
		dir := filepath.Dir(file)
		if info, err := os.Stat(file); err == nil && info.IsDir() {
			dir = file
		}
		path, err := contextPath(dir)
		if err != nil {
			return nil, err
		}
		if path == "" {
			bare = append(bare, file)
			continue
		}
		if selected != nil {
			if sameFile(selected.Path, path) {
				continue
			}
			return nil, fmt.Errorf("%s and %s come from different exports; check or apply each export's files on their own", selected.Path, path)
		}
		if selected, err = Read(path); err != nil {
			return nil, err
		}
	}
	if selected != nil && len(bare) > 0 {
		return nil, fmt.Errorf("%s is not from the export in %s; check or apply it on its own", bare[0], filepath.Dir(filepath.Dir(selected.Path)))
	}
	return selected, nil
}

// Compare refuses files from an export the node has moved on from: its
// live digests, from the context read paired with its summary, are not the
// export's baseline. The baseline was recomputed from the file's own
// contents when it was read. The edits must be carried over to a new export
// rather than reviewed over changes the export never saw.
func (s *Selected) Compare(contextSHA256, policySetSHA256, snapshotSHA256 string) error {
	baseline := s.Export.Baseline
	if baseline.SnapshotSHA256 == snapshotSHA256 {
		return nil
	}
	var moved []string
	if baseline.PolicySetSHA256 != policySetSHA256 {
		moved = append(moved, "policy")
	}
	if s.Export.Context.SHA256() != contextSHA256 {
		moved = append(moved, "ASA set, network map or role")
	}
	if len(moved) == 0 {
		moved = append(moved, "policy context")
	}
	return &StaleError{Path: s.Path, ExportedAt: s.Export.ExportedAt, Moved: strings.Join(moved, " and ")}
}

// StaleError reports an export the node has moved on from.
type StaleError struct {
	Path       string
	ExportedAt time.Time
	// Moved says what changed: the policy, the context, or both.
	Moved string
}

func (e *StaleError) Error() string {
	return fmt.Sprintf("the export %s (taken %s) is stale: the node's %s changed since; export again and carry your edits over",
		e.Path, e.ExportedAt.Format(time.RFC3339), e.Moved)
}

// ForDir selects the node context for the policy files in dir: override,
// when set, or the export dir is, if it is one.
func ForDir(dir, override string) (*Selected, error) {
	if override != "" {
		return Read(override)
	}
	path, err := contextPath(dir)
	if err != nil || path == "" {
		return nil, err
	}
	return Read(path)
}

// contextPath is the context file of the export in dir, or "" when dir is
// not an export. An unfinished export is one: reading it reports that.
func contextPath(dir string) (string, error) {
	contextDir := filepath.Join(dir, ContextDir)
	info, err := os.Lstat(contextDir)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s is not a directory", contextDir)
	}
	path := filepath.Join(contextDir, ContextFile)
	for _, name := range []string{ContextFile, InProgressFile} {
		if _, err := os.Lstat(filepath.Join(contextDir, name)); err == nil {
			return path, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
	}
	return "", nil
}

// Read reads the context file at path. An export still in progress, or one
// that stopped before finishing, has an in-progress marker beside its
// context and is refused.
func Read(path string) (*Selected, error) {
	marker := filepath.Join(filepath.Dir(path), InProgressFile)
	if _, err := os.Lstat(marker); err == nil {
		return nil, fmt.Errorf("the export in %s did not finish (%s is present); export again", filepath.Dir(filepath.Dir(path)), marker)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	data, err := readBounded(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%s has no %s: not a complete export; export again", filepath.Dir(path), ContextFile)
		}
		return nil, err
	}
	export, err := policycontext.ParseExport(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &Selected{Path: path, Export: export}, nil
}

// readBounded reads a regular file of at most MaxExportBytes, refusing a
// symlink or anything larger rather than reading it whole.
func readBounded(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, policycontext.MaxExportBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > policycontext.MaxExportBytes {
		return nil, fmt.Errorf("%s is more than %d bytes", path, policycontext.MaxExportBytes)
	}
	return data, nil
}

func sameFile(a, b string) bool {
	if a == b {
		return true
	}
	ai, err := os.Stat(a)
	if err != nil {
		return false
	}
	bi, err := os.Stat(b)
	return err == nil && os.SameFile(ai, bi)
}
