// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyexport

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/aplane-algo/aplane/internal/policycontext"
)

// Selected is the context chosen for a set of policy files, and the file it
// was read from.
type Selected struct {
	Path   string
	Export *policycontext.Export
}

// Discover selects the node context for policy files. A file's context is
// the export it sits in: the .appolicy directory beside it. override, when
// set, names a context file to use for every file instead.
//
// It returns nil when no file has a context: the files are not from an
// export (or come from stdin, named "-"). Everything else that is not one
// complete, readable context for all the files is an error, never a quiet
// fallback to no context: an unfinished or damaged export, or files from
// different exports, or some files from an export and some not.
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
		dir := filepath.Join(filepath.Dir(file), ContextDir)
		info, err := os.Lstat(dir)
		if errors.Is(err, os.ErrNotExist) {
			bare = append(bare, file)
			continue
		}
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("%s is not a directory", dir)
		}
		path := filepath.Join(dir, ContextFile)
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
