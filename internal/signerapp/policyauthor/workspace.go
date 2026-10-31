// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyauthor

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
)

// Workspace is the set of policy files an editing session works on: one file,
// or every *.json file directly inside a directory. Documents are identified
// by their "key" field, never by file name, so files keep the names people
// gave them.
type Workspace struct {
	// Path is the file or directory opened.
	Path  string
	IsDir bool
	// Role is the role the workspace's documents are for: the first valid
	// role a file names, in file-name order.
	Role  noderole.Role
	Files []*File
	// Problems are the rules across files: at most one default, no key in two
	// files, and one role throughout. They are reported per file, so a file
	// stays open and repairable while it breaks one.
	Problems []Problem
}

// Open loads a workspace. It fails only when path cannot be opened at all;
// a file that cannot be read or decoded is loaded with its problems.
func Open(path string) (*Workspace, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	w := &Workspace{Path: path, IsDir: info.IsDir()}
	var paths []string
	if w.IsDir {
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".json") && !e.IsDir() {
				paths = append(paths, filepath.Join(path, e.Name()))
			}
		}
		sort.Strings(paths)
	} else {
		paths = []string{path}
	}

	for _, p := range paths {
		f := LoadFile(p)
		if w.Role == "" {
			w.Role = f.Role
		}
		w.Files = append(w.Files, f)
	}
	w.Check()
	return w, nil
}

// Check recomputes the rules across files.
func (w *Workspace) Check() {
	w.Problems = nil
	byKey := map[string][]*File{}
	for _, f := range w.Files {
		if f.Key != "" {
			byKey[f.Key] = append(byKey[f.Key], f)
		}
		if f.Role != "" && w.Role != "" && f.Role != w.Role {
			w.add(f, "/role", fmt.Sprintf("the document is for a %s node, but the workspace holds %s documents", f.Role, w.Role))
		}
	}
	for key, files := range byKey {
		if len(files) < 2 {
			continue
		}
		for _, f := range files {
			var others []string
			for _, o := range files {
				if o != f {
					others = append(others, filepath.Base(o.Path))
				}
			}
			what := fmt.Sprintf("key %q is also in %s", key, strings.Join(others, ", "))
			if key == policy.DefaultKey {
				what = "a workspace holds at most one default document; another is in " + strings.Join(others, ", ")
			}
			w.add(f, "/key", what)
		}
	}
	sort.SliceStable(w.Problems, func(i, j int) bool { return w.Problems[i].Path < w.Problems[j].Path })
}

func (w *Workspace) add(f *File, pointer, message string) {
	w.Problems = append(w.Problems, Problem{Path: f.Path, Pointer: pointer, Severity: SeverityError, Message: message})
}

// AllProblems returns every file's problems and the workspace's, grouped by
// file in file order.
func (w *Workspace) AllProblems() []Problem {
	var out []Problem
	for _, f := range w.Files {
		out = append(out, f.Problems...)
		for _, p := range w.Problems {
			if p.Path == f.Path {
				out = append(out, p)
			}
		}
	}
	return out
}

// Errors reports whether any file or workspace rule has an error.
func (w *Workspace) Errors() bool {
	for _, p := range w.AllProblems() {
		if p.Severity == SeverityError {
			return true
		}
	}
	return false
}
