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

// Workspace is the set of policy files an editing or check session works on:
// the files it was opened with, and every *.json file directly inside each
// directory it was opened with. All of them are one bundle, so the rules
// across files hold however the files were named. Documents are identified
// by their "key" field, never by file name, so files keep the names people
// gave them.
type Workspace struct {
	// Paths are the files and directories opened.
	Paths []string
	// Role is the role the workspace's documents are for: the first valid
	// role a file names, in load order.
	Role  noderole.Role
	Files []*File
	// Problems are the rules across files: at most one default, no key in two
	// files, and one role throughout. They are reported per file, so a file
	// stays open and repairable while it breaks one.
	Problems []Problem
}

// Open loads the files and directories in paths as one workspace. A
// directory contributes the *.json files directly inside it, in name order;
// a file named twice, directly or through its directory, is loaded once. Open
// fails only when a path cannot be opened at all; a file that cannot be read
// or decoded is loaded with its problems.
func Open(paths ...string) (*Workspace, error) {
	w := &Workspace{Paths: paths}
	var files []string
	seen := map[string]bool{}
	add := func(file string) error {
		abs, err := filepath.Abs(file)
		if err != nil {
			return err
		}
		if !seen[abs] {
			seen[abs] = true
			files = append(files, file)
		}
		return nil
	}
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			if err := add(path); err != nil {
				return nil, err
			}
			continue
		}
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil, err
		}
		var names []string
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".json") && !e.IsDir() {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)
		for _, name := range names {
			if err := add(filepath.Join(path, name)); err != nil {
				return nil, err
			}
		}
	}

	for _, p := range files {
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
