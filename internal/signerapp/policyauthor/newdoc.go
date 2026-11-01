// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyauthor

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/policytext"
)

// StartingPoint is a document a new one can start from. Every field of a new
// document is written out from it; nothing is defaulted silently.
type StartingPoint struct {
	Label   string
	Summary string
	build   func(key string) (*policy.Draft, error)
}

// Draft builds the starting document for key.
func (s StartingPoint) Draft(key string) (*policy.Draft, error) { return s.build(key) }

// StartingPoints lists what a new document for role can start from: the
// shipped default for the role, a copy of each valid document of that role
// in the workspace, and the role's presets.
func (w *Workspace) StartingPoints(role noderole.Role) []StartingPoint {
	withKey := func(d *policy.Draft, key string) (*policy.Draft, error) {
		v, _ := json.Marshal(key)
		return d.Set("/key", v)
	}
	out := []StartingPoint{{
		Label:   "The shipped " + string(role) + " default",
		Summary: "the default a new " + string(role) + " store starts with",
		build: func(key string) (*policy.Draft, error) {
			data, err := policy.EmbeddedDefault(role)
			if err != nil {
				return nil, err
			}
			d, err := policy.ParseDraft(data)
			if err != nil {
				return nil, err
			}
			return withKey(d, key)
		},
	}}
	for _, f := range w.Files {
		if f.Document == nil || f.Role != role {
			continue
		}
		f := f
		out = append(out, StartingPoint{
			Label:   "A copy of " + filepath.Base(f.Path),
			Summary: "every field of that document, under the new key",
			build:   func(key string) (*policy.Draft, error) { return withKey(f.Draft, key) },
		})
	}
	for _, p := range policytext.Presets(role) {
		p := p
		out = append(out, StartingPoint{
			Label:   "Preset " + p.Name,
			Summary: p.Summary,
			build: func(key string) (*policy.Draft, error) {
				text, err := policytext.PresetTemplate(role, p.Name, key)
				if err != nil {
					return nil, err
				}
				stripped, err := policytext.StripComments([]byte(text))
				if err != nil {
					return nil, err
				}
				return policy.ParseDraft(stripped)
			},
		})
	}
	return out
}

// CheckNewKey checks a new document's key as the decoder will: "default", an
// address on a signer node, or a Witness Key ID on a cosigner node. A key
// another file in the workspace already holds is refused too.
func (w *Workspace) CheckNewKey(role noderole.Role, key string) error {
	if err := policy.ValidateDocumentKey(role, key); err != nil {
		return err
	}
	for _, f := range w.Files {
		if f.Key == key {
			return fmt.Errorf("%s already holds the document for %q", filepath.Base(f.Path), key)
		}
	}
	return nil
}

// NewFilePath is where a new document is created: in the workspace's
// directory (the first directory it was opened with, or the directory of its
// first file), under name. A name that is taken is refused.
func (w *Workspace) NewFilePath(name string) (string, error) {
	if name == "" || filepath.Base(name) != name || filepath.Ext(name) != ".json" {
		return "", fmt.Errorf("enter a file name ending in .json, with no directory")
	}
	dir := "."
	for i, p := range w.Paths {
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			dir = p
			break
		}
		if i == 0 {
			dir = filepath.Dir(p)
		}
	}
	path := filepath.Join(dir, name)
	if _, err := os.Lstat(path); err == nil {
		return "", fmt.Errorf("%s already exists", path)
	}
	for _, f := range w.Files {
		if f.Path == path {
			return "", fmt.Errorf("%s is already open", path)
		}
	}
	return path, nil
}

// Add returns a copy of the workspace holding f as well, with the rules
// across files checked again. A file outside every opened path is added to
// Paths, so reopening the workspace finds it.
func (w *Workspace) Add(f *File) *Workspace {
	c := *w
	c.Files = append(append([]*File(nil), w.Files...), f)
	covered := false
	for _, p := range w.Paths {
		if p == f.Path {
			covered = true
		}
		if info, err := os.Stat(p); err == nil && info.IsDir() && filepath.Clean(p) == filepath.Dir(f.Path) {
			covered = true
		}
	}
	if !covered {
		c.Paths = append(append([]string(nil), w.Paths...), f.Path)
	}
	c.Check()
	return &c
}
