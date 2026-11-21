// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sourcetokens

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/keyclass"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// This file reads and writes token files in one already-resolved generation:
// source_tokens/<selector>.enc, and deleted/source_tokens/<selector>.enc for
// a deleted key's. The caller holds the store mutation lock for every write.

// Selectors lists the selectors with a token file in the generation, sorted,
// after checking that the namespace holds only canonical <selector>.enc
// regular files. It decrypts nothing.
func Selectors(active storepaths.GenPaths) ([]string, error) {
	entries, err := os.ReadDir(active.SourceTokensDir())
	if err != nil {
		return nil, fmt.Errorf("read source tokens: %w", err)
	}
	selectors := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		selector, ok := strings.CutSuffix(name, storepaths.SourceTokenFileExtension)
		if !ok || ValidateSelector(selector) != nil || !entry.Type().IsRegular() {
			return nil, fmt.Errorf("source tokens contain unsupported entry %q", name)
		}
		selectors = append(selectors, selector)
	}
	slices.Sort(selectors)
	return selectors, nil
}

// LoadFiles decrypts and decodes every token file in the generation for a
// node of role, sorted by selector. Each must open as its own selector's
// (its name is the only identity it has), hold the schema, and be within the
// limits. Token files exist only on cosigner nodes: one on any other node is
// a node role conflict (keyclass.ErrNodeRoleConflict), which fails the node
// closed as a role-forbidden key does. Nothing else is checked, notably not
// whether a policy document uses a token. The caller zeroes the files.
func LoadFiles(active storepaths.GenPaths, role noderole.Role, kr *crypto.Keyring) ([]*File, error) {
	selectors, err := Selectors(active)
	if err != nil {
		return nil, err
	}
	if len(selectors) > 0 && role != noderole.RoleCosigner {
		return nil, fmt.Errorf("%w: node role %q does not allow source token files: %s",
			keyclass.ErrNodeRoleConflict, role, strings.Join(selectors, ", "))
	}
	files := make([]*File, 0, len(selectors))
	for _, selector := range selectors {
		f, err := readFile(active.SourceTokenPath(selector), selector, kr)
		if err != nil {
			zeroFiles(files)
			return nil, err
		}
		files = append(files, f)
	}
	return files, nil
}

// LoadIndex is LoadFiles made into a runtime index.
func LoadIndex(active storepaths.GenPaths, role noderole.Role, kr *crypto.Keyring) (*Index, error) {
	files, err := LoadFiles(active, role, kr)
	if err != nil {
		return nil, err
	}
	defer zeroFiles(files)
	return NewIndex(files), nil
}

// ReadFile reads selector's token file from the generation. ok is false when
// selector has none.
func ReadFile(active storepaths.GenPaths, selector string, kr *crypto.Keyring) (f *File, ok bool, err error) {
	if err := ValidateSelector(selector); err != nil {
		return nil, false, err
	}
	path := active.SourceTokenPath(selector)
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return nil, false, nil
	} else if err != nil {
		return nil, false, err
	}
	f, err = readFile(path, selector, kr)
	if err != nil {
		return nil, false, err
	}
	return f, true, nil
}

// Listings reads the token files of the named selectors, or of every
// selector with one when none is named, and returns each selector's tokens
// by source name without their values. A named selector without a file is
// left out. Each file must open as its own selector's, as LoadFiles requires;
// every token decrypted is zeroed before Listings returns.
func Listings(active storepaths.GenPaths, kr *crypto.Keyring, selectors ...string) (map[string][]Entry, error) {
	if len(selectors) == 0 {
		var err error
		if selectors, err = Selectors(active); err != nil {
			return nil, err
		}
	}
	out := make(map[string][]Entry, len(selectors))
	for _, selector := range selectors {
		f, ok, err := ReadFile(active, selector, kr)
		if err != nil {
			return nil, err
		}
		if ok {
			out[selector] = f.Listing()
			f.Zero()
		}
	}
	return out, nil
}

// Names is Listings reduced to the source names with a token, by selector.
func Names(active storepaths.GenPaths, kr *crypto.Keyring) (map[string][]string, error) {
	listings, err := Listings(active, kr)
	if err != nil {
		return nil, err
	}
	out := make(map[string][]string, len(listings))
	for selector, entries := range listings {
		for _, entry := range entries {
			out[selector] = append(out[selector], entry.Source)
		}
	}
	return out, nil
}

// VerifyArchived opens one file of the deleted archive as the token file its
// name says it is, and zeroes what it decrypted.
func VerifyArchived(active storepaths.GenPaths, name string, kr *crypto.Keyring) error {
	selector, ok := strings.CutSuffix(name, storepaths.SourceTokenFileExtension)
	if !ok || ValidateSelector(selector) != nil {
		return fmt.Errorf("unsupported archived source token file %q", name)
	}
	f, err := readFile(active.DeletedSourceTokenPath(selector), selector, kr)
	if err != nil {
		return fmt.Errorf("archived %w", err)
	}
	f.Zero()
	return nil
}

func readFile(path, selector string, kr *crypto.Keyring) (*File, error) {
	data, _, err := fsutil.ReadRegularFileLimited(path, MaxFileBytes)
	if err != nil {
		return nil, fmt.Errorf("source tokens of %s: %w", selector, err)
	}
	return Open(data, selector, kr)
}

// WriteFile seals f and writes it as its selector's token file, durably:
// temp file, fsync, rename, directory fsync. It refuses a file over
// MaxFileBytes before writing anything. An error wrapping
// fsutil.ErrPublishedNotDurable means the new file is in place but may not
// survive a crash; any other error leaves the old file as it was.
func WriteFile(active storepaths.GenPaths, f *File, kr *crypto.Keyring) error {
	if f == nil {
		return fmt.Errorf("source token file is nil")
	}
	sealed, err := Seal(f, kr)
	if err != nil {
		return err
	}
	if err := fsutil.WriteFileDurable(active.SourceTokenPath(f.Selector), sealed); err != nil {
		return fmt.Errorf("write source tokens of %s: %w", f.Selector, err)
	}
	return nil
}

// RemoveFile deletes selector's token file durably. It is how the last token
// of a selector is removed: nothing is archived. A file that does not exist
// is not an error.
func RemoveFile(active storepaths.GenPaths, selector string) error {
	if err := ValidateSelector(selector); err != nil {
		return err
	}
	if err := fsutil.RemoveDurable(active.SourceTokenPath(selector)); err != nil {
		return fmt.Errorf("remove source tokens of %s: %w", selector, err)
	}
	return nil
}

// ArchivePath returns the path of selector's token file when it has one, for
// a key deletion to preflight against the deleted-archive bounds with the
// key's other files. ok is false when selector has none.
func ArchivePath(active storepaths.GenPaths, selector string) (path string, ok bool, err error) {
	if ValidateSelector(selector) != nil {
		// A signer key's address never has a token file.
		return "", false, nil
	}
	path = active.SourceTokenPath(selector)
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return "", false, nil
	} else if err != nil {
		return "", false, err
	}
	return path, true, nil
}

// Archive moves a deleted key's token file into the deleted archive,
// replacing an earlier archived file for the same key. Key deletion is the
// only operation that archives token files. It is a no-op when the key has
// none.
func Archive(active storepaths.GenPaths, selector string) error {
	path, ok, err := ArchivePath(active, selector)
	if err != nil || !ok {
		return err
	}
	archiveDir := active.DeletedSourceTokensDir()
	if err := fsutil.MkdirAllPrivate(archiveDir); err != nil {
		return fmt.Errorf("create deleted source tokens directory: %w", err)
	}
	if err := os.Rename(path, filepath.Join(archiveDir, filepath.Base(path))); err != nil {
		return fmt.Errorf("archive source tokens of %s: %w", selector, err)
	}
	if err := fsutil.SyncDir(active.SourceTokensDir()); err != nil {
		return err
	}
	return fsutil.SyncDir(archiveDir)
}

func zeroFiles(files []*File) {
	for _, f := range files {
		f.Zero()
	}
}
