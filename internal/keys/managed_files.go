// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keys

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/witness"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

const (
	AccountKeyExtension         = ".key"
	CosignerCredentialExtension = ".cos"
)

// MaxCosignerCredentials caps the cosigner credentials one store holds. With
// the cap on cosigner policy documents it bounds the admin policy summary,
// which lists every key, to one admin message.
const MaxCosignerCredentials = 8192

// ErrCosignerCredentialLimit reports that a store already holds
// MaxCosignerCredentials cosigner credentials.
var ErrCosignerCredentialLimit = errors.New("cosigner credential limit reached")

// CountCosignerCredentials counts the cosigner credentials in a key
// namespace by file name.
func CountCosignerCredentials(keysDir string) (int, error) {
	entries, err := os.ReadDir(keysDir)
	if err != nil && !os.IsNotExist(err) {
		return 0, err
	}
	count := 0
	for _, entry := range entries {
		if _, class, ok := ParseManagedCredentialFilename(entry.Name()); ok && class == ManagedCredentialCosigner {
			count++
		}
	}
	return count, nil
}

type ManagedCredentialClass string

type ManagedCredentialFile struct {
	Selector string
	Class    ManagedCredentialClass
	Name     string
	Path     string
}

const (
	ManagedCredentialAccount  ManagedCredentialClass = "account"
	ManagedCredentialCosigner ManagedCredentialClass = "cosigner"
)

var (
	ErrManagedCredentialClassMismatch    = errors.New("managed credential filename class mismatch")
	ErrManagedCredentialSelectorMismatch = errors.New("managed credential filename selector mismatch")
	ErrManagedCredentialClassConflict    = errors.New("contradictory managed credential class exists")
	ErrManagedCredentialExists           = errors.New("managed credential already exists")
)

// ManagedCredentialClassForCategory maps a canonical payload category to its
// sole signer-managed filename class.
func ManagedCredentialClassForCategory(category string) (ManagedCredentialClass, error) {
	switch category {
	case CategoryEd25519, CategoryNativePQ, CategoryDSALsig, CategoryGenericLsig:
		return ManagedCredentialAccount, nil
	case CategoryWitness:
		return ManagedCredentialCosigner, nil
	default:
		return "", fmt.Errorf("unsupported managed credential category %q", category)
	}
}

func (c ManagedCredentialClass) Extension() string {
	switch c {
	case ManagedCredentialAccount:
		return AccountKeyExtension
	case ManagedCredentialCosigner:
		return CosignerCredentialExtension
	default:
		return ""
	}
}

// ParseManagedCredentialFilename recognizes only signer-managed private
// credential files. Standalone .wit artifacts and public sidecars are never
// candidates.
func ParseManagedCredentialFilename(name string) (selector string, class ManagedCredentialClass, ok bool) {
	switch {
	case strings.HasSuffix(name, AccountKeyExtension):
		selector = strings.TrimSuffix(name, AccountKeyExtension)
		class = ManagedCredentialAccount
	case strings.HasSuffix(name, CosignerCredentialExtension):
		selector = strings.TrimSuffix(name, CosignerCredentialExtension)
		class = ManagedCredentialCosigner
	default:
		return "", "", false
	}
	if selector == "" || filepath.Base(name) != name {
		return "", "", false
	}
	return selector, class, true
}

// ScanManagedCredentialFiles returns concrete private credential paths for
// both managed filename classes. It does not open or validate payloads.
func ScanManagedCredentialFiles(dir string) ([]ManagedCredentialFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read managed credential directory: %w", err)
	}

	files := make([]ManagedCredentialFile, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		selector, class, ok := ParseManagedCredentialFilename(entry.Name())
		if !ok {
			continue
		}
		files = append(files, ManagedCredentialFile{
			Selector: selector,
			Class:    class,
			Name:     entry.Name(),
			Path:     filepath.Join(dir, entry.Name()),
		})
	}
	return files, nil
}

func CanonicalManagedCredentialFilename(selector, category string) (string, error) {
	class, err := ManagedCredentialClassForCategory(category)
	if err != nil {
		return "", err
	}
	if err := validateManagedSelector(selector, class); err != nil {
		return "", err
	}
	return selector + class.Extension(), nil
}

func CanonicalManagedCredentialPath(paths storepaths.Paths, selector, category string) (string, error) {
	active, err := genstore.ResolveActive(paths)
	if err != nil {
		return "", err
	}
	return CanonicalManagedCredentialPathActive(active, selector, category)
}

// CanonicalManagedCredentialPathActive is CanonicalManagedCredentialPath
// against an authenticated generation capability.
func CanonicalManagedCredentialPathActive(active storepaths.ActivePaths, selector, category string) (string, error) {
	name, err := CanonicalManagedCredentialFilename(selector, category)
	if err != nil {
		return "", err
	}
	return filepath.Join(active.KeysDir(), name), nil
}

// AccountKeyFilePath is for code that already owns a validated Algorand
// account address. Canonical writers should prefer CanonicalManagedCredentialPath.
func AccountKeyFilePath(paths storepaths.Paths, address string) string {
	return AccountKeyFilePathActive(mustResolveActive(paths), address)
}

// AccountKeyFilePathActive is AccountKeyFilePath against resolved
// active-store paths.
func AccountKeyFilePathActive(active storepaths.ActivePaths, address string) string {
	return filepath.Join(active.KeysDir(), address+AccountKeyExtension)
}

// CosignerCredentialFilePath is for code that already owns a validated Witness
// Key ID. Canonical writers should prefer CanonicalManagedCredentialPath.
func CosignerCredentialFilePath(paths storepaths.Paths, witnessKeyID string) string {
	return CosignerCredentialFilePathActive(mustResolveActive(paths), witnessKeyID)
}

// mustResolveActive backs the string-returning convenience path builders,
// which have no production callers (writers use the Active variants); a
// present-but-invalid store-root selection panics rather than inventing an
// active path.
func mustResolveActive(paths storepaths.Paths) storepaths.ActivePaths {
	generationID, ok := paths.BoundActiveGeneration()
	if !ok {
		panic("active generation capability is not bound; authenticate store-root.enc first")
	}
	return paths.GenerationPaths(generationID)
}

// CosignerCredentialFilePathActive is CosignerCredentialFilePath against
// resolved active-store paths.
func CosignerCredentialFilePathActive(active storepaths.ActivePaths, witnessKeyID string) string {
	return filepath.Join(active.KeysDir(), witnessKeyID+CosignerCredentialExtension)
}

// ManagedCredentialDestination reports the canonical destination and whether
// it exists, while rejecting an active file in the contradictory class.
func ManagedCredentialDestination(paths storepaths.Paths, selector, category string) (string, bool, error) {
	active, err := genstore.ResolveActive(paths)
	if err != nil {
		return "", false, err
	}
	return ManagedCredentialDestinationActive(active, selector, category)
}

// ManagedCredentialDestinationActive is ManagedCredentialDestination against
// resolved active-store paths.
func ManagedCredentialDestinationActive(active storepaths.ActivePaths, selector, category string) (string, bool, error) {
	class, err := ManagedCredentialClassForCategory(category)
	if err != nil {
		return "", false, err
	}
	canonicalPath, err := CanonicalManagedCredentialPathActive(active, selector, category)
	if err != nil {
		return "", false, err
	}

	otherClass := ManagedCredentialAccount
	if class == ManagedCredentialAccount {
		otherClass = ManagedCredentialCosigner
	}
	contradictoryPath := filepath.Join(active.KeysDir(), selector+otherClass.Extension())
	if _, err := os.Lstat(contradictoryPath); err == nil {
		return "", false, fmt.Errorf("%w: %s", ErrManagedCredentialClassConflict, contradictoryPath)
	} else if !os.IsNotExist(err) {
		return "", false, fmt.Errorf("inspect contradictory managed credential %s: %w", contradictoryPath, err)
	}

	if _, err := os.Lstat(canonicalPath); err == nil {
		return canonicalPath, true, nil
	} else if !os.IsNotExist(err) {
		return "", false, fmt.Errorf("inspect managed credential destination %s: %w", canonicalPath, err)
	}
	return canonicalPath, false, nil
}

func ValidateManagedCredentialFilename(name, derivedSelector, category string) error {
	wantClass, err := ManagedCredentialClassForCategory(category)
	if err != nil {
		return err
	}
	if err := validateManagedSelector(derivedSelector, wantClass); err != nil {
		return err
	}
	gotSelector, gotClass, ok := ParseManagedCredentialFilename(name)
	if !ok {
		return fmt.Errorf("%w: %q is not a managed credential filename", ErrManagedCredentialClassMismatch, name)
	}
	if gotClass != wantClass {
		return fmt.Errorf(
			"%w: payload category %q requires %s, got %s",
			ErrManagedCredentialClassMismatch,
			category,
			wantClass.Extension(),
			gotClass.Extension(),
		)
	}
	if gotSelector != derivedSelector {
		return fmt.Errorf(
			"%w: filename selector %q does not match payload-derived selector %q",
			ErrManagedCredentialSelectorMismatch,
			gotSelector,
			derivedSelector,
		)
	}
	return nil
}

func validateManagedSelector(selector string, class ManagedCredentialClass) error {
	switch class {
	case ManagedCredentialAccount:
		address, err := types.DecodeAddress(selector)
		if err != nil || address.String() != selector {
			return fmt.Errorf("invalid canonical Algorand account selector %q", selector)
		}
		return nil
	case ManagedCredentialCosigner:
		if _, err := witness.NormalizeID(selector); err != nil {
			return fmt.Errorf("invalid canonical Witness Key ID %q: %w", selector, err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported managed credential class %q", class)
	}
}

// CredentialContext returns the envelope object context for a managed
// credential identified by its canonical selector and payload category.
func CredentialContext(selector, category string) (crypto.ObjectContext, error) {
	class, err := ManagedCredentialClassForCategory(category)
	if err != nil {
		return crypto.ObjectContext{}, err
	}
	return contextForClass(selector, class)
}

// CredentialContextForFile recovers the object context from a managed
// credential's canonical filename.
//
// Reading identity out of the name is safe because the name is canonical and
// derived from the selector: the store never renames a credential, and a file
// moved under another name simply fails to open, which is the detection this
// binding exists to provide. The directory the file sits in is deliberately
// ignored — generations copy credentials between namespaces without
// re-encrypting them.
func CredentialContextForFile(path string) (crypto.ObjectContext, error) {
	selector, class, ok := ParseManagedCredentialFilename(filepath.Base(path))
	if !ok {
		return crypto.ObjectContext{}, fmt.Errorf(
			"%q is not a canonical managed credential filename", filepath.Base(path),
		)
	}
	return contextForClass(selector, class)
}

// Context returns the object context for a scanned managed credential.
func (f ManagedCredentialFile) Context() (crypto.ObjectContext, error) {
	return contextForClass(f.Selector, f.Class)
}

func contextForClass(selector string, class ManagedCredentialClass) (crypto.ObjectContext, error) {
	switch class {
	case ManagedCredentialAccount:
		return crypto.AccountKeyContext(selector), nil
	case ManagedCredentialCosigner:
		return crypto.CosignerCredentialContext(selector), nil
	default:
		return crypto.ObjectContext{}, fmt.Errorf("unsupported managed credential class %q", class)
	}
}
