// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keys

import (
	"errors"
	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	"os"
	"path/filepath"
	"testing"

	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/witness"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestManagedCredentialClassForCategory(t *testing.T) {
	tests := []struct {
		category string
		class    ManagedCredentialClass
		ext      string
	}{
		{CategoryEd25519, ManagedCredentialAccount, AccountKeyExtension},
		{CategoryDSALsig, ManagedCredentialAccount, AccountKeyExtension},
		{CategoryGenericLsig, ManagedCredentialAccount, AccountKeyExtension},
		{CategoryWitness, ManagedCredentialSentry, SentryCredentialExtension},
	}
	for _, test := range tests {
		class, err := ManagedCredentialClassForCategory(test.category)
		if err != nil {
			t.Fatalf("ManagedCredentialClassForCategory(%q): %v", test.category, err)
		}
		if class != test.class || class.Extension() != test.ext {
			t.Fatalf("category %q = (%q, %q), want (%q, %q)", test.category, class, class.Extension(), test.class, test.ext)
		}
	}
	if _, err := ManagedCredentialClassForCategory("future"); err == nil {
		t.Fatal("unknown category was accepted")
	}
}

func TestCanonicalManagedCredentialFilename(t *testing.T) {
	account := types.Address{1}.String()
	witnessID, err := witness.ID(witness.Falcon1024V1, make([]byte, witness.Falcon1024PublicKeySize))
	if err != nil {
		t.Fatal(err)
	}

	accountName, err := CanonicalManagedCredentialFilename(account, CategoryEd25519)
	if err != nil {
		t.Fatal(err)
	}
	if accountName != account+AccountKeyExtension {
		t.Fatalf("account filename = %q", accountName)
	}
	witnessName, err := CanonicalManagedCredentialFilename(witnessID, CategoryWitness)
	if err != nil {
		t.Fatal(err)
	}
	if witnessName != witnessID+SentryCredentialExtension {
		t.Fatalf("witness filename = %q", witnessName)
	}

	paths := storepaths.NewPaths(t.TempDir())
	genstoretest.MintFirst(t, paths, "default")
	path, err := CanonicalManagedCredentialPath(paths, "default", witnessID, CategoryWitness)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(activeKeysDirForTest(t, paths, "default"), witnessName); path != want {
		t.Fatalf("path = %q, want %q", path, want)
	}

	if _, err := CanonicalManagedCredentialFilename(witnessID, CategoryEd25519); err == nil {
		t.Fatal("Witness Key ID was accepted as an account selector")
	}
	if _, err := CanonicalManagedCredentialFilename(account, CategoryWitness); err == nil {
		t.Fatal("account address was accepted as a Witness Key ID")
	}
}

func TestValidateManagedCredentialFilename(t *testing.T) {
	account := types.Address{2}.String()
	witnessID, err := witness.ID(witness.Falcon1024V1, make([]byte, witness.Falcon1024PublicKeySize))
	if err != nil {
		t.Fatal(err)
	}

	if err := ValidateManagedCredentialFilename(account+AccountKeyExtension, account, CategoryEd25519); err != nil {
		t.Fatal(err)
	}
	if err := ValidateManagedCredentialFilename(witnessID+SentryCredentialExtension, witnessID, CategoryWitness); err != nil {
		t.Fatal(err)
	}
	if err := ValidateManagedCredentialFilename(witnessID+AccountKeyExtension, witnessID, CategoryWitness); !errors.Is(err, ErrManagedCredentialClassMismatch) {
		t.Fatalf("legacy witness .key error = %v", err)
	}
	if err := ValidateManagedCredentialFilename(account+SentryCredentialExtension, account, CategoryEd25519); !errors.Is(err, ErrManagedCredentialClassMismatch) {
		t.Fatalf("account .sen error = %v", err)
	}
	other := types.Address{3}.String()
	if err := ValidateManagedCredentialFilename(other+AccountKeyExtension, account, CategoryEd25519); !errors.Is(err, ErrManagedCredentialSelectorMismatch) {
		t.Fatalf("selector mismatch error = %v", err)
	}
}

func TestParseManagedCredentialFilenameExcludesStandaloneWitnessFiles(t *testing.T) {
	for _, name := range []string{"ID.wit", "ID.wit.json", "ID.json", ".key", "dir/ID.key"} {
		if _, _, ok := ParseManagedCredentialFilename(name); ok {
			t.Fatalf("ParseManagedCredentialFilename(%q) accepted non-candidate", name)
		}
	}
	selector, class, ok := ParseManagedCredentialFilename("ID.sen")
	if !ok || selector != "ID" || class != ManagedCredentialSentry {
		t.Fatalf("ParseManagedCredentialFilename(ID.sen) = (%q, %q, %v)", selector, class, ok)
	}
}

func TestScanManagedCredentialFiles(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"ACCOUNT.key", "WITNESS.sen", "EXTERNAL.wit", "EXTERNAL.wit.json", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("test"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "DIRECTORY.key"), 0o700); err != nil {
		t.Fatal(err)
	}

	files, err := ScanManagedCredentialFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("managed files = %#v, want 2", files)
	}
	if files[0].Name != "ACCOUNT.key" || files[0].Class != ManagedCredentialAccount || files[0].Selector != "ACCOUNT" {
		t.Fatalf("account record = %#v", files[0])
	}
	if files[1].Name != "WITNESS.sen" || files[1].Class != ManagedCredentialSentry || files[1].Selector != "WITNESS" {
		t.Fatalf("sentry record = %#v", files[1])
	}
}

func TestManagedCredentialDestinationRejectsContradictoryClass(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	genstoretest.MintFirst(t, paths, "default")
	identityID := "default"
	account := types.Address{4}.String()
	if err := os.MkdirAll(activeKeysDirForTest(t, paths, identityID), 0o700); err != nil {
		t.Fatal(err)
	}
	contradictory := filepath.Join(activeKeysDirForTest(t, paths, identityID), account+SentryCredentialExtension)
	if err := os.WriteFile(contradictory, []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ManagedCredentialDestination(paths, identityID, account, CategoryEd25519); !errors.Is(err, ErrManagedCredentialClassConflict) {
		t.Fatalf("ManagedCredentialDestination() error = %v, want class conflict", err)
	}
}
