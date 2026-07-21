// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keys

import (
	"errors"
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

	paths := storepaths.NewPaths("/store")
	path, err := CanonicalManagedCredentialPath(paths, "default", witnessID, CategoryWitness)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join("/store", "identities", "default", "keys", witnessName); path != want {
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
