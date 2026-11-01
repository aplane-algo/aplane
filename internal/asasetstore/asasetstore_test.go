// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package asasetstore

import (
	"bytes"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/asaset"
	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

var masterKey = []byte("01234567890123456789012345678901")

func generation(t *testing.T) storepaths.GenPaths {
	t.Helper()
	gen := storepaths.NewPaths(t.TempDir()).GenerationPaths("gen-1-0123abcd")
	if err := os.MkdirAll(gen.Dir(), 0o700); err != nil {
		t.Fatal(err)
	}
	return gen
}

func sampleSet(t *testing.T) *asaset.Set {
	t.Helper()
	s, err := asaset.New([]asaset.Entry{{
		Identity:              asaset.Identity{Genesis: asaset.GenesisHash{1}, AssetID: 7},
		Name:                  "Example",
		UnitName:              "XYZ",
		Decimals:              2,
		Creator:               types.Address{3}.String(),
		ConfirmedAt:           time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC),
		NetworkAtConfirmation: "private-dev",
	}})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestWriteThenLoad(t *testing.T) {
	gen := generation(t)
	kr := cryptotest.Keyring(t, masterKey)
	if err := Write(gen, sampleSet(t), kr, time.Unix(100, 0)); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{gen.ASASetPath(), gen.ASASetIntegritySidecar()} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v, mode %v; want 0600", path, err, info.Mode().Perm())
		}
	}
	got, err := Load(gen, cryptotest.Keyring(t, masterKey))
	if err != nil {
		t.Fatal(err)
	}
	if e := got.Entries(); len(e) != 1 || e[0].UnitName != "XYZ" {
		t.Fatalf("loaded %+v", e)
	}
}

func TestAbsentIsEmpty(t *testing.T) {
	got, err := Load(generation(t), cryptotest.Keyring(t, masterKey))
	if err != nil || len(got.Entries()) != 0 {
		t.Fatalf("Load() = %+v, %v; want the empty set", got, err)
	}
}

// Every way short of a valid, authenticated file fails, and none of them
// reads as an empty set.
func TestIntegrityFailuresAreNotEmpty(t *testing.T) {
	kr := cryptotest.Keyring(t, masterKey)
	tests := map[string]struct {
		damage func(t *testing.T, gen storepaths.GenPaths)
		want   error
	}{
		"file without sidecar": {func(t *testing.T, gen storepaths.GenPaths) { remove(t, gen.ASASetIntegritySidecar()) }, ErrMissingSidecar},
		"sidecar without file": {func(t *testing.T, gen storepaths.GenPaths) { remove(t, gen.ASASetPath()) }, ErrMissingFile},
		"tampered file": {func(t *testing.T, gen storepaths.GenPaths) {
			data := read(t, gen.ASASetPath())
			write(t, gen.ASASetPath(), bytes.Replace(data, []byte(`"decimals": 2`), []byte(`"decimals": 9`), 1))
		}, ErrMismatch},
		"garbled sidecar": {func(t *testing.T, gen storepaths.GenPaths) { write(t, gen.ASASetIntegritySidecar(), []byte("{")) }, ErrBadSidecar},
		"authenticated but invalid": {func(t *testing.T, gen storepaths.GenPaths) {
			bad := []byte(`{"format": "aplane.asa-set.v1", "assets": [{}]}` + "\n")
			sc, err := signSidecar(bad, kr, time.Unix(1, 0))
			if err != nil {
				t.Fatal(err)
			}
			write(t, gen.ASASetPath(), bad)
			write(t, gen.ASASetIntegritySidecar(), sc)
		}, ErrInvalid},
		// The sidecar is bound to this file's integrity domain: a policy
		// sidecar over the very same bytes does not authenticate it.
		"another file's sidecar": {func(t *testing.T, gen storepaths.GenPaths) {
			psc, err := policy.SignPolicyIntegrity(read(t, gen.ASASetPath()), kr, time.Unix(1, 0))
			if err != nil {
				t.Fatal(err)
			}
			pbytes, err := policy.MarshalPolicyIntegritySidecar(psc)
			if err != nil {
				t.Fatal(err)
			}
			write(t, gen.ASASetIntegritySidecar(), pbytes)
		}, ErrIntegrity},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			gen := generation(t)
			if err := Write(gen, sampleSet(t), kr, time.Unix(100, 0)); err != nil {
				t.Fatal(err)
			}
			tc.damage(t, gen)
			got, err := Load(gen, kr)
			if err == nil || got != nil {
				t.Fatalf("Load() = %+v, %v; want an integrity failure", got, err)
			}
			if !errors.Is(err, ErrIntegrity) || !errors.Is(err, tc.want) {
				t.Fatalf("Load() error = %v; want %v", err, tc.want)
			}
		})
	}
}

func TestAnotherKeyringCannotAuthenticate(t *testing.T) {
	gen := generation(t)
	if err := Write(gen, sampleSet(t), cryptotest.Keyring(t, masterKey), time.Unix(100, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(gen, cryptotest.Keyring(t, bytes.Repeat([]byte{0x42}, 32))); !errors.Is(err, ErrMismatch) {
		t.Fatalf("Load() with another keyring error = %v; want a mismatch", err)
	}
}

func TestResignMovesToTheNewKeyring(t *testing.T) {
	gen := generation(t)
	oldKR := cryptotest.Keyring(t, masterKey)
	newKR := cryptotest.Keyring(t, bytes.Repeat([]byte{0x42}, 32))
	if err := Write(gen, sampleSet(t), oldKR, time.Unix(100, 0)); err != nil {
		t.Fatal(err)
	}
	data := read(t, gen.ASASetPath())
	resigned, err := Resign(data, read(t, gen.ASASetIntegritySidecar()), oldKR, newKR, time.Unix(200, 0))
	if err != nil {
		t.Fatal(err)
	}
	write(t, gen.ASASetIntegritySidecar(), resigned)
	if _, err := Load(gen, newKR); err != nil {
		t.Fatalf("Load() under the new keyring: %v", err)
	}
	if _, err := Load(gen, oldKR); err == nil {
		t.Fatal("the old keyring still authenticates the re-signed set")
	}
	if _, err := Resign(append(data, ' '), read(t, gen.ASASetIntegritySidecar()), newKR, oldKR, time.Unix(300, 0)); err == nil {
		t.Fatal("Resign accepted bytes its sidecar does not authenticate")
	}
}

func remove(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func write(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
