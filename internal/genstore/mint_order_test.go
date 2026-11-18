// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package genstore

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// Mint refuses a request before it stages anything, and when a request is
// wrong in two ways it is the earlier check that answers. Each case below is
// wrong in the way its name says and in a way a later check would catch, so
// the error names which check ran first.
func TestMintRefusesInOrder(t *testing.T) {
	apply := func(storepaths.GenPaths) error { return nil }
	valid := func(t *testing.T) MintRequest {
		return MintRequest{
			SkipCandidateValidation: true, GenerationID: testGenD, Parent: testGenC, Integrity: testKeyring(t),
			Operation: "test-activation", OperationID: "op-order", CreatedAt: time.Unix(1_753_500_950, 0),
		}
	}
	const (
		established = iota // root selects C, the newest of A, B and C
		rootless           // A, B and C on disk and no store root
		empty              // nothing
		residue            // established, with a staging directory left behind
	)
	tests := []struct {
		name    string
		store   int
		request func(t *testing.T, r MintRequest) MintRequest
		want    string // what the error starts with
	}{
		// The request's own shape, in the order it is checked.
		{"a bad generation ID before a missing operation", established, func(t *testing.T, r MintRequest) MintRequest {
			r.GenerationID, r.Operation = "not-a-generation", ""
			return r
		}, `invalid generation ID "not-a-generation"`},
		{"a missing operation before missing candidate validation", established, func(t *testing.T, r MintRequest) MintRequest {
			r.OperationID, r.SkipCandidateValidation = "", false
			return r
		}, "mint requires a durable operation identity"},
		{"missing candidate validation before an empty reconstruction with no apply", established, func(t *testing.T, r MintRequest) MintRequest {
			r.SkipCandidateValidation, r.StartEmpty = false, true
			return r
		}, "mint requires candidate validation"},
		{"an empty reconstruction with no apply before a rollback source that is the parent", established, func(t *testing.T, r MintRequest) MintRequest {
			r.StartEmpty, r.RollbackSourceGenerationID = true, r.Parent
			return r
		}, "empty reconstruction requires a parent and apply function"},
		{"a rollback source with no apply before one that is the parent", established, func(t *testing.T, r MintRequest) MintRequest {
			r.RollbackSourceGenerationID = r.Parent
			return r
		}, "rollback source requires a parent and apply function"},
		{"a rollback source that is the parent before a missing keyring", established, func(t *testing.T, r MintRequest) MintRequest {
			r.RollbackSourceGenerationID, r.Apply, r.Integrity = r.Parent, apply, nil
			return r
		}, "rollback source must differ from the outgoing parent"},
		{"a parent with no keyring before a first mint with no passphrase", established, func(t *testing.T, r MintRequest) MintRequest {
			r.Integrity, r.FirstGeneration = nil, true
			return r
		}, "mint with a parent requires an integrity keyring"},
		{"no keyring before a first mint with no passphrase", established, func(t *testing.T, r MintRequest) MintRequest {
			r.Parent, r.Integrity, r.FirstGeneration = "", nil, true
			return r
		}, "store-root mint requires an integrity keyring"},
		{"a first mint with no passphrase before a pre-sealed parent that is missing", established, func(t *testing.T, r MintRequest) MintRequest {
			r.Parent, r.FirstGeneration, r.OutgoingSealAlreadyWritten = "", true, true
			return r
		}, "store-root first mint requires an initial passphrase"},
		{"a pre-sealed parent that is missing before a half-given replacement root", established, func(t *testing.T, r MintRequest) MintRequest {
			r.Parent, r.OutgoingSealAlreadyWritten, r.ReplacementPassphrase = "", true, []byte("next")
			return r
		}, "pre-sealed outgoing generation requires a parent"},
		{"a half-given replacement root before a stale parent", established, func(t *testing.T, r MintRequest) MintRequest {
			r.Parent, r.ReplacementPassphrase = testGenA, []byte("next")
			return r
		}, "replacement root requires a successor, a pre-sealed outgoing generation, a successor keyring, and a passphrase"},
		{"a replacement root on a first mint", established, func(t *testing.T, r MintRequest) MintRequest {
			r.Parent, r.FirstGeneration, r.InitialPassphrase = "", true, testStoreRootPassphrase
			r.ReplacementKeyring, r.ReplacementPassphrase = testKeyring(t), []byte("next")
			return r
		}, "replacement root requires a successor"},

		// A first mint.
		{"a first mint with a parent before the store root is looked for", established, func(t *testing.T, r MintRequest) MintRequest {
			r.FirstGeneration, r.InitialPassphrase = true, testStoreRootPassphrase
			return r
		}, "atomic store-root first mint must be parentless"},
		{"a first mint over a store root", established, func(t *testing.T, r MintRequest) MintRequest {
			r.Parent, r.FirstGeneration, r.InitialPassphrase = "", true, testStoreRootPassphrase
			return r
		}, "mint: store root already exists"},
		{"a first mint over generations with no root", rootless, func(t *testing.T, r MintRequest) MintRequest {
			r.Parent, r.FirstGeneration, r.InitialPassphrase = "", true, testStoreRootPassphrase
			return r
		}, "first mint: "},

		// A successor mint.
		{"a successor with no parent before the store root is read", empty, func(t *testing.T, r MintRequest) MintRequest {
			r.Parent = ""
			return r
		}, "atomic store-root successor mint requires a parent"},
		{"a successor on a store with no root", rootless, func(t *testing.T, r MintRequest) MintRequest {
			return r
		}, "mint: "},
		{"a keyring that is not the store's before a stale parent", established, func(t *testing.T, r MintRequest) MintRequest {
			r.Parent, r.Integrity = testGenA, cryptotest.Keyring(t, bytes.Repeat([]byte{0x33}, 32))
			return r
		}, "mint: authenticate store root: "},
		{"a stale parent before the store is checked for residue", residue, func(t *testing.T, r MintRequest) MintRequest {
			r.Parent = testGenA
			return r
		}, `mint parent "` + testGenA + `" is not the store-root current generation ` + testGenC},
		{"a store that needs reconciling", residue, func(t *testing.T, r MintRequest) MintRequest {
			return r
		}, "mint preflight: generation store requires reconciliation before another mint"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paths := storepaths.NewPaths(t.TempDir())
			if tt.store != empty {
				buildGenerationChain(t, paths)
			}
			switch tt.store {
			case rootless:
				if err := os.Remove(paths.StoreRootPath()); err != nil {
					t.Fatal(err)
				}
			case residue:
				if err := os.Mkdir(filepath.Join(paths.GenerationsDir(), storepaths.GenerationStagingPrefix+"left-behind"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			before := generationNames(t, paths)

			_, err := Mint(paths, tt.request(t, valid(t)))
			if err == nil || !strings.HasPrefix(err.Error(), tt.want) {
				t.Fatalf("error = %v, want one starting %q", err, tt.want)
			}
			// A refused mint stages and publishes nothing.
			if after := generationNames(t, paths); strings.Join(after, ",") != strings.Join(before, ",") {
				t.Fatalf("generations directory changed: %v, was %v", after, before)
			}
		})
	}
}

// generationNames lists the generations directory, or nothing when there is
// none.
func generationNames(t *testing.T, paths storepaths.Paths) []string {
	t.Helper()
	entries, err := os.ReadDir(paths.GenerationsDir())
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}
