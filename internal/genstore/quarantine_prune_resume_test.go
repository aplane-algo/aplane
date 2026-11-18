// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package genstore

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/storepaths"
)

// A prune of a quarantined generation that is already gone finishes what an
// interrupted prune left: it removes the tombstone if one is there and
// reports the generation absent, and refuses a tombstone that is not a real
// directory.
func TestPruneQuarantinedFinishesAnInterruptedPrune(t *testing.T) {
	tests := []struct {
		name      string
		tombstone func(t *testing.T, path string)
		wantErr   string
		wantLeft  bool // the tombstone is still there afterwards
	}{
		{name: "no tombstone", tombstone: func(*testing.T, string) {}},
		{name: "a tombstone directory", tombstone: func(t *testing.T, path string) {
			if err := os.MkdirAll(filepath.Join(path, "keys"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(path, "keys", "left.key"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "a tombstone that is a file", tombstone: func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, wantErr: "quarantine prune tombstone is not a regular directory: ", wantLeft: true},
		{name: "a tombstone that is a symlink", tombstone: func(t *testing.T, path string) {
			if err := os.Symlink(t.TempDir(), path); err != nil {
				t.Fatal(err)
			}
		}, wantErr: "quarantine prune tombstone is not a regular directory: ", wantLeft: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paths := storepaths.NewPaths(t.TempDir())
			if err := os.MkdirAll(paths.QuarantinedGenerationsDir(), 0o700); err != nil {
				t.Fatal(err)
			}
			tombstone := filepath.Join(paths.QuarantineDir(), storepaths.GenerationStagingPrefix+"prune-"+testGenD)
			tt.tombstone(t, tombstone)

			results, err := PruneQuarantined(paths, []string{testGenD})
			if tt.wantErr != "" {
				if err == nil || !strings.HasPrefix(err.Error(), tt.wantErr) || len(results) != 0 {
					t.Fatalf("results %v, error %v; want an error starting %q and no results", results, err, tt.wantErr)
				}
			} else if want := []QuarantinePruneResult{{GenerationID: testGenD, AlreadyAbsent: true}}; err != nil || !reflect.DeepEqual(results, want) {
				t.Fatalf("results %v, error %v; want %v", results, err, want)
			}
			if _, statErr := os.Lstat(tombstone); (statErr == nil) != tt.wantLeft {
				t.Fatalf("tombstone left behind = %v, want %v", statErr == nil, tt.wantLeft)
			}
		})
	}
}
