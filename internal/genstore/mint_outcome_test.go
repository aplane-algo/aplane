// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package genstore

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// Mint classifies what it left the store root selecting, so its callers need
// no read-back of their own: a failure before the root replacement is
// NotCommitted, a replacement whose durability is unknown is Uncertain, and
// a failure after the root landed, or none, is Committed.
func TestMintClassifiesWhatItLeftTheRootSelecting(t *testing.T) {
	failure := errors.New("injected")
	for _, tc := range []struct {
		name     string
		hook     func(paths storepaths.Paths) func(fsutil.HookOp, string) error
		validate func(storepaths.GenPaths) error
		after    func() error
		want     MintOutcome
		selected string // the generation the root selects afterwards
	}{
		{name: "commits", want: Committed, selected: testGenB},
		{name: "candidate rejected", validate: func(storepaths.GenPaths) error { return failure },
			want: NotCommitted, selected: testGenA},
		{name: "failure before the root replacement",
			hook: func(storepaths.Paths) func(fsutil.HookOp, string) error {
				return func(op fsutil.HookOp, path string) error {
					if op == fsutil.OpFileSync && filepath.Base(path) == storepaths.StoreRootName {
						return failure
					}
					return nil
				}
			},
			want: NotCommitted, selected: testGenA},
		{name: "replacement durability unknown",
			hook: func(paths storepaths.Paths) func(fsutil.HookOp, string) error {
				return func(op fsutil.HookOp, path string) error {
					if op == fsutil.OpDirSync && path == paths.ProductDir() {
						return failure
					}
					return nil
				}
			},
			want: Uncertain, selected: testGenB},
		{name: "failure after the root landed", after: func() error { return failure },
			want: Committed, selected: testGenB},
	} {
		t.Run(tc.name, func(t *testing.T) {
			paths := storepaths.NewPaths(t.TempDir())
			first := mintFirst(t, paths, map[string]string{"keys/A.key": "a"})
			if tc.hook != nil {
				fsutil.TestHook = tc.hook(paths)
				t.Cleanup(func() { fsutil.TestHook = nil })
			}
			req := MintRequest{
				GenerationID: testGenB, Parent: first.GenerationID(), Integrity: testKeyring(t),
				Operation: "test-outcome", OperationID: "op-outcome", CreatedAt: time.Unix(1_753_500_100, 0),
				ValidateCandidate: tc.validate, AfterRootCommit: tc.after,
			}
			if req.ValidateCandidate == nil {
				req.SkipCandidateValidation = true
			}
			_, err := Mint(paths, req)
			fsutil.TestHook = nil
			if got := MintOutcomeOf(err); got != tc.want {
				t.Fatalf("MintOutcomeOf(%v) = %v, want %v", err, got, tc.want)
			}
			if tc.want != Committed || tc.after != nil {
				if err == nil {
					t.Fatal("Mint() error = nil, want the injected failure")
				}
			}
			if got := selectedForTest(t, paths).GenerationID(); got != tc.selected {
				t.Fatalf("the root selects %s, want %s", got, tc.selected)
			}
		})
	}
}
