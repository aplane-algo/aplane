// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keytypestate

import (
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

type gatedStub struct {
	lsigprovider.LSigProvider
	gated bool
}

func (gatedStub) KeyType() string                           { return "test.gated-state.v1" }
func (gatedStub) RoutingFamily() string                     { return "test.gated-state" }
func (gatedStub) Version() int                              { return 1 }
func (gatedStub) Category() string                          { return lsigprovider.CategoryDSALsig }
func (s gatedStub) GenerationRequiresCurrentApproval() bool { return s.gated }
func (gatedStub) CompatibilityFingerprint() string {
	return "1:" + strings.Repeat("b", 64)
}

func TestNeedsApproval(t *testing.T) {
	const keyType = "test.gated-state.v1"
	current := "1:" + strings.Repeat("b", 64)
	for _, test := range []struct {
		name   string
		gated  bool
		record *Record
		want   bool
	}{
		{"no record", true, nil, true},
		{"disabled record", true, &Record{State: StateDisabled, Fingerprint: current}, true},
		{"current approval", true, &Record{State: StateEnabled, Fingerprint: current}, false},
		{"stale approval", true, &Record{State: StateEnabled, Fingerprint: "1:" + strings.Repeat("a", 64)}, true},
		{"not gated", false, &Record{State: StateEnabled, Fingerprint: "1:" + strings.Repeat("a", 64)}, false},
		{"not gated and no record", false, nil, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			lsigprovider.Register(gatedStub{gated: test.gated})
			t.Cleanup(func() { lsigprovider.Unregister(keyType) })
			paths := genstoretest.MintFirst(t, storepaths.NewPaths(t.TempDir()))
			if test.record != nil {
				record := *test.record
				record.KeyType, record.Source = keyType, SourceCompiled
				if err := Put(paths, record); err != nil {
					t.Fatal(err)
				}
			}
			got, err := NeedsApproval(paths, keyType)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("NeedsApproval() = %v, want %v", got, test.want)
			}
		})
	}
}
