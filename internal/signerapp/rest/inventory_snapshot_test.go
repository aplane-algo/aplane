// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rest

import (
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// The key list beside a reload is the one before it or the one after it: every
// key of one published revision, each exactly as that revision has it. A
// publish installs the keystore's maps before the runtime's, and the list once
// read both. It needs two CPUs to catch a list that does: on one, no reader runs
// between the two installs.
func TestKeyListIsOnePublishedRevision(t *testing.T) {
	ir := setupProductRuntime(t, true)
	selection, err := ir.ActivePaths()
	if err != nil {
		t.Fatal(err)
	}
	// Both revisions hold the same addresses, under other key types, and one
	// address of its own, so a list mixed from the two can't pass for either.
	revision := func(n int) keystore.Contents {
		held := make(map[string]keys.KeyScanInfo)
		for i := range 8 {
			held[types.Address{byte(i + 1)}.String()] = keys.KeyScanInfo{
				KeyFile: fmt.Sprintf("keys/%d-%d.key", n, i), KeyType: fmt.Sprintf("type-%d", n),
				Category: []string{keys.CategoryEd25519, keys.CategoryNativePQ}[n], PublicKeyHex: fmt.Sprintf("%02x%02x", n, i),
				TemplateFingerprint: []string{"fingerprint", ""}[n], ValidRekeyTarget: n == 1,
			}
		}
		held[types.Address{byte(100 + n)}.String()] = keys.KeyScanInfo{KeyFile: "keys/own.key", KeyType: fmt.Sprintf("type-%d", n)}
		return keystore.Contents{Selection: &selection, Keys: held}
	}
	var next atomic.Int32
	ir.SetBuildFunc(func(*crypto.Keyring) (*productruntime.Loaded, error) {
		return &productruntime.Loaded{Selection: &selection, PolicyVerified: true, Contents: revision(int(next.Add(1) % 2))}, nil
	}, productruntime.ReloadEffects{})
	publish := func() {
		if _, err := ir.FollowCommit(genstore.Committed); err != nil {
			t.Error(err)
		}
	}
	list := func() map[string]signerapi.KeyInfo {
		byAddress := make(map[string]signerapi.KeyInfo)
		for _, key := range (Service{}).BuildKeyInfoList(ir) {
			byAddress[key.Address] = key
		}
		return byAddress
	}
	var published [2]map[string]signerapi.KeyInfo
	for range published {
		publish()
		published[next.Load()%2] = list()
	}
	for n, kind := range []string{"ed25519", "native_pq"} {
		if len(published[n]) != 9 {
			t.Fatalf("revision %d lists %d keys, want 9", n, len(published[n]))
		}
		key := published[n][types.Address{3}.String()]
		want := signerapi.KeyInfo{
			Address: types.Address{3}.String(), PublicKeyHex: fmt.Sprintf("%02x02", n), KeyType: fmt.Sprintf("type-%d", n),
			AuthorizationKind: kind, ValidRekeyTarget: n == 1,
			TemplateProvenanceStatus: key.TemplateProvenanceStatus, TemplateProvenanceNote: key.TemplateProvenanceNote,
		}
		if !reflect.DeepEqual(key, want) {
			t.Fatalf("revision %d lists %+v, want %+v", n, key, want)
		}
	}
	// The fingerprint decides the provenance, which differs too.
	if status := published[0][types.Address{3}.String()].TemplateProvenanceStatus; status == published[1][types.Address{3}.String()].TemplateProvenanceStatus {
		t.Fatalf("both revisions list the provenance %q", status)
	}

	var readers sync.WaitGroup
	stop := make(chan struct{})
	for range 4 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if got := list(); !reflect.DeepEqual(got, published[0]) && !reflect.DeepEqual(got, published[1]) {
					t.Errorf("a key list of no published revision: %+v", got)
					return
				}
			}
		}()
	}
	for range 300 {
		publish()
	}
	close(stop)
	readers.Wait()
}
