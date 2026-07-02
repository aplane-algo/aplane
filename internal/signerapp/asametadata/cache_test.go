// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package asametadata

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/asa"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/serverconfig"
)

func TestMetadataByIDUsesBuiltinAsSignerCacheSeed(t *testing.T) {
	meta, err := NewStore(t.TempDir()).MetadataByID("testnet", 10458941, nil, false)
	if err != nil {
		t.Fatalf("MetadataByID() error = %v", err)
	}
	if meta.AssetID != 10458941 || meta.UnitName != "USDC" || meta.Decimals != 6 {
		t.Fatalf("metadata = %+v, want testnet USDC", meta)
	}
	if meta.Source != asa.SourceCache {
		t.Fatalf("Source = %q, want %q", meta.Source, asa.SourceCache)
	}
}

func TestFormatterRendersDisplayAmountWithAssetID(t *testing.T) {
	format := NewStore(t.TempDir()).Formatter()
	got, ok := format("testnet", 10458941, 2_000_000)
	if !ok {
		t.Fatal("Formatter() ok = false, want true")
	}
	if got != "2 USDC (ASA 10458941)" {
		t.Fatalf("Formatter() = %q, want %q", got, "2 USDC (ASA 10458941)")
	}
}

func TestSearchLocalMatchesUnitNameCaseInsensitiveAndSorted(t *testing.T) {
	dataDir := t.TempDir()
	store := NewStore(dataDir)
	for _, meta := range []asa.Metadata{
		{AssetID: 44, Name: "Second Duplicate", UnitName: "DUP", Decimals: 6},
		{AssetID: 11, Name: "First Duplicate", UnitName: "dup", Decimals: 2},
		{AssetID: 99, Name: "Different", UnitName: "OTHER", Decimals: 0},
	} {
		if err := store.SaveLocalMetadata("customnet", meta); err != nil {
			t.Fatalf("SaveLocalMetadata() error = %v", err)
		}
	}

	got, err := store.SearchLocal("customnet", "DuP")
	if err != nil {
		t.Fatalf("SearchLocal() error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("SearchLocal() returned %d results, want 2: %+v", len(got), got)
	}
	if got[0].AssetID != 11 || got[1].AssetID != 44 {
		t.Fatalf("SearchLocal() asset order = [%d %d], want [11 44]", got[0].AssetID, got[1].AssetID)
	}
	if got[0].Network != "customnet" || got[0].Source != asa.SourceCache {
		t.Fatalf("SearchLocal() metadata = %+v, want cache-sourced customnet metadata", got[0])
	}
}

func TestFormatterDoesNotWaitBehindLiveLookup(t *testing.T) {
	store := NewStore(t.TempDir())
	started := make(chan struct{})
	release := make(chan struct{})
	var startedOnce sync.Once
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startedOnce.Do(func() { close(started) })
		<-release
		http.Error(w, "released", http.StatusInternalServerError)
	}))
	defer server.Close()

	cfg := testAlgodServerConfig("customnet", server.URL)
	liveDone := make(chan error, 1)
	go func() {
		_, err := store.MetadataByID("customnet", 777, cfg, true)
		liveDone <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("live ASA metadata lookup did not reach test server")
	}

	formatDone := make(chan struct {
		value string
		ok    bool
	}, 1)
	go func() {
		value, ok := store.Formatter()("customnet", 778, 1)
		formatDone <- struct {
			value string
			ok    bool
		}{value: value, ok: ok}
	}()
	select {
	case result := <-formatDone:
		if result.ok || result.value != "" {
			t.Fatalf("Formatter() = (%q, %v), want cache miss while live lookup is blocked", result.value, result.ok)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Formatter() blocked behind live ASA metadata lookup")
	}

	releaseOnce.Do(func() { close(release) })
	select {
	case <-liveDone:
	case <-time.After(time.Second):
		t.Fatal("live ASA metadata lookup did not finish after release")
	}
}

func TestMetadataByIDCoalescesConcurrentLiveLookups(t *testing.T) {
	store := NewStore(t.TempDir())
	const (
		network = "customnet"
		assetID = uint64(888)
	)
	started := make(chan struct{})
	release := make(chan struct{})
	var startedOnce sync.Once
	var requestCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		startedOnce.Do(func() { close(started) })
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"index":%d,"params":{"creator":"creator","decimals":3,"name":"Live Asset","unit-name":"LIVE","total":1000}}`, assetID)
	}))
	defer server.Close()
	cfg := testAlgodServerConfig(network, server.URL)

	first := make(chan metadataResult, 1)
	second := make(chan metadataResult, 1)
	go func() {
		meta, err := store.MetadataByID(network, assetID, cfg, true)
		first <- metadataResult{meta: meta, err: err}
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first live ASA metadata lookup did not reach test server")
	}
	go func() {
		meta, err := store.MetadataByID(network, assetID, cfg, true)
		second <- metadataResult{meta: meta, err: err}
	}()
	time.Sleep(50 * time.Millisecond)
	if got := atomic.LoadInt32(&requestCount); got != 1 {
		close(release)
		t.Fatalf("live request count before release = %d, want 1", got)
	}
	close(release)

	for name, ch := range map[string]chan metadataResult{"first": first, "second": second} {
		select {
		case result := <-ch:
			if result.err != nil {
				t.Fatalf("%s MetadataByID() error = %v", name, result.err)
			}
			if result.meta.AssetID != assetID || result.meta.UnitName != "LIVE" || result.meta.Decimals != 3 || result.meta.Source != asa.SourceLive {
				t.Fatalf("%s MetadataByID() = %+v, want live LIVE asset", name, result.meta)
			}
		case <-time.After(time.Second):
			t.Fatalf("%s MetadataByID() did not finish", name)
		}
	}
	if got := atomic.LoadInt32(&requestCount); got != 1 {
		t.Fatalf("live request count after both lookups = %d, want 1", got)
	}
}

type metadataResult struct {
	meta asa.Metadata
	err  error
}

func testAlgodServerConfig(network, serverURL string) *serverconfig.ServerConfig {
	return &serverconfig.ServerConfig{
		Algod: apconfig.AlgodConfig{
			network: &apconfig.AlgodNetworkConfig{Server: serverURL},
		},
	}
}
