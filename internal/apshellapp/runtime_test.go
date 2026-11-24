// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/addressdisplay"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

func TestExecutionStateReflectsEngine(t *testing.T) {
	eng := engine.NewEngine("testnet")
	eng.SetWriteMode(true)
	eng.SetSimulate(true)

	app := New(eng, config.DefaultConfig(), t.TempDir())
	state := app.ExecutionState()

	if state.Network != "testnet" {
		t.Fatalf("state.Network = %q, want testnet", state.Network)
	}
	if !state.WriteMode {
		t.Fatal("state.WriteMode = false, want true")
	}
	if !state.Simulate {
		t.Fatal("state.Simulate = false, want true")
	}
	if state.IsConnected {
		t.Fatal("state.IsConnected = true, want false")
	}
}

func TestConfigurePluginsUsesCurrentNetworkConfig(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Algod = config.AlgodConfig{
		"testnet": &config.AlgodNetworkConfig{Server: "https://testnet.example", Token: "test-token"},
	}

	eng := engine.NewEngine("testnet")

	plugins := &fakePluginRuntime{}
	app := New(eng, cfg, t.TempDir())
	app.Plugins = plugins

	app.ConfigurePlugins()
	if plugins.network != "testnet" {
		t.Fatalf("plugin network = %q, want testnet", plugins.network)
	}
	if plugins.algodURL != "https://testnet.example" || plugins.algodToken != "test-token" {
		t.Fatalf("plugin algod config = %q/%q", plugins.algodURL, plugins.algodToken)
	}
}

// A network with no algod settings gives plugins the network and empty algod
// settings.
func TestConfigurePluginsWithoutAlgodConfig(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Algod = config.AlgodConfig{
		"mainnet": &config.AlgodNetworkConfig{Server: "https://mainnet.example", Token: "main-token"},
	}
	plugins := &fakePluginRuntime{algodURL: "stale", algodToken: "stale"}
	app := New(engine.NewEngine("testnet"), cfg, t.TempDir())
	app.Plugins = plugins

	app.ConfigurePlugins()
	if plugins.network != "testnet" || plugins.algodURL != "" || plugins.algodToken != "" {
		t.Fatalf("plugin config = %q %q/%q, want testnet with no algod", plugins.network, plugins.algodURL, plugins.algodToken)
	}
}

// The display marker and signableAddresses() are one rule,
// cache.IsAccountSignable: a key the signer lists with no authorization kind,
// or with one this client does not know, is neither marked nor listed, and
// neither is an account rekeyed to one.
func TestSignableMarkerAgreesWithSignableAddresses(t *testing.T) {
	addressdisplay.SetColorSupported(false)
	defer addressdisplay.ResetColorSupport()

	known, noKind, unknownKind := types.Address{1}.String(), types.Address{2}.String(), types.Address{3}.String()
	toKnown, toNoKind, toUnknownKind := types.Address{4}.String(), types.Address{5}.String(), types.Address{6}.String()
	eng := engine.NewEngine("testnet")
	if err := eng.PopulateSignerCache([]signerapi.KeyInfo{
		{Address: known, KeyType: "ed25519", AuthorizationKind: "ed25519"},
		{Address: noKind, KeyType: "ed25519"},
		{Address: unknownKind, KeyType: "ed25519", AuthorizationKind: "quantum_magic"},
	}); err != nil {
		t.Fatalf("PopulateSignerCache() error = %v", err)
	}
	// A rekeyed account is known to the client by its alias.
	eng.AliasCache.Aliases = map[string]string{"to-known": toKnown, "to-no-kind": toNoKind, "to-unknown-kind": toUnknownKind}
	eng.AuthCache.AuthAddresses = map[string]string{toKnown: known, toNoKind: noKind, toUnknownKind: unknownKind}
	app := New(eng, config.DefaultConfig(), t.TempDir())

	signable := eng.GetSignableAddresses()
	want := []string{known, toKnown}
	slices.Sort(want)
	if !slices.Equal(signable, want) {
		t.Fatalf("GetSignableAddresses() = %v, want %v", signable, want)
	}
	for _, address := range []string{known, noKind, unknownKind, toKnown, toNoKind, toUnknownKind} {
		formatted := app.FormatAddress(address)
		if marked, listed := strings.HasSuffix(formatted, " @"), slices.Contains(signable, address); marked != listed {
			t.Errorf("FormatAddress(%s) = %q (marked %v), but listed as signable = %v", address, formatted, marked, listed)
		}
	}
}

func TestFormatAddressMarksRotatingAccountAtAnyStage(t *testing.T) {
	addressdisplay.SetColorSupported(false)
	defer addressdisplay.ResetColorSupport()

	rot := types.Address{7}.String()
	ordinary := types.Address{8}.String()
	stage := types.Address{9}.String()

	eng := engine.NewEngine("testnet")
	if err := eng.PopulateSignerCache([]signerapi.KeyInfo{
		{Address: rot, KeyType: "aplane.rotating-triple-wotsc.v1", AuthorizationKind: "logic_sig", SigningFlow: signerapi.SigningFlowRotating1},
		{Address: ordinary, KeyType: "ed25519", AuthorizationKind: "ed25519"},
	}); err != nil {
		t.Fatalf("PopulateSignerCache() error = %v", err)
	}
	eng.AuthCache.AuthAddresses = map[string]string{rot: stage, ordinary: stage}
	app := New(eng, config.DefaultConfig(), t.TempDir())

	if got := app.FormatAddress(rot); got != rot+" @" {
		t.Fatalf("FormatAddress(rotating) = %q, want signable marker", got)
	}
	if got := app.FormatAddress(ordinary); got != ordinary {
		t.Fatalf("FormatAddress(rekeyed-away ordinary) = %q, want no marker", got)
	}
}

func TestDisplayAndCompleterDepsRaceSafeWithConcurrentSignerCacheUpdates(t *testing.T) {
	addressdisplay.SetColorSupported(false)
	defer addressdisplay.ResetColorSupport()

	addr := types.Address{9}.String()
	eng := engine.NewEngine("testnet")
	app := New(eng, config.DefaultConfig(), t.TempDir())
	deps := app.CompleterDeps()
	keys := []signerapi.KeyInfo{
		{Address: addr, KeyType: "ed25519", AuthorizationKind: "ed25519"},
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			if i%2 == 0 {
				_ = eng.PopulateSignerCache(keys)
			} else {
				eng.ResetSignerCache(false)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_ = app.FormatAddress(addr)
			_ = app.FormatKeyTypeForDisplay(addr, "ed25519")
			_ = deps.SignerAddresses()
		}
	}()
	wg.Wait()
}
