// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package v1

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/algo"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
	"github.com/aplane-algo/aplane/lsig/falcon1024/signerops"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestFalcon1024V1_KeyType(t *testing.T) {
	f := &Falcon1024V1{}
	if f.KeyType() != "aplane.falcon1024.v1" {
		t.Errorf("KeyType() = %q, want %q", f.KeyType(), "aplane.falcon1024.v1")
	}
}

func TestFalcon1024V1_Family(t *testing.T) {
	f := &Falcon1024V1{}
	if f.RoutingFamily() != family.Name {
		t.Errorf("RoutingFamily() = %q, want %q", f.RoutingFamily(), family.Name)
	}
}

func TestFalcon1024V1_Version(t *testing.T) {
	f := &Falcon1024V1{}
	if f.Version() != 1 {
		t.Errorf("Version() = %d, want 1", f.Version())
	}
}

func TestFalcon1024V1GenerateTEALUsesV13AutoSalt(t *testing.T) {
	f := &Falcon1024V1{}
	pubKey := make([]byte, family.PublicKeySize)

	teal, err := f.GenerateTEAL(pubKey, nil)
	if err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}
	if !strings.Contains(teal, "#pragma version 13") {
		t.Fatalf("GenerateTEAL() missing TEAL v13:\n%s", teal)
	}
	preamble, _ := lsigsalt.StylePushbytes.SourcePreamble()
	if strings.Contains(teal, "bytecblock 0x00") || strings.Contains(teal, strings.TrimSpace(preamble)) || strings.Contains(teal, "Counter byte") {
		t.Fatalf("GenerateTEAL() contains an APlane manual salt anchor:\n%s", teal)
	}
}

// liveCompilerEndpoint is an algod the live golden may compile against.
type liveCompilerEndpoint struct {
	name, url, token string
	// lenient lets a non-transport error (for example an older LocalNet that
	// rejects TEAL v13) fall through to the next endpoint.
	lenient bool
}

// liveCompilerEndpoints returns where the live golden compiles: only the
// endpoint named by TEAL_COMPILE_ALGOD_URL when set, otherwise a local LocalNet
// first and the repo's public node second.
func liveCompilerEndpoints() []liveCompilerEndpoint {
	token := os.Getenv(algo.TEALCompileAlgodTokenEnv)
	if token == "" {
		token = os.Getenv("ALGOD_TOKEN")
	}
	if u := os.Getenv(algo.TEALCompileAlgodURLEnv); u != "" {
		return []liveCompilerEndpoint{{name: "TEAL_COMPILE_ALGOD_URL", url: u, token: token}}
	}
	return []liveCompilerEndpoint{
		// algokit LocalNet defaults.
		{name: "LocalNet", url: "http://localhost:4001", token: strings.Repeat("a", 64), lenient: true},
		{name: "public algod", url: algo.ResolveTEALCompileAlgodURL(), token: token},
	}
}

// probeEndpoint reports whether a TCP connection to the endpoint's host opens
// within a second.
func probeEndpoint(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	conn, err := net.DialTimeout("tcp", u.Host, time.Second)
	if err != nil {
		return err
	}
	return conn.Close()
}

// errNoLiveCompiler means no endpoint could be reached or would compile the
// program; it is the only outcome that may skip the live golden.
var errNoLiveCompiler = errors.New("no algod could compile the program")

// checkLiveCompilerGolden compiles the test key's program on the first
// endpoint that will do it and checks the result against the golden. A node
// is passed over only if it is unreachable or, for a lenient endpoint, rejects
// the compile request (HTTP 400, for example an older LocalNet without TEAL
// v13). Once a node returns compiled output, every problem with it is an
// error: bad bytecode, a hash that disagrees with the address, an address
// that is on the curve, or a different program.
func checkLiveCompilerGolden(t *testing.T, endpoints []liveCompilerEndpoint) error {
	t.Helper()
	pubKey := falconTestPublicKey(t)
	var passedOver []string
	for _, ep := range endpoints {
		if ep.lenient {
			// The SDK client's dial timeout is 30 s; a dropped-packet LocalNet
			// address should not cost that.
			if err := probeEndpoint(ep.url); err != nil {
				t.Logf("%s not reachable, trying the next node: %v", ep.name, err)
				passedOver = append(passedOver, fmt.Sprintf("%s: %v", ep.name, err))
				continue
			}
		}
		client, err := algod.MakeClient(ep.url, ep.token)
		if err != nil {
			return fmt.Errorf("%s: make client: %w", ep.name, err)
		}
		f := &Falcon1024V1{}
		f.SetAlgodClient(client)
		derived, err := f.DeriveLsigWithSalt(context.Background(), pubKey, nil)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) {
				passedOver = append(passedOver, fmt.Sprintf("%s: %v", ep.name, err))
				continue
			}
			var rejected common.BadRequest
			if ep.lenient && errors.As(err, &rejected) {
				t.Logf("%s rejected the compile request, trying the next node: %v", ep.name, err)
				passedOver = append(passedOver, fmt.Sprintf("%s: %v", ep.name, err))
				continue
			}
			return fmt.Errorf("%s: DeriveLsigWithSalt(): %w", ep.name, err)
		}
		if v, err := client.Versions().Do(context.Background()); err == nil {
			t.Logf("compiled by %s (%s), algod %d.%d.%d", ep.name, ep.url, v.Build.Major, v.Build.Minor, v.Build.BuildNumber)
		}
		if !derived.CompilerAutoSalted || lsigsalt.IsOnCurve(derived.Address) {
			return fmt.Errorf("%s: derived result = %+v, want compiler-auto-salted off-curve bytecode", ep.name, derived)
		}
		if len(derived.Bytecode) != 1801 || derived.Address.String() != goldenAddress {
			return fmt.Errorf("%s: compiler golden = %d bytes / %s", ep.name, len(derived.Bytecode), derived.Address.String())
		}
		return nil
	}
	return fmt.Errorf("%w: %s", errNoLiveCompiler, strings.Join(passedOver, "; "))
}

// TestFalcon1024V1CompilerAutoSaltGolden asks a live algod to compile the
// test key's program, trying a local LocalNet first and the public node only
// if that is absent or rejects the request. It skips when no node is
// available, or when APLANE_SKIP_LIVE_COMPILER=1;
// APLANE_REQUIRE_LIVE_COMPILER=1 turns "no node available" into a failure.
// A node that returns output the golden does not accept always fails.
func TestFalcon1024V1CompilerAutoSaltGolden(t *testing.T) {
	if os.Getenv("APLANE_SKIP_LIVE_COMPILER") == "1" {
		t.Skip("APLANE_SKIP_LIVE_COMPILER=1")
	}
	err := checkLiveCompilerGolden(t, liveCompilerEndpoints())
	if errors.Is(err, errNoLiveCompiler) && os.Getenv("APLANE_REQUIRE_LIVE_COMPILER") != "1" {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
}

// TestLiveCompilerFallback pins which LocalNet outcomes may fall through to
// the next node, using stand-in nodes.
func TestLiveCompilerFallback(t *testing.T) {
	bytecode := readGoldenBytecode(t)
	good, err := crypto.LogicSigAccount{Lsig: types.LogicSig{Logic: bytecode}}.Address()
	if err != nil {
		t.Fatal(err)
	}
	node := func(status int, hash string, result []byte) liveCompilerEndpoint {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if status != http.StatusOK {
				http.Error(w, "unsupported", status)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"hash":   hash,
				"result": base64.StdEncoding.EncodeToString(result),
			})
		}))
		t.Cleanup(srv.Close)
		return liveCompilerEndpoint{name: "stand-in", url: srv.URL, lenient: true}
	}
	fallback := node(http.StatusOK, good.String(), bytecode)
	fallback.lenient = false

	other := types.Address{1}
	tests := []struct {
		name    string
		first   liveCompilerEndpoint
		wantErr bool
	}{
		{"compile request rejected", node(http.StatusBadRequest, "", nil), false},
		{"unreachable", liveCompilerEndpoint{name: "closed", url: "http://127.0.0.1:1", lenient: true}, false},
		{"hash disagrees with the bytecode", node(http.StatusOK, other.String(), bytecode), true},
		{"empty bytecode", node(http.StatusOK, good.String(), nil), true},
		{"server error", node(http.StatusInternalServerError, "", nil), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkLiveCompilerGolden(t, []liveCompilerEndpoint{tt.first, fallback})
			if tt.wantErr && (err == nil || errors.Is(err, errNoLiveCompiler)) {
				t.Fatalf("err = %v, want a validation failure", err)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("err = %v, want fallback to succeed", err)
			}
		})
	}
}

func TestFalcon1024V1_DeriveLsig_RequiresAlgod(t *testing.T) {
	f := &Falcon1024V1{} // No algod client set

	seed := make([]byte, 64)
	pubKey, _, err := signerops.New(nil).GenerateKeypair(seed)
	if err != nil {
		t.Fatalf("GenerateKeypair() error: %v", err)
	}

	// Should fail without algod client
	_, _, err = f.DeriveLsig(context.Background(), pubKey, nil)
	if err == nil {
		t.Error("DeriveLsig() should fail without algod client")
	}
	if !strings.Contains(err.Error(), "algod client not set") {
		t.Errorf("Expected 'algod client not set' error, got: %v", err)
	}
}

func falconTestPublicKey(t *testing.T) []byte {
	t.Helper()

	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i)
	}
	pubKey, _, err := signerops.New(nil).GenerateKeypair(seed)
	if err != nil {
		t.Fatalf("GenerateKeypair() error = %v", err)
	}
	return pubKey
}

func TestFalcon1024V1_DeriveLsig(t *testing.T) {
	// Create algod client
	client, err := algod.MakeClient(algo.ResolveTEALCompileAlgodURL(), "")
	if err != nil {
		t.Skipf("Could not create algod client: %v", err)
	}

	f := &Falcon1024V1{}
	f.SetAlgodClient(client)

	// Generate keypair from test seed
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i)
	}

	pubKey, _, err := signerops.New(nil).GenerateKeypair(seed)
	if err != nil {
		t.Fatalf("GenerateKeypair() error: %v", err)
	}

	// Derive LogicSig
	bytecode, addr, err := f.DeriveLsig(context.Background(), pubKey, nil)
	if err != nil {
		t.Fatalf("DeriveLsig() error: %v", err)
	}

	if len(bytecode) != 1801 {
		t.Errorf("Bytecode length = %d, want 1801", len(bytecode))
	}

	if addr == "" {
		t.Error("Address should not be empty")
	}
	salted, err := f.DeriveLsigWithSalt(context.Background(), pubKey, nil)
	if err != nil {
		t.Fatalf("DeriveLsigWithSalt() error: %v", err)
	}
	if !bytes.Equal(bytecode, salted.Bytecode) || addr != salted.Address.String() {
		t.Fatalf("DeriveLsigWithSalt() = (%x, %s), want (%x, %s)", salted.Bytecode, salted.Address.String(), bytecode, addr)
	}
	if lsigsalt.IsOnCurve(salted.Address) {
		t.Fatalf("DeriveLsigWithSalt() returned on-curve address %s", salted.Address.String())
	}
	if !salted.CompilerAutoSalted {
		t.Fatal("DeriveLsigWithSalt() did not identify compiler auto-salting")
	}

	// Verify determinism
	bytecode2, addr2, err := f.DeriveLsig(context.Background(), pubKey, nil)
	if err != nil {
		t.Fatalf("DeriveLsig() second call error: %v", err)
	}

	if addr != addr2 {
		t.Errorf("Address derivation not deterministic: %s != %s", addr, addr2)
	}

	if !bytes.Equal(bytecode, bytecode2) {
		t.Error("Bytecode derivation not deterministic")
	}

	t.Logf("Derived address: %s", addr)
}

// TestZeroSuffixMatchesStandardFalcon verifies that a composed provider
// with no TEAL suffix produces identical bytecode to standard aplane.falcon1024.v1.
func TestZeroSuffixMatchesStandardFalcon(t *testing.T) {
	client, err := algod.MakeClient(algo.ResolveTEALCompileAlgodURL(), "")
	if err != nil {
		t.Skipf("Could not create algod client: %v", err)
	}

	// Create a composed provider with NO TEAL suffix (using the factory)
	pureComposed := newFalconV1Composed()
	pureComposed.SetAlgodClient(client)

	// Generate keypair from same seed
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i)
	}

	pubKey, _, err := signerops.New(nil).GenerateKeypair(seed)
	if err != nil {
		t.Fatalf("GenerateKeypair() error: %v", err)
	}

	standard := &Falcon1024V1{}
	standard.SetAlgodClient(client)
	standardBytecode, standardAddr, err := standard.DeriveLsig(context.Background(), pubKey, nil)
	if err != nil {
		t.Fatalf("standard DeriveLsig() error: %v", err)
	}

	// Derive using composed with no TEAL suffix
	composedBytecode, composedAddr, err := pureComposed.DeriveLsig(context.Background(), pubKey, nil)
	if err != nil {
		t.Fatalf("Composed DeriveLsig() error: %v", err)
	}

	// Compare
	t.Logf("Standard aplane.falcon1024.v1:")
	t.Logf("  Address: %s", standardAddr)
	t.Logf("  Bytecode length: %d bytes", len(standardBytecode))
	t.Logf("  First 20 bytes: %x", standardBytecode[:20])

	t.Logf("Composed with no TEAL suffix:")
	t.Logf("  Address: %s", composedAddr)
	t.Logf("  Bytecode length: %d bytes", len(composedBytecode))
	t.Logf("  First 20 bytes: %x", composedBytecode[:20])

	if standardAddr != composedAddr {
		t.Errorf("Addresses differ:\n  standard: %s\n  composed: %s", standardAddr, composedAddr)
	}

	if !bytes.Equal(standardBytecode, composedBytecode) {
		t.Errorf("Bytecode differs:\n  standard len: %d\n  composed len: %d",
			len(standardBytecode), len(composedBytecode))
	}
}

func TestFalcon1024V1PlainSignatureBound(t *testing.T) {
	ok := make([]byte, family.MaxSignatureSize)
	tooLong := make([]byte, family.MaxSignatureSize+1)

	for name, build := range map[string]func([]byte) ([][]byte, error){
		"BuildArgs":          func(sig []byte) ([][]byte, error) { return (&Falcon1024V1{}).BuildArgs(sig, nil) },
		"BuildSignatureArgs": (&FalconOps{}).BuildSignatureArgs,
	} {
		t.Run(name, func(t *testing.T) {
			if args, err := build(ok); err != nil || len(args) != 1 || len(args[0]) != len(ok) {
				t.Fatalf("maximum-size signature: args=%d err=%v", len(args), err)
			}
			if _, err := build(tooLong); err == nil || !strings.Contains(err.Error(), "maximum") {
				t.Fatalf("oversized signature: err = %v, want a size rejection", err)
			}
			for _, empty := range [][]byte{nil, {}} {
				if _, err := build(empty); err == nil {
					t.Fatalf("empty signature %#v accepted", empty)
				}
			}
		})
	}
}
