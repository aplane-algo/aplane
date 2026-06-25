// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package lsigprovider

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	util "github.com/aplane-algo/aplane/internal/xregistry"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
)

type stubProvider struct {
	keyType  string
	family   string
	version  int
	category string
}

func (p stubProvider) KeyType() string       { return p.keyType }
func (p stubProvider) RoutingFamily() string { return p.family }
func (p stubProvider) Version() int {
	if p.version != 0 {
		return p.version
	}
	return 1
}
func (p stubProvider) Category() string {
	if p.category != "" {
		return p.category
	}
	return CategoryGenericLsig
}
func (p stubProvider) DisplayName() string            { return p.keyType }
func (p stubProvider) Description() string            { return "" }
func (p stubProvider) DisplayColor() string           { return "" }
func (p stubProvider) CreationParams() []ParameterDef { return nil }
func (p stubProvider) ValidateCreationParams(map[string]string) error {
	return nil
}
func (p stubProvider) RuntimeArgs() []RuntimeArgDef                          { return nil }
func (p stubProvider) BuildArgs([]byte, map[string][]byte) ([][]byte, error) { return nil, nil }

func TestRegisterPanicsOnDuplicateKeyType(t *testing.T) {
	originalProviders := providers
	originalClient := storedClient
	providers = util.NewStringRegistry[LSigProvider]()
	storedClient = nil
	defer func() {
		providers = originalProviders
		storedClient = originalClient
	}()

	Register(stubProvider{keyType: "test-v1", family: "test"})

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("Register() did not panic on duplicate key type")
		} else if got := fmt.Sprint(r); !strings.Contains(got, "duplicate LSig provider registration") {
			t.Fatalf("panic = %q, want duplicate registration message", got)
		}
	}()

	Register(stubProvider{keyType: "TEST-V1", family: "test"})
}

func TestRegisterIfAbsentIgnoresDuplicateKeyType(t *testing.T) {
	originalProviders := providers
	originalClient := storedClient
	providers = util.NewStringRegistry[LSigProvider]()
	storedClient = nil
	defer func() {
		providers = originalProviders
		storedClient = originalClient
	}()

	if added := RegisterIfAbsent(stubProvider{keyType: "test-v1", family: "test"}); !added {
		t.Fatal("RegisterIfAbsent() = false, want true for first registration")
	}

	if added := RegisterIfAbsent(stubProvider{keyType: "TEST-V1", family: "test"}); added {
		t.Fatal("RegisterIfAbsent() = true, want false for duplicate registration")
	}
}

type stubConfigurableProvider struct {
	stubProvider
	client *algod.Client
}

func (p *stubConfigurableProvider) SetAlgodClient(client *algod.Client) {
	p.client = client
}

func TestRegisterPanicsOnInvalidContract(t *testing.T) {
	tests := []struct {
		name string
		p    stubProvider
		want string
	}{
		{name: "empty key type", p: stubProvider{family: "test"}, want: "empty key type"},
		{name: "empty family", p: stubProvider{keyType: "test-v1"}, want: "empty family"},
		{name: "invalid version", p: stubProvider{keyType: "test-v1", family: "test", version: -1}, want: "invalid version"},
		{name: "key type whitespace", p: stubProvider{keyType: "test v1", family: "test"}, want: "contains whitespace"},
		{name: "invalid category", p: stubProvider{keyType: "test-v1", family: "test", category: "mystery"}, want: "invalid category"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalProviders := providers
			originalClient := storedClient
			providers = util.NewStringRegistry[LSigProvider]()
			storedClient = nil
			defer func() {
				providers = originalProviders
				storedClient = originalClient
			}()

			defer func() {
				if r := recover(); r == nil {
					t.Fatal("Register() did not panic on invalid provider contract")
				} else if got := fmt.Sprint(r); !strings.Contains(got, tt.want) {
					t.Fatalf("panic = %q, want %q", got, tt.want)
				}
			}()

			Register(tt.p)
		})
	}
}

func TestRegisterAppliesStoredClientToLateProvider(t *testing.T) {
	originalProviders := providers
	originalClient := storedClient
	providers = util.NewStringRegistry[LSigProvider]()
	storedClient = nil
	defer func() {
		providers = originalProviders
		storedClient = originalClient
	}()

	client, err := algod.MakeClient("https://example.com", "")
	if err != nil {
		t.Fatalf("MakeClient() error = %v", err)
	}
	ConfigureAlgodClient(client)

	p := &stubConfigurableProvider{stubProvider: stubProvider{keyType: "test-v1", family: "test"}}
	Register(p)

	if p.client != client {
		t.Fatal("late-registered provider did not receive stored algod client")
	}
}

func TestConcurrentRegisterAndConfigureAlgodClient(t *testing.T) {
	originalProviders := providers
	originalClient := storedClient
	providers = util.NewStringRegistry[LSigProvider]()
	storedClient = nil
	defer func() {
		providers = originalProviders
		storedClient = originalClient
	}()

	clientA, err := algod.MakeClient("https://example.com", "")
	if err != nil {
		t.Fatalf("MakeClient(clientA) error = %v", err)
	}
	clientB, err := algod.MakeClient("https://example.org", "")
	if err != nil {
		t.Fatalf("MakeClient(clientB) error = %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(2)

		go func(i int) {
			defer wg.Done()
			ConfigureAlgodClient(clientA)
			ConfigureAlgodClient(clientB)
			ConfigureAlgodClient(clientA)
		}(i)

		go func(i int) {
			defer wg.Done()
			p := &stubConfigurableProvider{
				stubProvider: stubProvider{
					keyType: fmt.Sprintf("test-%d-v1", i),
					family:  fmt.Sprintf("test-%d", i),
				},
			}
			Register(p)
		}(i)
	}
	wg.Wait()

	late := &stubConfigurableProvider{stubProvider: stubProvider{keyType: "late-v1", family: "late"}}
	Register(late)
	if late.client == nil {
		t.Fatal("late-registered provider did not receive stored algod client after concurrent configuration")
	}
}
