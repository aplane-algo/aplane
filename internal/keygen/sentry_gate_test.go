// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keygen

import (
	"context"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

type registryTestGenerator struct {
	family string
}

func (g *registryTestGenerator) RoutingFamily() string { return g.family }

func (g *registryTestGenerator) GenerateFromSeed(context.Context, storepaths.Paths, string, []byte, []byte, string, map[string]string) (*GenerationResult, error) {
	return nil, nil
}

func (g *registryTestGenerator) GenerateFromMnemonic(context.Context, storepaths.Paths, string, string, []byte, string, map[string]string) (*GenerationResult, error) {
	return nil, nil
}

func (g *registryTestGenerator) GenerateRandom(context.Context, storepaths.Paths, string, []byte, string, map[string]string) (*GenerationResult, error) {
	return nil, nil
}

func TestGetGeneratorRequiresExactSentryKeyTypeRegistration(t *testing.T) {
	original := registry
	registry = &GeneratorRegistry{generators: make(map[string]Generator)}
	defer func() { registry = original }()

	Register(&registryTestGenerator{family: "sentry-ed25519"})
	Register(&registryTestGenerator{family: "falcon1024"})

	tests := []string{
		keytypes.SentryComponentEd25519V1,
		keytypes.SentryComponentFalcon1024V1,
		keytypes.GuardedFalcon1024SentryEd25519V1,
		keytypes.GuardedFalcon1024SentryFalcon1024V1,
		keytypes.CorridorV1,
	}
	for _, keyType := range tests {
		t.Run(keyType, func(t *testing.T) {
			_, err := GetGenerator(keyType)
			if err == nil {
				t.Fatal("GetGenerator() error = nil, want exact-registration rejection")
			}
			if !strings.Contains(err.Error(), "no exact key generator registered") {
				t.Fatalf("GetGenerator() error = %v, want exact-registration rejection", err)
			}
		})
	}
}

func TestGetGeneratorAllowsExactSentryKeyTypeRegistration(t *testing.T) {
	original := registry
	registry = &GeneratorRegistry{generators: make(map[string]Generator)}
	defer func() { registry = original }()

	exact := &registryTestGenerator{family: keytypes.SentryComponentEd25519V1}
	Register(exact)

	got, err := GetGenerator(keytypes.SentryComponentEd25519V1)
	if err != nil {
		t.Fatalf("GetGenerator() error = %v", err)
	}
	if got != exact {
		t.Fatalf("GetGenerator() = %#v, want exact generator", got)
	}

	falconExact := &registryTestGenerator{family: keytypes.SentryComponentFalcon1024V1}
	Register(falconExact)
	got, err = GetGenerator(keytypes.SentryComponentFalcon1024V1)
	if err != nil {
		t.Fatalf("GetGenerator(falcon) error = %v", err)
	}
	if got != falconExact {
		t.Fatalf("GetGenerator(falcon) = %#v, want exact generator", got)
	}
}
