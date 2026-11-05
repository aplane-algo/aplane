// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package lsigprovider_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
)

var (
	instanceFingerprintA = "1:" + strings.Repeat("a", 64)
	instanceFingerprintB = "1:" + strings.Repeat("b", 64)
	instanceFingerprintC = "1:" + strings.Repeat("c", 64)
)

// fixedBoundedProvider has one contract for every set of values.
type fixedBoundedProvider struct {
	fingerprintTestProvider
	definitions []lsigprovider.ParameterDef
	metadata    *boundedmeta.Metadata
}

func (p fixedBoundedProvider) CreationParams() []lsigprovider.ParameterDef { return p.definitions }
func (p fixedBoundedProvider) BoundedAuthorizationMetadata() *boundedmeta.Metadata {
	return p.metadata
}

// perKeyProvider selects its contract from a "shape" parameter.
type perKeyProvider struct {
	fingerprintTestProvider
	shapes  map[string]string
	nothing bool
}

func (p perKeyProvider) CosignerComponentKeyType(params map[string]string) (string, bool) {
	if params["cosigner"] == "" {
		return "", false
	}
	return "test.component.v1", true
}

func (p perKeyProvider) ResolveInstance(params map[string]string) (*lsigprovider.Instance, error) {
	if p.nothing {
		return nil, nil
	}
	fingerprint, ok := p.shapes[params["shape"]]
	if !ok {
		return nil, errors.New("unknown shape")
	}
	return &lsigprovider.Instance{Values: params, Fingerprint: fingerprint}, nil
}

func (p perKeyProvider) StoredFingerprint(parameters map[string]string, _ *boundedmeta.Metadata) (string, error) {
	fingerprint, ok := p.shapes[parameters["shape"]]
	if !ok {
		return "", errors.New("unknown shape")
	}
	return fingerprint, nil
}

func registerForTest(t *testing.T, provider lsigprovider.LSigProvider) {
	t.Helper()
	lsigprovider.Register(provider)
	t.Cleanup(func() { lsigprovider.Unregister(provider.KeyType()) })
}

func TestFixedProviderInstanceMatchesItsDefinition(t *testing.T) {
	metadata := &boundedmeta.Metadata{
		Layer3Policy: boundedmeta.Layer3PolicyFixedAllowlist,
		Cosigner:     &boundedmeta.CosignerAuthorization{ComponentKeyType: "test.component.v1"},
	}
	definitions := []lsigprovider.ParameterDef{{Name: "recipients", Type: "address[]"}}
	provider := fixedBoundedProvider{
		fingerprintTestProvider: fingerprintTestProvider{keyType: "instance-fixed-v1", fingerprint: instanceFingerprintA},
		definitions:             definitions,
		metadata:                metadata,
	}

	component, ok := lsigprovider.CosignerComponentKeyType(provider, nil)
	if !ok || component != "test.component.v1" {
		t.Fatalf("CosignerComponentKeyType() = (%q, %v)", component, ok)
	}
	instance, err := lsigprovider.ResolveInstance(provider, map[string]string{"recipients": "B, A"})
	if err != nil {
		t.Fatalf("ResolveInstance() error = %v", err)
	}
	if got := instance.Values["recipients"]; got != "A,B" {
		t.Fatalf("Values[recipients] = %q, want the normalized list", got)
	}
	if instance.Fingerprint != instanceFingerprintA || instance.Bounded != metadata || len(instance.Parameters) != 1 {
		t.Fatalf("instance = %+v", instance)
	}
}

func TestFixedProviderWithoutBoundedContract(t *testing.T) {
	provider := fingerprintTestProvider{keyType: "instance-plain-v1", fingerprint: instanceFingerprintA}
	if component, ok := lsigprovider.CosignerComponentKeyType(provider, nil); ok {
		t.Fatalf("CosignerComponentKeyType() = %q, want none", component)
	}
	instance, err := lsigprovider.ResolveInstance(provider, nil)
	if err != nil {
		t.Fatalf("ResolveInstance() error = %v", err)
	}
	if instance.Bounded != nil {
		t.Fatalf("Bounded = %+v, want nil", instance.Bounded)
	}
}

func TestPerKeyProviderSelectsItsInstance(t *testing.T) {
	provider := perKeyProvider{
		fingerprintTestProvider: fingerprintTestProvider{keyType: "instance-per-key-v1", fingerprint: instanceFingerprintC},
		shapes:                  map[string]string{"list": instanceFingerprintA},
	}
	if component, ok := lsigprovider.CosignerComponentKeyType(provider, map[string]string{"cosigner": "ops"}); !ok || component == "" {
		t.Fatalf("CosignerComponentKeyType(cosigner) = (%q, %v)", component, ok)
	}
	if component, ok := lsigprovider.CosignerComponentKeyType(provider, nil); ok {
		t.Fatalf("CosignerComponentKeyType(none) = %q, want none", component)
	}
	if _, err := lsigprovider.ResolveInstance(provider, map[string]string{"shape": "other"}); err == nil {
		t.Fatal("ResolveInstance(unknown shape) succeeded")
	}
	provider.nothing = true
	if _, err := lsigprovider.ResolveInstance(provider, map[string]string{"shape": "list"}); err == nil {
		t.Fatal("ResolveInstance() accepted a nil instance")
	}
}

func TestCreationFingerprint(t *testing.T) {
	registerForTest(t, fingerprintTestProvider{keyType: "instance-created-fixed-v1", fingerprint: instanceFingerprintA})
	registerForTest(t, perKeyProvider{
		fingerprintTestProvider: fingerprintTestProvider{keyType: "instance-created-per-key-v1", fingerprint: instanceFingerprintC},
		shapes:                  map[string]string{"list": instanceFingerprintB},
	})

	if got, err := lsigprovider.CreationFingerprint("instance-created-fixed-v1", nil); err != nil || got != instanceFingerprintA {
		t.Fatalf("CreationFingerprint(fixed) = (%q, %v), want the type fingerprint", got, err)
	}
	// A per-key account records its shape, never the type-wide fingerprint.
	got, err := lsigprovider.CreationFingerprint("instance-created-per-key-v1", map[string]string{"shape": "list"})
	if err != nil || got != instanceFingerprintB {
		t.Fatalf("CreationFingerprint(per-key) = (%q, %v), want the shape fingerprint", got, err)
	}
	if _, err := lsigprovider.CreationFingerprint("instance-created-per-key-v1", map[string]string{"shape": "other"}); err == nil {
		t.Fatal("CreationFingerprint(unknown shape) succeeded")
	}
	if got, err := lsigprovider.CreationFingerprint("instance-created-unregistered-v1", nil); err != nil || got != "" {
		t.Fatalf("CreationFingerprint(unregistered) = (%q, %v), want none", got, err)
	}
}

func TestCompareAccountProvenance(t *testing.T) {
	const keyType = "instance-provenance-v1"
	list := map[string]string{"shape": "list"}
	// The type-wide fingerprint differs from every stored one, as it would once
	// a shape is added. Only the account's own shape may decide the result.
	registerForTest(t, perKeyProvider{
		fingerprintTestProvider: fingerprintTestProvider{keyType: keyType, fingerprint: instanceFingerprintC},
		shapes:                  map[string]string{"list": instanceFingerprintA, "changed": instanceFingerprintB},
	})

	for _, test := range []struct {
		name       string
		stored     string
		parameters map[string]string
		want       string
	}{
		{name: "unrelated shape added", stored: instanceFingerprintA, parameters: list},
		{name: "own shape changed", stored: instanceFingerprintA, parameters: map[string]string{"shape": "changed"}, want: lsigprovider.TemplateProvenanceStatusConflict},
		{name: "shape no longer available", stored: instanceFingerprintA, parameters: map[string]string{"shape": "gone"}, want: lsigprovider.TemplateProvenanceStatusUnavailable},
		{name: "different fingerprint format", stored: "2:" + strings.Repeat("a", 64), parameters: list, want: lsigprovider.TemplateProvenanceStatusUnavailable},
		{name: "nothing recorded", parameters: list},
	} {
		t.Run(test.name, func(t *testing.T) {
			status, note := lsigprovider.CompareAccountProvenance(keyType, test.stored, test.parameters, nil)
			if status != test.want {
				t.Fatalf("status = %q (%s), want %q", status, note, test.want)
			}
			if (status == "") != (note == "") {
				t.Fatalf("status %q has note %q", status, note)
			}
		})
	}
}

func TestCompareAccountProvenanceKeepsFixedBehavior(t *testing.T) {
	const keyType = "instance-provenance-fixed-v1"
	registerForTest(t, fingerprintTestProvider{keyType: keyType, fingerprint: instanceFingerprintA})
	for _, stored := range []string{instanceFingerprintA, instanceFingerprintB, ""} {
		status, note := lsigprovider.CompareAccountProvenance(keyType, stored, nil, nil)
		wantStatus, wantNote := lsigprovider.CompareTemplateFingerprint(keyType, stored)
		if status != wantStatus || note != wantNote {
			t.Fatalf("stored %q: (%q, %q), want (%q, %q)", stored, status, note, wantStatus, wantNote)
		}
	}
	if status, _ := lsigprovider.CompareAccountProvenance("instance-provenance-missing-v1", instanceFingerprintA, nil, nil); status != lsigprovider.TemplateProvenanceStatusUnavailable {
		t.Fatalf("unregistered provider status = %q", status)
	}
}
