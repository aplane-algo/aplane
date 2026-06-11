// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyeditor

import (
	"context"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/policy"
)

type fakeAdminPolicyClient struct {
	snapshot        AdminPolicySnapshot
	validation      AdminPolicyValidation
	replace         AdminPolicySnapshot
	err             error
	snapshotCalls   int
	validateCalls   int
	replaceCalls    int
	lastTarget      Target
	lastPolicyYAML  string
	lastExpectedSHA string
}

func (f *fakeAdminPolicyClient) GetPolicySnapshot(ctx context.Context, target Target) (AdminPolicySnapshot, error) {
	if err := ctx.Err(); err != nil {
		return AdminPolicySnapshot{}, err
	}
	f.snapshotCalls++
	f.lastTarget = target
	return f.snapshot, f.err
}

func (f *fakeAdminPolicyClient) ValidatePolicy(ctx context.Context, target Target, policyYAML string) (AdminPolicyValidation, error) {
	if err := ctx.Err(); err != nil {
		return AdminPolicyValidation{}, err
	}
	f.validateCalls++
	f.lastTarget = target
	f.lastPolicyYAML = policyYAML
	return f.validation, f.err
}

func (f *fakeAdminPolicyClient) ReplacePolicy(ctx context.Context, target Target, policyYAML, expectedCurrentSHA256 string) (AdminPolicySnapshot, error) {
	if err := ctx.Err(); err != nil {
		return AdminPolicySnapshot{}, err
	}
	f.replaceCalls++
	f.lastTarget = target
	f.lastPolicyYAML = policyYAML
	f.lastExpectedSHA = expectedCurrentSHA256
	return f.replace, f.err
}

func TestAdminStoreLoadParsesSnapshotAndRecordsSHA(t *testing.T) {
	client := &fakeAdminPolicyClient{
		snapshot: AdminPolicySnapshot{
			Success:      true,
			Target:       TargetSigner,
			IdentityID:   "default",
			PolicyYAML:   "max_fee_microalgos: 7000\n",
			PolicySHA256: "abc123",
			Canonical:    true,
		},
	}
	store := &AdminStore{Client: client, Target: TargetSigner}

	stored, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if client.snapshotCalls != 1 || client.lastTarget != TargetSigner {
		t.Fatalf("GetPolicySnapshot calls = %d target = %q, want one signer call", client.snapshotCalls, client.lastTarget)
	}
	if stored.MaxFeeMicroAlgos == nil || *stored.MaxFeeMicroAlgos != 7000 {
		t.Fatalf("MaxFeeMicroAlgos = %v, want 7000", stored.MaxFeeMicroAlgos)
	}
	if store.IdentityID() != "default" || store.LastSHA256() != "abc123" {
		t.Fatalf("store metadata identity=%q sha=%q, want default/abc123", store.IdentityID(), store.LastSHA256())
	}
}

func TestAdminStoreValidateUsesTargetMarshalAndClientValidation(t *testing.T) {
	client := &fakeAdminPolicyClient{
		validation: AdminPolicyValidation{Success: true, Target: TargetSentry, IdentityID: "default"},
	}
	store := &AdminStore{Client: client, Target: TargetSentry}
	stored, err := policy.ParseStoredSentryConfig([]byte(sentryYAMLForAdminStoreTest("allow_validate")))
	if err != nil {
		t.Fatalf("ParseStoredSentryConfig(): %v", err)
	}

	if err := store.Validate(context.Background(), stored); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if client.validateCalls != 1 || client.lastTarget != TargetSentry {
		t.Fatalf("ValidatePolicy calls = %d target = %q, want one sentry call", client.validateCalls, client.lastTarget)
	}
	if strings.Contains(client.lastPolicyYAML, "sentry:") ||
		!strings.Contains(client.lastPolicyYAML, "allow_validate") {
		t.Fatalf("validation YAML has wrong shape:\n%s", client.lastPolicyYAML)
	}
}

func TestAdminStoreSaveSendsExpectedSHAAndUpdatesFromReplaceSnapshot(t *testing.T) {
	client := &fakeAdminPolicyClient{
		snapshot: AdminPolicySnapshot{
			Success:      true,
			Target:       TargetSigner,
			IdentityID:   "default",
			PolicyYAML:   "max_fee_microalgos: 7000\n",
			PolicySHA256: "abc123",
		},
		replace: AdminPolicySnapshot{
			Success:      true,
			Target:       TargetSigner,
			IdentityID:   "default",
			PolicyYAML:   "max_fee_microalgos: 9000\n",
			PolicySHA256: "def456",
		},
	}
	store := &AdminStore{Client: client, Target: TargetSigner}
	if _, err := store.Load(context.Background()); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	maxFee := uint64(9000)
	if err := store.Save(context.Background(), &policy.StoredConfig{MaxFeeMicroAlgos: &maxFee}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	if client.replaceCalls != 1 || client.lastExpectedSHA != "abc123" {
		t.Fatalf("ReplacePolicy calls = %d expected SHA = %q, want one call with abc123", client.replaceCalls, client.lastExpectedSHA)
	}
	if store.LastSHA256() != "def456" {
		t.Fatalf("LastSHA256() = %q, want def456", store.LastSHA256())
	}
}

func TestAdminStoreFailedSaveDoesNotUpdateExpectedSHA(t *testing.T) {
	client := &fakeAdminPolicyClient{
		snapshot: AdminPolicySnapshot{
			Success:      true,
			Target:       TargetSigner,
			IdentityID:   "default",
			PolicyYAML:   "max_fee_microalgos: 7000\n",
			PolicySHA256: "abc123",
		},
		replace: AdminPolicySnapshot{
			Success: false,
			Target:  TargetSigner,
			Code:    "policy_snapshot_changed",
			Error:   "active policy changed",
		},
	}
	store := &AdminStore{Client: client, Target: TargetSigner}
	if _, err := store.Load(context.Background()); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	maxFee := uint64(9000)
	err := store.Save(context.Background(), &policy.StoredConfig{MaxFeeMicroAlgos: &maxFee})
	if err == nil {
		t.Fatal("Save() error = nil, want replace failure")
	}
	if store.LastSHA256() != "abc123" {
		t.Fatalf("LastSHA256() = %q, want unchanged abc123", store.LastSHA256())
	}
}

func sentryYAMLForAdminStoreTest(routeID string) string {
	return `transfer_policy:
  schema_version: 1
  enabled: true
  routes:
    - id: ` + routeID + `
      networks:
        - '*'
      sources:
        - '*'
      assets:
        - algo
      destinations:
        - '*'
`
}
