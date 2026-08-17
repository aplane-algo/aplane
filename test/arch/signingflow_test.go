// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package arch_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// clientPackageDirs are client-side packages that must route guarded signing
// on the runtime signing_flow metadata served by the daemon, never on the
// compiled guarded key-type vocabulary. The compiled switches stay available
// to signer-side code, which owns the keys it reports on.
var clientPackageDirs = []string{
	"../../internal/engine",
	"../../internal/engine/guarded",
	"../../internal/apshellapp",
	"../../internal/apshellcli",
	"../../internal/clientsign",
	"../../internal/clientstate",
	"../../internal/jsapi",
}

// forbiddenGuardedSwitches are the compiled key-type classification helpers
// that would silently re-couple clients to the built-in guarded families. A
// client using them cannot handle a guarded key family it was not compiled
// with; routing must come from signing_flow (see signerapi.SigningFlowSentry1).
var forbiddenGuardedSwitches = []string{
	"IsGuardedAccountKeyType",
	"SentryComponentKeyTypeForGuardedAccount",
	"ComponentPublicKeySize",
	"IsSentryComponentKeyType",
	"witness.ID(",
}

// TestClientPackagesRouteOnSigningFlow pins the sentry1 signing-flow
// contract: client packages must not classify keys with the compiled guarded
// key-type switches in production code. Test files are exempt because they
// simulate the daemon side of the contract.
func TestClientPackagesRouteOnSigningFlow(t *testing.T) {
	for _, dir := range clientPackageDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			path := filepath.Join(dir, name)
			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			for _, forbidden := range forbiddenGuardedSwitches {
				if strings.Contains(string(content), forbidden) {
					t.Errorf("%s uses compiled guarded key-type switch %s; client routing must use runtime signing_flow metadata", path, forbidden)
				}
			}
		}
	}
}

// TestSigningFlowCharacterizationInventory keeps the behavioral tests that
// define the pre-unification baseline visible while the component and assembly
// transports are collapsed. A listed test may be renamed only when its
// replacement pins the same gate or byte-level boundary.
func TestSigningFlowCharacterizationInventory(t *testing.T) {
	testsByFile := map[string][]string{
		"../../internal/signerapp/signing/component_test.go": {
			"TestPrepareComponentSigningCanonicalizesTargetsAndMessages",
			"TestSignComponentSentryRequiresPolicyBeforeKeyLoad",
			"TestSignComponentSentryPolicyAllowsSigning",
			"TestAssembleDecodedGuardedVerifiesAndBuildsSignedGroup",
			"TestAssembleDecodedGuardedRejectsMismatchedPassthrough",
		},
		"../../internal/signerapp/signing/component_gate_test.go": {
			"TestSignComponentUserRoleRejectedBySignerPolicy",
			"TestSignComponentUserRoleOperatorApproves",
			"TestSignComponentUserRoleUserAutoApproveSkipsPrompt",
			"TestSignComponentUserRoleForeignRekeyLegForcesReview",
		},
		"../../internal/signerapp/signing/bounded_sentry_test.go": {
			"TestValidateBoundedComponentPlanRequiresSentrySpend",
			"TestBoundedAssemblyReceiptBindsRuntimeAndMetadata",
			"TestAssembleBoundedTargetVerifiesBothAuthorities",
		},
	}
	for path, names := range testsByFile {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for _, name := range names {
			if !strings.Contains(string(content), "func "+name+"(") {
				t.Errorf("%s no longer contains %s; add an equivalent characterization before removing it", path, name)
			}
		}
	}
}

func TestUnifiedSigningRoutesRemainSingular(t *testing.T) {
	content, err := os.ReadFile("../../internal/signerapp/daemon/http_runtime.go")
	if err != nil {
		t.Fatal(err)
	}
	routes := string(content)
	for _, retired := range []string{"/sign/bounded-component", "/sign/bounded-assemble"} {
		if strings.Contains(routes, retired) {
			t.Errorf("retired flow-specific route %q was reintroduced", retired)
		}
	}
	for _, shared := range []string{"/sign/component", "/sign/assemble"} {
		if count := strings.Count(routes, `mux.HandleFunc("`+shared+`"`); count != 1 {
			t.Errorf("shared route %q registration count = %d, want 1", shared, count)
		}
	}
}

func TestFrozenComponentValidatorNeverCanonicalizes(t *testing.T) {
	content, err := os.ReadFile("../../internal/signerapp/signing/frozen_component.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(content)
	for _, forbidden := range []string{".PlanGroup(", "planGroupWhileSignable("} {
		if strings.Contains(source, forbidden) {
			t.Errorf("frozen component validator contains canonicalizing call %q", forbidden)
		}
	}
}
