// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/noderole"
)

// decodeStep breaks a complete document at one step of DecodePolicyV1.
type decodeStep struct {
	name  string
	apply func(doc, transferPolicy map[string]any)
}

func set(field string, value any) func(doc, tp map[string]any) {
	return func(doc, _ map[string]any) { doc[field] = value }
}

func setTransfer(field string, value any) func(doc, tp map[string]any) {
	return func(_, tp map[string]any) { tp[field] = value }
}

func remove(field string) func(doc, tp map[string]any) {
	return func(doc, _ map[string]any) { delete(doc, field) }
}

// routeToAnUndefinedSet gives the document a well-formed route that names an
// asset set it does not define, which only the final validation refuses. It
// leaves routes alone when an earlier step already broke them.
func routeToAnUndefinedSet(_, tp map[string]any) {
	if _, broken := tp["routes"].(int); broken {
		return
	}
	tp["routes"] = []any{map[string]any{
		"id": "r", "networks": []any{"testnet"}, "sources": []any{"*"}, "assets": []any{"@undefined"}, "destinations": []any{"*"},
	}}
}

func otherRole(role noderole.Role) noderole.Role {
	if role == noderole.RoleSigner {
		return noderole.RoleCosigner
	}
	return noderole.RoleSigner
}

// The steps of the decoder in the order it takes them. Each role refuses the
// fields that belong to the other, at the step where the other reads them.
func decodeSteps(role noderole.Role) []decodeStep {
	signer := role == noderole.RoleSigner
	either := func(forSigner, forCosigner func(doc, tp map[string]any)) func(doc, tp map[string]any) {
		if signer {
			return forSigner
		}
		return forCosigner
	}
	return []decodeStep{
		{"format", set("format", 1)},
		{"role", set("role", "observer")},
		{"key", set("key", 5)},
		{"description", set("description", 5)},
		{"rekeys", either(remove("rekeys"), set("rekeys", "allow"))},
		{"reject_close_remainder", set("reject_close_remainder", "x")},
		{"reject_asset_close", set("reject_asset_close", "x")},
		{"reject_clawback", set("reject_clawback", "x")},
		{"reject_rekey", either(set("reject_rekey", false), set("reject_rekey", "x"))},
		{"always_review_warnings", either(set("always_review_warnings", "x"), set("always_review_warnings", false))},
		{"auto_approve_self_noop_transfer", either(set("auto_approve_self_noop_transfer", "x"), set("auto_approve_self_noop_transfer", false))},
		{"max_fee_microalgos", set("max_fee_microalgos", true)},
		{"transaction_types", set("transaction_types", 5)},
		{"limits", set("limits", 5)},
		{"address_sets", set("address_sets", 5)},
		{"asset_sets", set("asset_sets", 5)},
		{"transfer_policy.on_no_route", either(setTransfer("on_no_route", 5), setTransfer("on_no_route", "reject"))},
		{"transfer_policy.close_on_no_route", either(setTransfer("close_on_no_route", 5), setTransfer("close_on_no_route", "reject"))},
		{"transfer_policy.clawback_on_no_route", either(setTransfer("clawback_on_no_route", 5), setTransfer("clawback_on_no_route", "reject"))},
		{"transfer_policy.blocked_destinations", setTransfer("blocked_destinations", 5)},
		{"transfer_policy.routes", setTransfer("routes", 5)},
		{"transfer_policy unknown field", setTransfer("not_a_field", 1)},
		{"rekey_policy", either(set("rekey_policy", []any{}), set("rekey_policy", 5))},
		{"unknown field", set("not_a_field", 1)},
		{"validation", routeToAnUndefinedSet},
	}
}

// Other ways to break a step, by the name of the step they replace.
func decodeStepVariants(role noderole.Role) []decodeStep {
	return []decodeStep{
		{"role", set("role", string(otherRole(role)))},
		{"key", set("key", "not a key")},
		{"transfer_policy.on_no_route", remove("transfer_policy")},
		{"transfer_policy.on_no_route", set("transfer_policy", 5)},
	}
}

// brokenJSON is a complete document broken at the given steps.
func brokenJSON(t *testing.T, role noderole.Role, steps []decodeStep) []byte {
	t.Helper()
	doc := minimalPolicyMap(role, DefaultKey)
	tp, _ := doc["transfer_policy"].(map[string]any)
	for _, step := range steps {
		step.apply(doc, tp)
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func decodeBroken(t *testing.T, role noderole.Role, steps []decodeStep) error {
	t.Helper()
	_, err := DecodePolicyV1(brokenJSON(t, role, steps), DefaultKey, role)
	return err
}

// checkDecodeOrder breaks every step together with all the steps after it and
// requires the error the step gives alone, so the whole order is pinned.
func checkDecodeOrder(t *testing.T, role noderole.Role, steps []decodeStep) {
	t.Helper()
	alone := make([]string, len(steps))
	seen := map[string]string{}
	for i, step := range steps {
		err := decodeBroken(t, role, steps[i:i+1])
		if err == nil {
			t.Fatalf("breaking %s alone was accepted", step.name)
		}
		alone[i] = err.Error()
		if other, dup := seen[alone[i]]; dup {
			t.Fatalf("%s and %s give the same error %q, so their order cannot be told apart", other, step.name, alone[i])
		}
		seen[alone[i]] = step.name
	}
	for i, step := range steps {
		err := decodeBroken(t, role, steps[i:])
		if err == nil || err.Error() != alone[i] {
			t.Errorf("broken from %s on: error = %v, want %q", step.name, err, alone[i])
		}
	}
}

// A document broken at several steps reports the earliest one.
func TestDecodePolicyV1ReportsTheEarliestBrokenStep(t *testing.T) {
	for _, role := range []noderole.Role{noderole.RoleSigner, noderole.RoleCosigner} {
		t.Run(string(role), func(t *testing.T) {
			if err := decodeBroken(t, role, nil); err != nil {
				t.Fatalf("the unbroken document: %v", err)
			}
			steps := decodeSteps(role)
			checkDecodeOrder(t, role, steps)

			// The last step is refused by validation and nothing earlier.
			if err := decodeBroken(t, role, steps[len(steps)-1:]); !strings.Contains(err.Error(), `unknown asset set "undefined"`) {
				t.Fatalf("the validation step's error = %v", err)
			}

			for _, variant := range decodeStepVariants(role) {
				swapped := append([]decodeStep(nil), steps...)
				found := false
				for i := range swapped {
					if swapped[i].name == variant.name {
						swapped[i], found = variant, true
					}
				}
				if !found {
					t.Fatalf("no step named %s", variant.name)
				}
				checkDecodeOrder(t, role, swapped)
			}
		})
	}
}

// The checks inside the key step run in order: the key must be valid for the
// role before it is compared with the file name.
func TestDecodePolicyV1ChecksTheKeyBeforeItsFileName(t *testing.T) {
	validKeys := map[noderole.Role]string{noderole.RoleSigner: v1Ops.String(), noderole.RoleCosigner: testWitnessKeyIDV1}
	for _, role := range []noderole.Role{noderole.RoleSigner, noderole.RoleCosigner} {
		t.Run(string(role), func(t *testing.T) {
			invalid := brokenJSON(t, role, []decodeStep{{"key", set("key", "not a key")}})
			if _, err := DecodePolicyV1(invalid, "another-file", role); err == nil || !strings.Contains(err.Error(), "policy key must be") {
				t.Fatalf("an invalid key under another file name: error = %v, want the invalid key reported", err)
			}
			valid := brokenJSON(t, role, []decodeStep{{"key", set("key", validKeys[role])}})
			if _, err := DecodePolicyV1(valid, DefaultKey, role); err == nil || !strings.Contains(err.Error(), "does not match its file name") {
				t.Fatalf("a valid key under another file name: error = %v, want the mismatch reported", err)
			}
			if _, err := DecodePolicyV1(valid, validKeys[role], role); err != nil {
				t.Fatalf("a valid key under its own file name: %v", err)
			}
		})
	}
}

// Unknown members are reported in document order, not sorted.
func TestDecodePolicyV1ReportsTheFirstUnknownMemberInDocumentOrder(t *testing.T) {
	for _, role := range []noderole.Role{noderole.RoleSigner, noderole.RoleCosigner} {
		complete := string(brokenJSON(t, role, nil))
		data := `{"zzz_unknown":1,"aaa_unknown":1,` + strings.TrimPrefix(complete, "{")
		_, err := DecodePolicyV1([]byte(data), DefaultKey, role)
		if err == nil || !strings.HasPrefix(err.Error(), "/zzz_unknown: ") {
			t.Fatalf("%s: error = %v, want the first unknown member, /zzz_unknown", role, err)
		}
	}
}
