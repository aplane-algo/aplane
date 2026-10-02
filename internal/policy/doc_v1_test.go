// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	apconfig "github.com/aplane-algo/aplane/internal/config"
)

const testWitnessKeyIDV1 = "MYJZE3UF7G4JXR5STMQK5TSL5FNE7PE224BSKLZ2H4AJWJIPBEBQ"

var (
	v1Ops    = types.Address{0x11}
	v1Vendor = types.Address{0x22}
	v1Other  = types.Address{0x33}
	v1Bad    = types.Address{0x44}
	v1Holder = types.Address{0x55}
)

func TestDecodePolicyV1ReportsJSONPointer(t *testing.T) {
	signer := `{"format":"aplane.signer-policy.v1",%s}`
	route := `{"id":"r","networks":["testnet"],"sources":["*"],"assets":["algo"],"destinations":["*"]%s}`
	tp := func(routes string) string {
		return fmt.Sprintf(`"transfer_policy":{"enabled":true,"on_no_route":"reject","routes":[%s]}`, routes)
	}
	for _, tc := range []struct {
		name, doc, pointer, msg string
	}{
		{"duplicate key", `{"format":"aplane.signer-policy.v1","reject_clawback":true,"reject_clawback":false}`, "/reject_clawback", "duplicate key"},
		{"trailing data", `{"format":"aplane.signer-policy.v1"} {}`, "", "after the document"},
		{"invalid utf8", "{\"format\":\"aplane.signer-policy.v1\",\"description\":\"\xff\"}", "", "UTF-8"},
		{"numeric amount", fmt.Sprintf(signer, `"max_fee_microalgos":1000`), "/max_fee_microalgos", "decimal strings"},
		{"amount overflow", fmt.Sprintf(signer, `"max_fee_microalgos":"18446744073709551616"`), "/max_fee_microalgos", "18446744073709551615"},
		{"leading zero", fmt.Sprintf(signer, `"max_fee_microalgos":"0100"`), "/max_fee_microalgos", "leading zeros"},
		{"unknown nested field", fmt.Sprintf(signer, tp(fmt.Sprintf(route, `,"enabled":true`))), "/transfer_policy/routes/0/enabled", "unknown field"},
		{"bad route id", fmt.Sprintf(signer, tp(strings.Replace(fmt.Sprintf(route, ""), `"id":"r"`, `"id":"Bad"`, 1))), "/transfer_policy/routes/0/id", "route id"},
		{"bare asa id", fmt.Sprintf(signer, tp(strings.Replace(fmt.Sprintf(route, ""), `"algo"`, `"31566704"`, 1))), "/transfer_policy/routes/0/assets/0", "asa:<id>"},
		{"unknown set", fmt.Sprintf(signer, tp(strings.Replace(fmt.Sprintf(route, ""), `"sources":["*"]`, `"sources":["@ops"]`, 1))), "/transfer_policy/routes/0/sources/0", `unknown address set "ops"`},
		{"uncovered limit asset", fmt.Sprintf(signer, tp(fmt.Sprintf(route, `,"limits":{"testnet":{"asa:7":{"reject_above":"1"}}}`))), "/transfer_policy/routes/0/limits/testnet/asa:7", "does not cover asa:7"},
		{"uncovered limit network", fmt.Sprintf(signer, tp(fmt.Sprintf(route, `,"limits":{"mainnet":{"algo":{"reject_above":"1"}}}`))), "/transfer_policy/routes/0/limits/mainnet", "does not cover network"},
		{"review above reject", fmt.Sprintf(signer, `"limits":{"testnet":{"algo":{"review_above":"9","reject_above":"1"}}}`), "/limits/testnet/algo", "must not exceed"},
		{"clawback without asset_sources", fmt.Sprintf(signer, tp(fmt.Sprintf(route, `,"allow_clawback":true`))), "/transfer_policy/routes/0", "allow_clawback and asset_sources"},
		{"close with wildcard destination", fmt.Sprintf(signer, tp(fmt.Sprintf(route, `,"allow_close":true`))), "/transfer_policy/routes/0/destinations/0", "allow_close"},
		{"duplicate route id", fmt.Sprintf(signer, tp(fmt.Sprintf(route, "")+","+fmt.Sprintf(route, ""))), "/transfer_policy/routes/1/id", "duplicate route id"},
		{"enabled without on_no_route", fmt.Sprintf(signer, `"transfer_policy":{"enabled":true}`), "/transfer_policy", "on_no_route is required"},
		{"override transfer_policy", fmt.Sprintf(signer, fmt.Sprintf(`"key_overrides":{%q:{"transfer_policy":{}}}`, v1Ops.String())), "/key_overrides/" + v1Ops.String() + "/transfer_policy", "cannot carry transfer_policy"},
		{"override merged review above reject", fmt.Sprintf(signer, fmt.Sprintf(`"limits":{"testnet":{"algo":{"reject_above":"5"}}},"key_overrides":{%q:{"limits":{"testnet":{"algo":{"review_above":"9"}}}}}`, v1Ops.String())), "/key_overrides/" + v1Ops.String() + "/limits", "after merging"},
		{"duplicate address in set", fmt.Sprintf(signer, fmt.Sprintf(`"address_sets":{"ops":[%q,%q]}`, v1Ops.String(), v1Ops.String())), "/address_sets/ops/1", "duplicate address"},
		{"description too long", fmt.Sprintf(signer, fmt.Sprintf(`"description":%q`, strings.Repeat("中", maxPolicyDescriptionLength+1))), "/description", "1024 characters"},
		{"cosigner document on signer", `{"format":"aplane.cosigner-policy.v1"}`, "/format", "not accepted here"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeSignerPolicyV1([]byte(tc.doc))
			assertDocumentError(t, err, tc.pointer, tc.msg)
		})
	}

	t.Run("document too large", func(t *testing.T) {
		big := fmt.Sprintf(signer, fmt.Sprintf(`"description":%q`, strings.Repeat("x", maxPolicyDocumentBytes)))
		_, err := DecodeSignerPolicyV1([]byte(big))
		assertDocumentError(t, err, "", "larger than")
	})
	t.Run("cosigner key must match file name", func(t *testing.T) {
		doc := fmt.Sprintf(`{"format":"aplane.cosigner-policy.v1","key":%q,"transfer_policy":{"routes":[]}}`, testWitnessKeyIDV1)
		_, err := DecodeCosignerPolicyV1([]byte(doc), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
		assertDocumentError(t, err, "/key", "does not match its file name")
	})
	t.Run("description limit counts characters", func(t *testing.T) {
		doc := fmt.Sprintf(signer, fmt.Sprintf(`"description":%q`, strings.Repeat("中", maxPolicyDescriptionLength)))
		if _, err := DecodeSignerPolicyV1([]byte(doc)); err != nil {
			t.Fatalf("DecodeSignerPolicyV1() error = %v", err)
		}
	})
	t.Run("cosigner rekey per-network set", func(t *testing.T) {
		doc := fmt.Sprintf(`{"format":"aplane.cosigner-policy.v1","key":%q,"address_sets":{"ops":{"testnet":[%q]}},"transfer_policy":{"routes":[]},"rekey_policy":{"allowed":[{"sender":%q,"targets":["@ops"]}]}}`,
			testWitnessKeyIDV1, v1Ops.String(), v1Vendor.String())
		_, err := DecodeCosignerPolicyV1([]byte(doc), testWitnessKeyIDV1)
		assertDocumentError(t, err, "/rekey_policy/allowed/0/targets/0", "per-network address set")
	})
	t.Run("cosigner review threshold", func(t *testing.T) {
		doc := fmt.Sprintf(`{"format":"aplane.cosigner-policy.v1","key":%q,"limits":{"testnet":{"algo":{"review_above":"1"}}},"transfer_policy":{"routes":[]}}`, testWitnessKeyIDV1)
		_, err := DecodeCosignerPolicyV1([]byte(doc), testWitnessKeyIDV1)
		assertDocumentError(t, err, "/limits/testnet/algo/review_above", "cannot produce review verdicts")
	})
}

func assertDocumentError(t *testing.T, err error, pointer, msg string) {
	t.Helper()
	var docErr *DocumentError
	if !errors.As(err, &docErr) {
		t.Fatalf("error = %v, want *DocumentError", err)
	}
	if docErr.Pointer != pointer || !strings.Contains(docErr.Msg, msg) {
		t.Fatalf("error = %q at %q, want %q at %q", docErr.Msg, docErr.Pointer, msg, pointer)
	}
}

// TestSignerPolicyV1MatchesYAMLVerdicts compiles the same signer policy from
// policy.yaml and from v1 JSON and requires identical verdicts for every
// transaction, for the base config and for a key override.
func TestSignerPolicyV1MatchesYAMLVerdicts(t *testing.T) {
	yamlDoc := fmt.Sprintf(`
reject_clawback: true
max_fee_microalgos: 5000
review_algo_payments: {testnet: 100000000}
max_algo_payments: {testnet: 1000000000}
max_asa_amounts: {testnet: {"777": 500}}
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: review
  close_on_no_route: reject
  blocked_destinations: [%[1]s]
  address_sets: {ops: [%[2]s]}
  asset_sets: {usd: {testnet: [777]}}
  routes:
    - {id: ops-algo, networks: [testnet], sources: ["@ops"], assets: [algo], destinations: ["*"], limits: {reject_above: 50000000}}
    - {id: ops-usd, networks: [testnet], sources: ["@ops"], assets: ["@usd"], destinations: [%[3]s], limits: {review_above: 100}}
    - {id: ops-close, networks: [testnet], sources: ["@ops"], assets: [algo], destinations: [%[3]s], close: {allow: true}}
key_overrides:
  %[2]s: {max_fee_microalgos: 2000, review_algo_payments: {testnet: 10000000}}
`, v1Bad, v1Ops, v1Vendor)
	jsonDoc := fmt.Sprintf(`{
  "format": "aplane.signer-policy.v1",
  "reject_clawback": true,
  "max_fee_microalgos": "5000",
  "limits": {"testnet": {"algo": {"review_above": "100000000", "reject_above": "1000000000"}, "asa:777": {"reject_above": "500"}}},
  "address_sets": {"ops": [%[2]q]},
  "asset_sets": {"usd": {"testnet": ["asa:777"]}},
  "transfer_policy": {
    "enabled": true, "on_no_route": "review", "close_on_no_route": "reject", "blocked_destinations": [%[1]q],
    "routes": [
      {"id": "ops-algo", "networks": ["testnet"], "sources": ["@ops"], "assets": ["algo"], "destinations": ["*"], "limits": {"testnet": {"algo": {"reject_above": "50000000"}}}},
      {"id": "ops-usd", "networks": ["testnet"], "sources": ["@ops"], "assets": ["@usd"], "destinations": [%[3]q], "limits": {"testnet": {"asa:777": {"review_above": "100"}}}},
      {"id": "ops-close", "networks": ["testnet"], "sources": ["@ops"], "assets": ["algo"], "destinations": [%[3]q], "allow_close": true}
    ]
  },
  "key_overrides": {%[2]q: {"max_fee_microalgos": "2000", "limits": {"testnet": {"algo": {"review_above": "10000000"}}}}}
}`, v1Bad.String(), v1Ops.String(), v1Vendor.String())

	stored, err := ParseStoredConfig([]byte(yamlDoc))
	if err != nil {
		t.Fatalf("ParseStoredConfig() error = %v", err)
	}
	fromYAML, err := stored.ApplySigning(DefaultConfig())
	if err != nil {
		t.Fatalf("ApplySigning() error = %v", err)
	}
	doc, err := DecodeSignerPolicyV1([]byte(jsonDoc))
	if err != nil {
		t.Fatalf("DecodeSignerPolicyV1() error = %v", err)
	}
	fromJSON, err := doc.Compile(DefaultConfig())
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	distinct := map[string]bool{}
	for _, tc := range v1VerdictTransactions(t) {
		for _, key := range []string{v1Ops.String(), v1Other.String()} {
			want := policyVerdicts(tc.txn, fromYAML.ForKey(key))
			got := policyVerdicts(tc.txn, fromJSON.ForKey(key))
			if got != want {
				t.Errorf("%s signed by %s: v1 verdicts %q, yaml verdicts %q", tc.name, key[:6], got, want)
			}
			distinct[want] = true
		}
	}
	if len(distinct) < 8 {
		t.Fatalf("only %d distinct verdict sets; the transaction matrix is not exercising the policy", len(distinct))
	}
}

// TestCosignerPolicyV1MatchesYAMLVerdicts does the same for one cosigner key.
func TestCosignerPolicyV1MatchesYAMLVerdicts(t *testing.T) {
	yamlDoc := fmt.Sprintf(`
reject_close_remainder: true
max_fee_microalgos: 5000
max_asa_amounts: {testnet: {"777": 500}}
transfer_policy:
  schema_version: 1
  enabled: true
  blocked_destinations: [%[1]s]
  address_sets: {ops: [%[2]s]}
  routes:
    - {id: ops-usd, networks: [testnet], sources: ["@ops"], assets: ["asa:777"], destinations: [%[3]s], limits: {reject_above: 300}}
    - {id: ops-algo, networks: ["*"], sources: ["@ops"], assets: [algo], destinations: ["*"]}
rekey_policy:
  allowed:
    - {sender: "@ops", targets: [%[3]s]}
`, v1Bad, v1Ops, v1Vendor)
	jsonDoc := fmt.Sprintf(`{
  "format": "aplane.cosigner-policy.v1", "key": %[4]q,
  "reject_close_remainder": true,
  "max_fee_microalgos": "5000",
  "limits": {"testnet": {"asa:777": {"reject_above": "500"}}},
  "address_sets": {"ops": [%[2]q]},
  "transfer_policy": {"blocked_destinations": [%[1]q], "routes": [
    {"id": "ops-usd", "networks": ["testnet"], "sources": ["@ops"], "assets": ["asa:777"], "destinations": [%[3]q], "limits": {"testnet": {"asa:777": {"reject_above": "300"}}}},
    {"id": "ops-algo", "networks": ["*"], "sources": ["@ops"], "assets": ["algo"], "destinations": ["*"]}
  ]},
  "rekey_policy": {"allowed": [{"sender": "@ops", "targets": [%[3]q]}]}
}`, v1Bad.String(), v1Ops.String(), v1Vendor.String(), testWitnessKeyIDV1)

	stored, err := ParseStoredCosignerConfig([]byte(yamlDoc))
	if err != nil {
		t.Fatalf("ParseStoredCosignerConfig() error = %v", err)
	}
	fromYAML, err := stored.ApplyCosigner(DefaultConfig())
	if err != nil {
		t.Fatalf("ApplyCosigner() error = %v", err)
	}
	doc, err := DecodeCosignerPolicyV1([]byte(jsonDoc), testWitnessKeyIDV1)
	if err != nil {
		t.Fatalf("DecodeCosignerPolicyV1() error = %v", err)
	}
	fromJSON, err := doc.Compile(DefaultConfig())
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	for _, tc := range v1VerdictTransactions(t) {
		if got, want := policyVerdicts(tc.txn, fromJSON), policyVerdicts(tc.txn, fromYAML); got != want {
			t.Errorf("%s: v1 verdicts %q, yaml verdicts %q", tc.name, got, want)
		}
	}
	for _, pair := range [][2]types.Address{{v1Ops, v1Vendor}, {v1Ops, v1Other}, {v1Other, v1Vendor}} {
		if got, want := fromJSON.RekeyPolicy.Allows(pair[0], pair[1]), fromYAML.RekeyPolicy.Allows(pair[0], pair[1]); got != want {
			t.Errorf("rekey %s -> %s allowed = %v, yaml %v", pair[0].String()[:6], pair[1].String()[:6], got, want)
		}
	}
	if fromJSON.TransferPolicy.OnNoRoute != TransferOnNoRouteReject || fromJSON.TransferPolicy.CloseOnNoRoute != TransferOnNoRouteReject ||
		fromJSON.TransferPolicy.ClawbackOnNoRoute != TransferOnNoRouteReject || !fromJSON.TransferPolicy.Enabled {
		t.Fatalf("cosigner transfer policy = %+v, want enabled with reject route misses", fromJSON.TransferPolicy)
	}
}

// TestPolicyV1RouteLimitsArePerAsset covers what policy.yaml could not
// express: one route with different limits per asset, and ALGO in a set.
func TestPolicyV1RouteLimitsArePerAsset(t *testing.T) {
	doc, err := DecodeSignerPolicyV1([]byte(fmt.Sprintf(`{
  "format": "aplane.signer-policy.v1",
  "asset_sets": {"mix": {"testnet": ["algo", "asa:777"]}},
  "transfer_policy": {"enabled": true, "on_no_route": "reject", "routes": [
    {"id": "mixed", "networks": ["testnet"], "sources": ["*"], "assets": ["@mix"], "destinations": [%q],
     "limits": {"testnet": {"algo": {"reject_above": "100"}, "asa:777": {"reject_above": "5"}}}}
  ]}
}`, v1Vendor.String())))
	if err != nil {
		t.Fatalf("DecodeSignerPolicyV1() error = %v", err)
	}
	cfg, err := doc.Compile(DefaultConfig())
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	testnet := testGenesisDigest(t, apconfig.AlgorandTestnetGenesisHash)
	for _, tc := range []struct {
		name string
		txn  types.Transaction
		want string
	}{
		{"algo within its limit", v1Payment(testnet, v1Ops, v1Vendor, 100), ""},
		{"algo over its limit", v1Payment(testnet, v1Ops, v1Vendor, 101), TransferRoutingRouteRuleID("mixed", TransferRoutingRejectAboveOutcome)},
		{"asa within its own limit", v1AssetTransfer(testnet, v1Ops, v1Vendor, 777, 5), ""},
		{"asa over its own limit", v1AssetTransfer(testnet, v1Ops, v1Vendor, 777, 6), TransferRoutingRouteRuleID("mixed", TransferRoutingRejectAboveOutcome)},
		{"asset outside the set", v1AssetTransfer(testnet, v1Ops, v1Vendor, 888, 1), TransferRoutingRouteMissRuleID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := policyVerdicts(tc.txn, cfg); got != tc.want {
				t.Fatalf("verdicts = %q, want %q", got, tc.want)
			}
		})
	}
}

type v1VerdictCase struct {
	name string
	txn  types.Transaction
}

func v1VerdictTransactions(t *testing.T) []v1VerdictCase {
	testnet := testGenesisDigest(t, apconfig.AlgorandTestnetGenesisHash)
	unknown := types.Digest{0xee}
	payClose := v1Payment(testnet, v1Ops, v1Vendor, 1)
	payClose.CloseRemainderTo = v1Vendor
	payCloseOther := v1Payment(testnet, v1Ops, v1Vendor, 1)
	payCloseOther.CloseRemainderTo = v1Other
	clawback := v1AssetTransfer(testnet, v1Ops, v1Vendor, 777, 10)
	clawback.AssetSender = v1Holder
	highFee := v1Payment(testnet, v1Ops, v1Vendor, 1)
	highFee.Fee = 3000
	return []v1VerdictCase{
		{"small algo payment", v1Payment(testnet, v1Ops, v1Other, 10_000_000)},
		{"algo over route reject", v1Payment(testnet, v1Ops, v1Other, 60_000_000)},
		{"algo over document review", v1Payment(testnet, v1Ops, v1Other, 200_000_000)},
		{"algo over document reject", v1Payment(testnet, v1Ops, v1Other, 2_000_000_000)},
		{"algo to blocked destination", v1Payment(testnet, v1Ops, v1Bad, 1)},
		{"algo from unrouted sender", v1Payment(testnet, v1Other, v1Vendor, 1)},
		{"algo on unknown network", v1Payment(unknown, v1Ops, v1Vendor, 1)},
		{"usd within limits", v1AssetTransfer(testnet, v1Ops, v1Vendor, 777, 50)},
		{"usd over route review", v1AssetTransfer(testnet, v1Ops, v1Vendor, 777, 150)},
		{"usd over route cosigner reject", v1AssetTransfer(testnet, v1Ops, v1Vendor, 777, 400)},
		{"usd over document reject", v1AssetTransfer(testnet, v1Ops, v1Vendor, 777, 600)},
		{"usd to unrouted destination", v1AssetTransfer(testnet, v1Ops, v1Other, 777, 1)},
		{"unrouted asset", v1AssetTransfer(testnet, v1Ops, v1Vendor, 888, 1)},
		{"close to routed destination", payClose},
		{"close to unrouted destination", payCloseOther},
		{"clawback", clawback},
		{"fee between override and base caps", highFee},
	}
}

func v1Payment(genesis types.Digest, from, to types.Address, amount uint64) types.Transaction {
	return types.Transaction{
		Type:             types.PaymentTx,
		Header:           types.Header{Sender: from, Fee: 1000, GenesisHash: genesis},
		PaymentTxnFields: types.PaymentTxnFields{Receiver: to, Amount: types.MicroAlgos(amount)},
	}
}

func v1AssetTransfer(genesis types.Digest, from, to types.Address, asset, amount uint64) types.Transaction {
	return types.Transaction{
		Type:   types.AssetTransferTx,
		Header: types.Header{Sender: from, Fee: 1000, GenesisHash: genesis},
		AssetTransferTxnFields: types.AssetTransferTxnFields{
			XferAsset: types.AssetIndex(asset), AssetAmount: amount, AssetReceiver: to,
		},
	}
}

// policyVerdicts returns the sorted rule IDs every policy lint phase emits.
func policyVerdicts(txn types.Transaction, cfg *Config) string {
	var ids []string
	for _, phase := range [][]LintViolation{
		CheckTxnPolicyLints(txn, cfg, nil),
		CheckTxnReviewPolicyLints(txn, cfg),
		CheckTxnTransferRoutingPolicyLints(txn, cfg, false),
		CheckTxnTransferRoutingReviewPolicyLints(txn, cfg, false),
	} {
		for _, v := range phase {
			ids = append(ids, v.RuleID)
		}
	}
	sort.Strings(ids)
	return strings.Join(ids, ",")
}

// TestPolicyV1ZeroThresholdsAreEnforced pins that "0" is a threshold, not
// "unset": a zero reject_above rejects any nonzero amount for ALGO and ASAs.
func TestPolicyV1ZeroThresholdsAreEnforced(t *testing.T) {
	doc, err := DecodeSignerPolicyV1([]byte(`{
  "format": "aplane.signer-policy.v1",
  "limits": {"testnet": {"algo": {"review_above": "0", "reject_above": "0"}, "asa:777": {"reject_above": "0"}}}
}`))
	if err != nil {
		t.Fatalf("DecodeSignerPolicyV1() error = %v", err)
	}
	cfg, err := doc.Compile(DefaultConfig())
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	testnet := testGenesisDigest(t, apconfig.AlgorandTestnetGenesisHash)
	for _, tc := range []struct {
		name string
		txn  types.Transaction
		want string
	}{
		{"zero algo", v1Payment(testnet, v1Ops, v1Vendor, 0), ""},
		{"nonzero algo", v1Payment(testnet, v1Ops, v1Vendor, 1), MaxAlgoPaymentExceededRuleID + "," + ReviewAlgoPaymentExceededRuleID},
		{"nonzero asa", v1AssetTransfer(testnet, v1Ops, v1Vendor, 777, 1), MaxASAAmountExceededRuleID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := policyVerdicts(tc.txn, cfg); got != tc.want {
				t.Fatalf("verdicts = %q, want %q", got, tc.want)
			}
		})
	}
}
