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
	"github.com/aplane-algo/aplane/internal/noderole"
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
	route := `{"id":"r","networks":["testnet"],"sources":["*"],"assets":["algo"],"destinations":["*"]%s}`
	tp := func(routes string) string {
		return fmt.Sprintf(`"transfer_policy":{"routes":[%s]}`, routes)
	}
	// routeWith returns the base route with one substring replaced and extra
	// members appended.
	routeWith := func(old, replacement, extra string) string {
		return strings.Replace(fmt.Sprintf(route, extra), old, replacement, 1)
	}
	holder := v1Holder.String()
	signer := func(sparse string) []byte { return signerJSON(t, DefaultKey, "{"+sparse+"}") }
	cosigner := func(sparse string) []byte { return cosignerJSON(t, testWitnessKeyIDV1, "{"+sparse+"}") }
	for _, tc := range []struct {
		name    string
		doc     []byte
		key     string
		role    noderole.Role
		pointer string
		msg     string
	}{
		{"duplicate key", []byte(`{"format":"aplane.policy.v1","reject_clawback":true,"reject_clawback":false}`), DefaultKey, noderole.RoleSigner, "/reject_clawback", "duplicate key"},
		{"trailing data", append(signer(""), []byte(" {}")...), DefaultKey, noderole.RoleSigner, "", "after the document"},
		{"invalid utf8", []byte("{\"format\":\"aplane.policy.v1\",\"description\":\"\xff\"}"), DefaultKey, noderole.RoleSigner, "", "UTF-8"},
		{"wrong format", []byte(`{"format":"aplane.signer-policy.v1"}`), DefaultKey, noderole.RoleSigner, "/format", "unsupported format"},
		{"missing role", []byte(`{"format":"aplane.policy.v1"}`), DefaultKey, noderole.RoleSigner, "", `missing required field "role"`},
		{"unknown role", []byte(`{"format":"aplane.policy.v1","role":"auditor"}`), DefaultKey, noderole.RoleSigner, "/role", "role must be"},
		{"cosigner document on signer node", cosigner(""), testWitnessKeyIDV1, noderole.RoleSigner, "/role", "not accepted on a signer node"},
		{"signer document on cosigner node", signer(""), DefaultKey, noderole.RoleCosigner, "/role", "not accepted on a cosigner node"},
		{"key mismatch", signer(""), v1Ops.String(), noderole.RoleSigner, "/key", "does not match its file name"},
		{"signer key is witness id", signerJSON(t, testWitnessKeyIDV1, ""), testWitnessKeyIDV1, noderole.RoleSigner, "/key", "Algorand address"},
		{"cosigner key is address", cosignerJSON(t, v1Ops.String(), ""), v1Ops.String(), noderole.RoleCosigner, "/key", "Witness Key ID"},
		{"bad address checksum", signerJSON(t, strings.Repeat("A", 58), ""), strings.Repeat("A", 58), noderole.RoleSigner, "/key", "Algorand address"},
		{"missing required bool", []byte(strings.Replace(string(signer("")), `"always_review_warnings": false,`, "", 1)), DefaultKey, noderole.RoleSigner, "", `missing required field "always_review_warnings"`},
		{"missing max fee", []byte(strings.Replace(string(signer("")), `"max_fee_microalgos": "0",`, "", 1)), DefaultKey, noderole.RoleSigner, "", `missing required field "max_fee_microalgos"`},
		{"numeric amount", signer(`"max_fee_microalgos":1000`), DefaultKey, noderole.RoleSigner, "/max_fee_microalgos", "decimal strings"},
		{"amount overflow", signer(`"max_fee_microalgos":"18446744073709551616"`), DefaultKey, noderole.RoleSigner, "/max_fee_microalgos", "18446744073709551615"},
		{"leading zero", signer(`"max_fee_microalgos":"0100"`), DefaultKey, noderole.RoleSigner, "/max_fee_microalgos", "leading zeros"},
		{"missing transaction types", []byte(strings.Replace(string(signer("")), `"transaction_types": {`, `"transaction_typos": {`, 1)), DefaultKey, noderole.RoleSigner, "", `missing required field "transaction_types"`},
		{"transaction types missing wildcard", signer(`"transaction_types":{"pay":"allow"}`), DefaultKey, noderole.RoleSigner, "/transaction_types", `missing required field "*"`},
		{"unknown transaction type", signer(`"transaction_types":{"*":"allow","pmt":"allow"}`), DefaultKey, noderole.RoleSigner, "/transaction_types/pmt", "unknown transaction type"},
		{"unknown type verdict", signer(`"transaction_types":{"*":"prompt"}`), DefaultKey, noderole.RoleSigner, "/transaction_types/*", "must be one of allow, review, reject"},
		{"cosigner review type", cosigner(`"transaction_types":{"*":"reject","pay":"review"}`), testWitnessKeyIDV1, noderole.RoleCosigner, "/transaction_types/pay", "cannot produce review"},
		{"cosigner allow non-transfer type", cosigner(`"transaction_types":{"*":"reject","appl":"allow"}`), testWitnessKeyIDV1, noderole.RoleCosigner, "/transaction_types/appl", "only pay and axfer"},
		{"cosigner wildcard allow", cosigner(`"transaction_types":{"*":"allow"}`), testWitnessKeyIDV1, noderole.RoleCosigner, "/transaction_types/*", "only pay and axfer"},
		{"cosigner omitted wildcard still rejects non-transfer allow", cosigner(`"transaction_types":{"pay":"allow","appl":"allow"}`), testWitnessKeyIDV1, noderole.RoleCosigner, "/transaction_types/appl", "only pay and axfer"},
		{"cosigner review field", cosigner(`"always_review_warnings":true`), testWitnessKeyIDV1, noderole.RoleCosigner, "/always_review_warnings", "not accepted in a cosigner document"},
		{"cosigner foreign rekey field", cosigner(`"reject_foreign_rekey":true`), testWitnessKeyIDV1, noderole.RoleCosigner, "/reject_foreign_rekey", "not accepted in a cosigner document"},
		{"cosigner route miss field", cosigner(`"transfer_policy":{"on_no_route":"reject"}`), testWitnessKeyIDV1, noderole.RoleCosigner, "/transfer_policy/on_no_route", "not accepted in a cosigner document"},
		{"cosigner review threshold", cosigner(`"limits":{"testnet":{"algo":{"review_above":"1"}}}`), testWitnessKeyIDV1, noderole.RoleCosigner, "/limits/testnet/algo/review_above", "cannot produce review verdicts"},
		{"signer rekey policy", signer(`"rekey_policy":{"allowed":[]}`), DefaultKey, noderole.RoleSigner, "/rekey_policy", "not accepted in a signer document"},
		{"signer reject_rekey", signer(`"reject_rekey":true`), DefaultKey, noderole.RoleSigner, "/reject_rekey", "not accepted in a signer document"},
		{"signer missing on_no_route", []byte(strings.Replace(string(signer("")), `"on_no_route": "reject",`, "", 1)), DefaultKey, noderole.RoleSigner, "/transfer_policy", `missing required field "on_no_route"`},
		{"transfer_policy enabled", signer(`"transfer_policy":{"enabled":true}`), DefaultKey, noderole.RoleSigner, "/transfer_policy/enabled", "unknown field"},
		{"key overrides", signer(fmt.Sprintf(`"key_overrides":{%q:{}}`, v1Ops.String())), DefaultKey, noderole.RoleSigner, "/key_overrides", "unknown field"},
		{"unknown nested field", signer(tp(fmt.Sprintf(route, `,"enabled":true`))), DefaultKey, noderole.RoleSigner, "/transfer_policy/routes/0/enabled", "unknown field"},
		{"bad route id", signer(tp(routeWith(`"id":"r"`, `"id":"Bad"`, ""))), DefaultKey, noderole.RoleSigner, "/transfer_policy/routes/0/id", "route id"},
		{"bare asa id", signer(tp(routeWith(`"algo"`, `"31566704"`, ""))), DefaultKey, noderole.RoleSigner, "/transfer_policy/routes/0/assets/0", "asa:<id>"},
		{"unknown set", signer(tp(routeWith(`"sources":["*"]`, `"sources":["@ops"]`, ""))), DefaultKey, noderole.RoleSigner, "/transfer_policy/routes/0/sources/0", `unknown address set "ops"`},
		{"uncovered limit asset", signer(tp(fmt.Sprintf(route, `,"limits":{"testnet":{"asa:7":{"reject_above":"1"}}}`))), DefaultKey, noderole.RoleSigner, "/transfer_policy/routes/0/limits/testnet/asa:7", "does not cover asa:7"},
		{"uncovered limit network", signer(tp(fmt.Sprintf(route, `,"limits":{"mainnet":{"algo":{"reject_above":"1"}}}`))), DefaultKey, noderole.RoleSigner, "/transfer_policy/routes/0/limits/mainnet", "does not cover network"},
		{"review above reject", signer(`"limits":{"testnet":{"algo":{"review_above":"9","reject_above":"1"}}}`), DefaultKey, noderole.RoleSigner, "/limits/testnet/algo", "must not exceed"},
		{"clawback without asset_sources", signer(tp(fmt.Sprintf(route, `,"allow_clawback":true`))), DefaultKey, noderole.RoleSigner, "/transfer_policy/routes/0", "allow_clawback and asset_sources"},
		{"close with wildcard destination", signer(tp(fmt.Sprintf(route, `,"allow_close":true`))), DefaultKey, noderole.RoleSigner, "/transfer_policy/routes/0/destinations/0", "allow_close"},
		{"duplicate route id", signer(tp(fmt.Sprintf(route, "") + "," + fmt.Sprintf(route, ""))), DefaultKey, noderole.RoleSigner, "/transfer_policy/routes/1/id", "duplicate route id"},
		{"duplicate address in set", signer(fmt.Sprintf(`"address_sets":{"ops":[%q,%q]}`, v1Ops.String(), v1Ops.String())), DefaultKey, noderole.RoleSigner, "/address_sets/ops/1", "duplicate address"},
		{"description too long", signer(fmt.Sprintf(`"description":%q`, strings.Repeat("中", maxPolicyDescriptionLength+1))), DefaultKey, noderole.RoleSigner, "/description", "1024 characters"},
		{"invalid on_no_route", signer(`"transfer_policy":{"on_no_route":"allow"}`), DefaultKey, noderole.RoleSigner, "/transfer_policy/on_no_route", "must be one of"},
		{"invalid close_on_no_route", signer(`"transfer_policy":{"close_on_no_route":"allow"}`), DefaultKey, noderole.RoleSigner, "/transfer_policy/close_on_no_route", "must be one of"},
		{"invalid clawback_on_no_route", signer(`"transfer_policy":{"clawback_on_no_route":"allow"}`), DefaultKey, noderole.RoleSigner, "/transfer_policy/clawback_on_no_route", "must be one of"},
		{"route id leading dash", signer(tp(routeWith(`"id":"r"`, `"id":"-bad"`, ""))), DefaultKey, noderole.RoleSigner, "/transfer_policy/routes/0/id", "route id"},
		{"route id punctuation", signer(tp(routeWith(`"id":"r"`, `"id":"bad.route"`, ""))), DefaultKey, noderole.RoleSigner, "/transfer_policy/routes/0/id", "route id"},
		{"route missing networks", signer(tp(routeWith(`"networks":["testnet"],`, "", ""))), DefaultKey, noderole.RoleSigner, "/transfer_policy/routes/0", `missing required field "networks"`},
		{"route missing sources", signer(tp(routeWith(`"sources":["*"],`, "", ""))), DefaultKey, noderole.RoleSigner, "/transfer_policy/routes/0", `missing required field "sources"`},
		{"route missing assets", signer(tp(routeWith(`"assets":["algo"],`, "", ""))), DefaultKey, noderole.RoleSigner, "/transfer_policy/routes/0", `missing required field "assets"`},
		{"route missing destinations", signer(tp(routeWith(`,"destinations":["*"]`, "", ""))), DefaultKey, noderole.RoleSigner, "/transfer_policy/routes/0", `missing required field "destinations"`},
		{"wildcard mixed with concrete network", signer(tp(routeWith(`"networks":["testnet"]`, `"networks":["*","testnet"]`, ""))), DefaultKey, noderole.RoleSigner, "/transfer_policy/routes/0/networks/0", "invalid network id"},
		{"unknown asset set", signer(tp(routeWith(`"assets":["algo"]`, `"assets":["@usd"]`, ""))), DefaultKey, noderole.RoleSigner, "/transfer_policy/routes/0/assets/0", `unknown asset set "usd"`},
		{"self source", signer(tp(routeWith(`"sources":["*"]`, `"sources":["self"]`, ""))), DefaultKey, noderole.RoleSigner, "/transfer_policy/routes/0/sources/0", "invalid Algorand address"},
		{"self asset source", signer(tp(fmt.Sprintf(route, `,"asset_sources":["self"],"allow_clawback":true`))), DefaultKey, noderole.RoleSigner, "/transfer_policy/routes/0/asset_sources/0", "invalid Algorand address"},
		{"asset_sources without allow_clawback", signer(tp(fmt.Sprintf(route, fmt.Sprintf(`,"asset_sources":[%q]`, holder)))), DefaultKey, noderole.RoleSigner, "/transfer_policy/routes/0", "allow_clawback and asset_sources"},
		{"clawback route self destination", signer(tp(routeWith(`"destinations":["*"]`, `"destinations":["self"]`, fmt.Sprintf(`,"asset_sources":[%q],"allow_clawback":true`, holder)))), DefaultKey, noderole.RoleSigner, "/transfer_policy/routes/0/destinations/0", "self is not allowed in a clawback"},
		{"invalid asset term", signer(tp(routeWith(`"assets":["algo"]`, `"assets":["not-an-asset"]`, ""))), DefaultKey, noderole.RoleSigner, "/transfer_policy/routes/0/assets/0", "asa:<id>"},
		{"zero asa id", signer(tp(routeWith(`"assets":["algo"]`, `"assets":["asa:0"]`, ""))), DefaultKey, noderole.RoleSigner, "/transfer_policy/routes/0/assets/0", "asa:<id>"},
		{"wildcard network key in asset set", signer(`"asset_sets":{"bad":{"*":["asa:1"]}}`), DefaultKey, noderole.RoleSigner, "/asset_sets/bad/*", "invalid network id"},
		{"route review above reject", signer(tp(fmt.Sprintf(route, `,"limits":{"testnet":{"algo":{"review_above":"10","reject_above":"9"}}}`))), DefaultKey, noderole.RoleSigner, "/transfer_policy/routes/0/limits/testnet/algo", "must not exceed"},
		{"blocked destination self", signer(`"transfer_policy":{"blocked_destinations":["self"]}`), DefaultKey, noderole.RoleSigner, "/transfer_policy/blocked_destinations/0", "invalid Algorand address"},
		{"blocked destination wildcard", signer(`"transfer_policy":{"blocked_destinations":["*"]}`), DefaultKey, noderole.RoleSigner, "/transfer_policy/blocked_destinations/0", "invalid Algorand address"},
		{"blocked destination set reference", signer(`"transfer_policy":{"blocked_destinations":["@bad"]}`), DefaultKey, noderole.RoleSigner, "/transfer_policy/blocked_destinations/0", "invalid Algorand address"},
		{"duplicate blocked destination", signer(fmt.Sprintf(`"transfer_policy":{"blocked_destinations":[%q,%q]}`, holder, holder)), DefaultKey, noderole.RoleSigner, "/transfer_policy/blocked_destinations/1", "duplicate address"},
		{"cosigner rekey per-network set", cosigner(fmt.Sprintf(`"address_sets":{"ops":{"testnet":[%q]}},"rekey_policy":{"allowed":[{"sender":%q,"targets":["@ops"]}]}`, v1Ops.String(), v1Vendor.String())), testWitnessKeyIDV1, noderole.RoleCosigner, "/rekey_policy/allowed/0/targets/0", "per-network address set"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodePolicyV1(tc.doc, tc.key, tc.role)
			assertDocumentError(t, err, tc.pointer, tc.msg)
		})
	}

	t.Run("document too large", func(t *testing.T) {
		big := signer(fmt.Sprintf(`"description":%q`, strings.Repeat("x", maxPolicyDocumentBytes)))
		_, err := DecodePolicyV1(big, DefaultKey, noderole.RoleSigner)
		assertDocumentError(t, err, "", "larger than")
	})
	t.Run("description limit counts characters", func(t *testing.T) {
		doc := signer(fmt.Sprintf(`"description":%q`, strings.Repeat("中", maxPolicyDescriptionLength)))
		if _, err := DecodePolicyV1(doc, DefaultKey, noderole.RoleSigner); err != nil {
			t.Fatalf("DecodePolicyV1() error = %v", err)
		}
	})
	t.Run("unsupported node role", func(t *testing.T) {
		if _, err := DecodePolicyV1(signer(""), DefaultKey, "auditor"); err == nil {
			t.Fatal("DecodePolicyV1 accepted an unsupported role")
		}
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

func TestEmbeddedDefaultsDecodeAndCompile(t *testing.T) {
	for _, role := range []noderole.Role{noderole.RoleSigner, noderole.RoleCosigner} {
		data, err := EmbeddedDefault(role)
		if err != nil {
			t.Fatal(err)
		}
		doc, err := DecodePolicyV1(data, DefaultKey, role)
		if err != nil {
			t.Fatalf("%s default: %v", role, err)
		}
		cfg, err := doc.Compile(DefaultConfig())
		if err != nil {
			t.Fatalf("%s default compile: %v", role, err)
		}
		if cfg.Role != role || !doc.IsDefault() {
			t.Fatalf("%s default compiled role %q", role, cfg.Role)
		}
		if role == noderole.RoleSigner {
			if cfg.VerdictForType(types.ApplicationCallTx) != TransactionTypeAllow || !cfg.RejectForeignRekey || !cfg.AlwaysReviewWarnings {
				t.Fatalf("signer default = %+v", cfg)
			}
			if cfg.TransferPolicy.OnNoRoute != TransferOnNoRouteOperatorDefault || len(cfg.TransferPolicy.Routes) != 1 || cfg.TransferPolicy.Routes[0].ID != SelfTransferRouteID {
				t.Fatalf("signer default routing = %+v", cfg.TransferPolicy)
			}
		} else {
			if cfg.VerdictForType(types.PaymentTx) != TransactionTypeReject || !cfg.RejectRekey || len(cfg.TransferPolicy.Routes) != 0 {
				t.Fatalf("cosigner default = %+v", cfg)
			}
		}
	}
	if _, err := EmbeddedDefault("auditor"); err == nil {
		t.Fatal("EmbeddedDefault accepted an unsupported role")
	}
}

func TestTransactionTypesVerdictResolution(t *testing.T) {
	var none TransactionTypesV1
	if got := none.Verdict("pay"); got != TransactionTypeReject {
		t.Fatalf("nil map verdict = %q, want reject", got)
	}
	m := TransactionTypesV1{"*": TransactionTypeReview, "pay": TransactionTypeAllow}
	if m.Verdict("pay") != TransactionTypeAllow || m.Verdict("appl") != TransactionTypeReview {
		t.Fatalf("verdicts = %v", m)
	}
	var nilCfg *Config
	if nilCfg.VerdictForType(types.PaymentTx) != TransactionTypeReject || (&Config{}).VerdictForType(types.PaymentTx) != TransactionTypeReject {
		t.Fatal("a Config without a map must reject")
	}
	cfg := routingConfig(t, `{"transaction_types": {"*": "reject", "pay": "allow", "keyreg": "review"}}`)
	if cfg.VerdictForType(types.PaymentTx) != TransactionTypeAllow || cfg.VerdictForType(types.KeyRegistrationTx) != TransactionTypeReview || cfg.VerdictForType(types.ApplicationCallTx) != TransactionTypeReject {
		t.Fatalf("compiled verdicts = %v", cfg.TransactionTypes)
	}
	clone := cfg.Clone()
	clone.TransactionTypes["pay"] = TransactionTypeReject
	if cfg.VerdictForType(types.PaymentTx) != TransactionTypeAllow {
		t.Fatal("Clone shares the transaction_types map")
	}
}

// A cosigner document may omit "*", whose only legal value there is reject:
// the omitted entry rejects every type the map does not name, with the same
// rule IDs, and the document diffs equal to one that spells the reject out.
func TestCosignerTransactionTypesWildcardOptional(t *testing.T) {
	omitted := mustCosignerDoc(t, testWitnessKeyIDV1, `{"transaction_types":{"pay":"allow","axfer":"allow"}}`)
	explicit := mustCosignerDoc(t, testWitnessKeyIDV1, `{"transaction_types":{"*":"reject","pay":"allow","axfer":"allow"}}`)
	if _, ok := omitted.TransactionTypes[TransactionTypeWildcard]; ok {
		t.Fatal("decoder added a \"*\" entry the document did not have")
	}
	cfg, err := omitted.Compile(DefaultConfig())
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	for txType, want := range map[types.TxType]TransactionTypeVerdict{
		types.PaymentTx:           TransactionTypeAllow,
		types.AssetTransferTx:     TransactionTypeAllow,
		types.KeyRegistrationTx:   TransactionTypeReject,
		types.ApplicationCallTx:   TransactionTypeReject,
		types.AssetConfigTx:       TransactionTypeReject,
		types.TxType("future-tx"): TransactionTypeReject,
	} {
		if got := cfg.VerdictForType(txType); got != want {
			t.Errorf("%s verdict = %q, want %q", txType, got, want)
		}
	}
	if changes := DiffPolicyV1(explicit, omitted); len(changes) != 0 {
		t.Fatalf("omitting \"*\" diffs as %v, want no change", changes)
	}
	if _, err := DecodePolicyV1(signerJSON(t, DefaultKey, `{"transaction_types":{"pay":"allow"}}`), DefaultKey, noderole.RoleSigner); err == nil {
		t.Fatal("a signer document without \"*\" decoded")
	}
}

// TestSignerPolicyV1Verdicts pins the verdicts of a signer policy covering
// document limits, routes, sets, blocked destinations, close and clawback
// rules, and the type gate, for every transaction in the matrix.
func TestSignerPolicyV1Verdicts(t *testing.T) {
	sparse := fmt.Sprintf(`{
  "reject_clawback": true,
  "max_fee_microalgos": "5000",
  "transaction_types": {"*": "reject", "pay": "allow", "axfer": "allow", "keyreg": "review"},
  "limits": {"testnet": {"algo": {"review_above": "100000000", "reject_above": "1000000000"}, "asa:777": {"reject_above": "500"}}},
  "address_sets": {"ops": [%[2]q]},
  "asset_sets": {"usd": {"testnet": ["asa:777"]}},
  "transfer_policy": {
    "on_no_route": "review", "close_on_no_route": "reject", "blocked_destinations": [%[1]q],
    "routes": [
      {"id": "ops-algo", "networks": ["testnet"], "sources": ["@ops"], "assets": ["algo"], "destinations": ["*"], "limits": {"testnet": {"algo": {"reject_above": "50000000"}}}},
      {"id": "ops-usd", "networks": ["testnet"], "sources": ["@ops"], "assets": ["@usd"], "destinations": [%[3]q], "limits": {"testnet": {"asa:777": {"review_above": "100"}}}},
      {"id": "ops-close", "networks": ["testnet"], "sources": ["@ops"], "assets": ["algo"], "destinations": [%[3]q], "allow_close": true}
    ]
  }
}`, v1Bad.String(), v1Ops.String(), v1Vendor.String())
	cfg, err := mustSignerDoc(t, v1Ops.String(), sparse).Compile(DefaultConfig())
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	want := map[string]string{
		"small algo payment":             "",
		"algo over route reject":         "transfer_policy:ops-algo:reject_above",
		"algo over document review":      "review_algo_payment_exceeded,transfer_policy:ops-algo:reject_above",
		"algo over document reject":      "max_algo_payment_exceeded,review_algo_payment_exceeded,transfer_policy:ops-algo:reject_above",
		"algo to blocked destination":    "transfer_policy:blocked_destination",
		"algo from unrouted sender":      "transfer_policy:route_miss",
		"algo on unknown network":        "review_unknown_genesis_hash,transfer_policy:unknown_genesis_hash,unknown_genesis_hash",
		"usd within limits":              "",
		"usd over route review":          "transfer_policy:ops-usd:review_above",
		"usd over route cosigner reject": "transfer_policy:ops-usd:review_above",
		"usd over document reject":       "max_asa_amount_exceeded,transfer_policy:ops-usd:review_above",
		"usd to unrouted destination":    "transfer_policy:route_miss",
		"unrouted asset":                 "transfer_policy:route_miss",
		"close to routed destination":    "",
		"close to unrouted destination":  "transfer_policy:ops-algo:close_rejected",
		"clawback":                       "reject_clawback,transfer_policy:clawback_rejected",
		"fee under cap":                  "",
		"fee over cap":                   "max_fee_exceeded",
		"key registration":               "transaction_type:keyreg",
		"application call":               "transaction_type:appl",
	}
	for _, tc := range v1VerdictTransactions(t) {
		if got := policyVerdicts(tc.txn, cfg); got != want[tc.name] {
			t.Errorf("%s: verdicts %q, want %q", tc.name, got, want[tc.name])
		}
	}
}

// TestCosignerPolicyV1Verdicts does the same for one cosigner key's policy.
func TestCosignerPolicyV1Verdicts(t *testing.T) {
	sparse := fmt.Sprintf(`{
  "reject_close_remainder": true,
  "max_fee_microalgos": "5000",
  "limits": {"testnet": {"asa:777": {"reject_above": "500"}}},
  "address_sets": {"ops": [%[2]q]},
  "transfer_policy": {"blocked_destinations": [%[1]q], "routes": [
    {"id": "ops-usd", "networks": ["testnet"], "sources": ["@ops"], "assets": ["asa:777"], "destinations": [%[3]q], "limits": {"testnet": {"asa:777": {"reject_above": "300"}}}},
    {"id": "ops-algo", "networks": ["*"], "sources": ["@ops"], "assets": ["algo"], "destinations": ["*"]}
  ]},
  "rekey_policy": {"allowed": [{"sender": "@ops", "targets": [%[3]q]}]}
}`, v1Bad.String(), v1Ops.String(), v1Vendor.String())
	cfg, err := mustCosignerDoc(t, testWitnessKeyIDV1, sparse).Compile(DefaultConfig())
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	if cfg.RejectForeignRekey || cfg.AlwaysReviewWarnings || cfg.AutoApproveSelfNoOpTransfer || cfg.TransferPolicy.OnNoRoute != TransferOnNoRouteReject {
		t.Fatalf("cosigner compile carried signer-only settings: %+v", cfg)
	}
	want := map[string]string{
		"small algo payment":             "",
		"algo over route reject":         "",
		"algo over document review":      "",
		"algo over document reject":      "",
		"algo to blocked destination":    "transfer_policy:blocked_destination",
		"algo from unrouted sender":      "transfer_policy:route_miss",
		"algo on unknown network":        "transfer_policy:unknown_genesis_hash",
		"usd within limits":              "",
		"usd over route review":          "",
		"usd over route cosigner reject": "transfer_policy:ops-usd:reject_above",
		"usd over document reject":       "max_asa_amount_exceeded,transfer_policy:ops-usd:reject_above",
		"usd to unrouted destination":    "transfer_policy:route_miss",
		"unrouted asset":                 "transfer_policy:route_miss",
		"close to routed destination":    "reject_close_remainder,transfer_policy:ops-algo:close_rejected",
		"close to unrouted destination":  "reject_close_remainder,transfer_policy:ops-algo:close_rejected",
		"clawback":                       "transfer_policy:clawback_rejected",
		"fee under cap":                  "",
		"fee over cap":                   "max_fee_exceeded",
		"key registration":               "transaction_type:keyreg",
		"application call":               "transaction_type:appl",
	}
	for _, tc := range v1VerdictTransactions(t) {
		if got := policyVerdicts(tc.txn, cfg); got != want[tc.name] {
			t.Errorf("%s: verdicts %q, want %q", tc.name, got, want[tc.name])
		}
	}
	if !cfg.RekeyPolicy.Allows(v1Ops, v1Vendor) || cfg.RekeyPolicy.Allows(v1Ops, v1Other) {
		t.Fatal("rekey_policy did not compile to the listed edge only")
	}
}

func TestPolicyV1RouteLimitsArePerAsset(t *testing.T) {
	cfg := routingConfig(t, fmt.Sprintf(`{
  "asset_sets": {"mix": {"testnet": ["algo", "asa:777"]}},
  "transfer_policy": {"routes": [
    {"id": "mixed", "networks": ["testnet"], "sources": ["*"], "assets": ["@mix"], "destinations": [%q],
     "limits": {"testnet": {"algo": {"reject_above": "100"}, "asa:777": {"reject_above": "5"}}}}
  ]}
}`, v1Vendor.String()))
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
	feeUnder := v1Payment(testnet, v1Ops, v1Vendor, 1)
	feeUnder.Fee = 3000
	feeOver := v1Payment(testnet, v1Ops, v1Vendor, 1)
	feeOver.Fee = 6000
	keyreg := types.Transaction{Type: types.KeyRegistrationTx, Header: types.Header{Sender: v1Ops, Fee: 1000, GenesisHash: testnet}}
	appl := types.Transaction{Type: types.ApplicationCallTx, Header: types.Header{Sender: v1Ops, Fee: 1000, GenesisHash: testnet}}
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
		{"fee under cap", feeUnder},
		{"fee over cap", feeOver},
		{"key registration", keyreg},
		{"application call", appl},
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
	cfg := routingConfig(t, `{"limits": {"testnet": {"algo": {"review_above": "0", "reject_above": "0"}, "asa:777": {"reject_above": "0"}}},
  "transfer_policy": {"on_no_route": "operator_default"}}`)
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
