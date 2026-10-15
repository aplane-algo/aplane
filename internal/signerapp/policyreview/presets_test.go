// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyreview

import (
	"bytes"
	"encoding/base64"
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/santhosh-tekuri/jsonschema/v6"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/pkg/policyschema"
)

const presetTestKey = "MYJZE3UF7G4JXR5STMQK5TSL5FNE7PE224BSKLZ2H4AJWJIPBEBQ"

var (
	presetSender = types.Address{0x11}
	presetListed = types.Address{0x22}
	presetOther  = types.Address{0x33}
)

// presetCap is the mainnet ALGO cap the tests fill into capped-any.
const presetCap = 50_000_000

// fillPresetPlaceholders replaces every placeholder with a valid value.
func fillPresetPlaceholders(text string) string {
	return strings.NewReplacer(
		`"REPLACE-WITH-DESTINATION-ADDRESS"`, `"`+presetListed.String()+`"`,
		`"REPLACE-WITH-MAX-MICROALGOS"`, `"50000000"`,
	).Replace(text)
}

func decodePreset(t *testing.T, text, key string) (*policy.PolicyV1, error) {
	t.Helper()
	stripped, err := StripComments([]byte(text))
	if err != nil {
		t.Fatalf("StripComments: %v", err)
	}
	return policy.DecodePolicyV1(stripped, key, noderole.RoleCosigner)
}

// Every preset, once its placeholders are filled, decodes for the key it was
// rendered for and for the node default, passes the published JSON Schema,
// and draws no advisory: each carries a fee cap, and no reject_* flag
// contradicts a route.
func TestCosignerPresetsDecodeOnceFilled(t *testing.T) {
	schema := compilePresetSchema(t)
	presets := Presets(noderole.RoleCosigner)
	if len(presets) == 0 {
		t.Fatal("no cosigner presets")
	}
	for _, preset := range presets {
		for _, key := range []string{presetTestKey, policy.DefaultKey} {
			text, err := PresetTemplate(noderole.RoleCosigner, preset.Name, key)
			if err != nil {
				t.Fatalf("%s/%s: %v", preset.Name, key, err)
			}
			if got := strings.Contains(text, PresetPlaceholderPrefix); got != preset.Placeholders {
				t.Errorf("%s: carries placeholders = %v, Placeholders = %v", preset.Name, got, preset.Placeholders)
			}
			doc, err := decodePreset(t, fillPresetPlaceholders(text), key)
			if err != nil {
				t.Fatalf("%s/%s: %v", preset.Name, key, err)
			}
			stripped, err := StripComments([]byte(fillPresetPlaceholders(text)))
			if err != nil {
				t.Fatal(err)
			}
			instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(stripped))
			if err != nil {
				t.Fatal(err)
			}
			if err := schema.Validate(instance); err != nil {
				t.Errorf("%s/%s: schema: %v", preset.Name, key, err)
			}
			if doc.Key != key {
				t.Errorf("%s: key = %q, want %q", preset.Name, doc.Key, key)
			}
			if got := doc.Advisories(); len(got) != 0 {
				t.Errorf("%s: advisories %v", preset.Name, got)
			}
		}
	}
}

// An unfilled preset fails check at the placeholder, so it cannot be
// applied half-edited.
func TestCosignerPresetPlaceholdersFailCheck(t *testing.T) {
	for name, pointer := range map[string]string{
		"listed-destinations": "/address_sets/destinations/0",
		"capped-any":          "/limits/mainnet/algo/reject_above",
	} {
		text, err := PresetTemplate(noderole.RoleCosigner, name, presetTestKey)
		if err != nil {
			t.Fatal(err)
		}
		_, err = decodePreset(t, text, presetTestKey)
		var docErr *policy.DocumentError
		if !errors.As(err, &docErr) || docErr.Pointer != pointer {
			t.Errorf("%s: error %v, want one at %s", name, err, pointer)
		}
	}
}

// Each preset allows what its name says and nothing more. Every preset
// refuses rekeys through reject_rekey, checked on the compiled config.
func TestCosignerPresetVerdicts(t *testing.T) {
	mainnet := presetGenesis(t, apconfig.AlgorandMainnetGenesisHash)
	testnet := presetGenesis(t, apconfig.AlgorandTestnetGenesisHash)
	pay := func(genesis types.Digest, to types.Address, amount uint64) types.Transaction {
		return types.Transaction{Type: types.PaymentTx, Header: types.Header{Sender: presetSender, Fee: 1000, GenesisHash: genesis},
			PaymentTxnFields: types.PaymentTxnFields{Receiver: to, Amount: types.MicroAlgos(amount)}}
	}
	axfer := func(to types.Address) types.Transaction {
		return types.Transaction{Type: types.AssetTransferTx, Header: types.Header{Sender: presetSender, Fee: 1000, GenesisHash: mainnet},
			AssetTransferTxnFields: types.AssetTransferTxnFields{XferAsset: 777, AssetAmount: 1, AssetReceiver: to}}
	}
	closeOut := pay(mainnet, presetListed, 1)
	closeOut.CloseRemainderTo = presetListed
	highFee := pay(mainnet, presetSender, 1)
	highFee.Fee = 20_000
	txns := map[string]types.Transaction{
		"self payment":        pay(mainnet, presetSender, 1),
		"payment to listed":   pay(mainnet, presetListed, 1),
		"payment to other":    pay(mainnet, presetOther, 1),
		"asset to listed":     axfer(presetListed),
		"asset to self":       axfer(presetSender),
		"mainnet at cap":      pay(mainnet, presetOther, presetCap),
		"mainnet over cap":    pay(mainnet, presetOther, presetCap+1),
		"testnet over cap":    pay(testnet, presetOther, presetCap+1),
		"close-out":           closeOut,
		"fee over cap":        highFee,
		"application call":    {Type: types.ApplicationCallTx, Header: types.Header{Sender: presetSender, Fee: 1000, GenesisHash: mainnet}},
		"key registration":    {Type: types.KeyRegistrationTx, Header: types.Header{Sender: presetSender, Fee: 1000, GenesisHash: mainnet}},
		"unknown network pay": pay(types.Digest{0xee}, presetSender, 1),
	}
	// Every preset refuses these, whatever its routes.
	alwaysRefused := []string{"close-out", "fee over cap", "application call", "key registration", "unknown network pay"}
	allowed := map[string][]string{
		"deny-all":            nil,
		"self-only":           {"self payment", "asset to self"},
		"listed-destinations": {"payment to listed", "asset to listed"},
		"capped-any":          {"self payment", "payment to listed", "payment to other", "asset to listed", "asset to self", "mainnet at cap", "testnet over cap"},
		"any-transfer":        {"self payment", "payment to listed", "payment to other", "asset to listed", "asset to self", "mainnet at cap", "mainnet over cap", "testnet over cap"},
	}
	for _, preset := range Presets(noderole.RoleCosigner) {
		want, ok := allowed[preset.Name]
		if !ok {
			t.Fatalf("preset %s has no verdict expectations", preset.Name)
		}
		text, err := PresetTemplate(noderole.RoleCosigner, preset.Name, presetTestKey)
		if err != nil {
			t.Fatal(err)
		}
		doc, err := decodePreset(t, fillPresetPlaceholders(text), presetTestKey)
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := doc.Compile(policy.DefaultConfig())
		if err != nil {
			t.Fatal(err)
		}
		// The cosigner signing path refuses rekeys from this flag before
		// any rule below runs.
		if !cfg.RejectRekey {
			t.Errorf("%s: reject_rekey is false", preset.Name)
		}
		allows := map[string]bool{}
		for _, name := range want {
			allows[name] = true
		}
		names := make([]string, 0, len(txns))
		for name := range txns {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			violations := presetViolations(txns[name], cfg)
			if allows[name] != (violations == "") {
				t.Errorf("%s: %s allowed = %v (violations %q), want %v", preset.Name, name, violations == "", violations, allows[name])
			}
		}
		for _, name := range alwaysRefused {
			if allows[name] {
				t.Errorf("%s: expectations allow %s, which every preset refuses", preset.Name, name)
			}
		}
	}
}

func TestPresetTemplateRejectsUnknownNamesAndRoles(t *testing.T) {
	if _, err := PresetTemplate(noderole.RoleCosigner, "nope", presetTestKey); err == nil || !strings.Contains(err.Error(), "listed-destinations") {
		t.Fatalf("unknown preset error = %v, want the list of presets", err)
	}
	if Presets(noderole.RoleSigner) != nil {
		t.Fatal("signer presets exist")
	}
	if _, err := PresetTemplate(noderole.RoleSigner, "deny-all", policy.DefaultKey); err == nil {
		t.Fatal("rendered a signer preset")
	}
}

// presetViolations is every rule a cosigner applies to txn: the deny and
// routing phases. A cosigner has no review phase.
func presetViolations(txn types.Transaction, cfg *policy.Config) string {
	var ids []string
	for _, phase := range [][]policy.LintViolation{
		policy.CheckTxnPolicyLints(txn, cfg, nil),
		policy.CheckTxnTransferRoutingPolicyLints(txn, cfg, false),
	} {
		for _, v := range phase {
			ids = append(ids, v.RuleID)
		}
	}
	sort.Strings(ids)
	return strings.Join(ids, ",")
}

func presetGenesis(t *testing.T, encoded string) types.Digest {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	var out types.Digest
	copy(out[:], decoded)
	return out
}

func compilePresetSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(policyschema.SchemaV1))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("urn:aplane:policy:v1", doc); err != nil {
		t.Fatal(err)
	}
	schema, err := c.Compile("urn:aplane:policy:v1")
	if err != nil {
		t.Fatal(err)
	}
	return schema
}
