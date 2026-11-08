// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/avmsim"
	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/rekeylist"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	falconfamily "github.com/aplane-algo/aplane/lsig/falcon1024/family"
)

// An expert template whose only rekey is to a listed address. It spends ALGO
// and assets under author TEAL that admits everything, so the program's rules
// are the envelope and the rekey path.
const onlyTheseTemplateYAML = `schema_version: 2
derivation_version: 3
template_type: composed
base_key_type: aplane.falcon1024.v1
template_mode: strict
publisher: test
family: only-these
version: 1
display_name: "Only These"
max_opcode_cost: 20000

bounded:
  contract: bounded2
  spend_effects: [pay, axfer, asset_opt_in]
  max_fee: 10000
  rekey: only_these

template_variables: []

teal: |
  pushint 1
  assert
`

var (
	rekeyListSpendingKey  = bytes.Repeat([]byte{0x21}, falconfamily.PublicKeySize)
	rekeyListPrivateKey   = bytes.Repeat([]byte{0x77}, 64)
	rekeyListListedA      = rekeyListAddress(1)
	rekeyListListedB      = rekeyListAddress(2)
	rekeyListUnlisted     = rekeyListAddress(3)
	rekeyListAccount      = rekeyListAddress(9)
	rekeyListEntriesParam = rekeyListListedA.String() + "," + rekeyListListedB.String()
)

func rekeyListAddress(b byte) types.Address {
	var a types.Address
	a[0], a[31] = b, 1
	return a
}

func onlyTheseProvider(t *testing.T) *composeddsa.ComposedDSA {
	t.Helper()
	return authorAllowlistProvider(t, onlyTheseTemplateYAML)
}

func TestOnlyTheseTemplateDeclaresTheListContract(t *testing.T) {
	provider := onlyTheseProvider(t)
	var injected bool
	for _, def := range provider.CreationParams() {
		if def.Name == composeddsa.BoundedRekeyToParameter {
			injected = def.Required && def.Type == "address[]" && def.MaxItems == rekeylist.MaxEntries
		}
		if def.Name == boundedmeta.RekeyListRootParameter {
			t.Fatal("the generator's root is offered as a creation parameter")
		}
	}
	if !injected {
		t.Fatalf("the framework did not inject %s", composeddsa.BoundedRekeyToParameter)
	}
	metadata := provider.BoundedAuthorizationMetadata()
	if metadata == nil || metadata.Rekey != boundedmeta.RekeyRefused || metadata.RekeyList == nil ||
		metadata.RekeyList.Contract != boundedmeta.RekeyListContractV1 || metadata.RekeyList.Depth != rekeylist.Depth || metadata.RekeyList.RootHex != "" {
		t.Fatalf("metadata = %+v, rekey list %+v", metadata, metadata.RekeyList)
	}
	var proofSlot *boundedmeta.ArgumentSlot
	for i, slot := range metadata.ArgumentLayout {
		if slot.Source == boundedmeta.ArgSourceDerived {
			proofSlot = &metadata.ArgumentLayout[i]
		}
	}
	want := boundedmeta.ArgumentPathMask{Spend: boundedmeta.ArgForbidden, SpendingRekey: boundedmeta.ArgForbidden, ListedRekey: boundedmeta.ArgRequired}
	if proofSlot == nil || proofSlot.MaxSize != rekeylist.ProofSize || proofSlot.Paths != want {
		t.Fatalf("list proof slot = %+v", proofSlot)
	}
	if got := metadata.ArgumentBytesForPath(boundedmeta.PathListedRekey); got != 1423+rekeylist.ProofSize {
		t.Fatalf("listed rekey argument bytes = %d", got)
	}
}

// A listed address is a way out, so "only these" doesn't need the transfers a
// bare refused account must keep. It still can't sit beside a cosigner yet.
func TestOnlyTheseRules(t *testing.T) {
	assetsOnly := strings.Replace(onlyTheseTemplateYAML, "spend_effects: [pay, axfer, asset_opt_in]", "spend_effects: [axfer]", 1)
	if _, err := noneComposer(assetsOnly); err != nil {
		t.Fatalf("an assets-only list account was refused: %v", err)
	}
	mismatched := onlyTheseTemplateYAML + "\nparameters:\n  - name: rekey_to\n    type: address[]\n    required: true\n    min_items: 1\n    max_items: 3\n"
	// Like the cosigner key, the injected contract is enforced when the account
	// is generated.
	ownList, err := noneComposer(mismatched)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ownList.GenerateTEAL(rekeyListSpendingKey, map[string]string{
		composeddsa.BoundedRekeyToParameter: rekeyListListedA.String(), boundedmeta.RekeyListRootParameter: strings.Repeat("00", 32),
	}); err == nil || !strings.Contains(err.Error(), "framework-injected contract") {
		t.Fatalf("a template's own rekey_to: error = %v", err)
	}
	cosigned := strings.Replace(onlyTheseTemplateYAML, "  rekey: only_these\n", "  rekey: only_these\n  cosigner:\n    contract: cosigner1\n    required_on: [spend]\n", 1)
	if _, err := noneComposer(cosigned); err == nil || !strings.Contains(err.Error(), "cosigned account is not supported") {
		t.Fatalf("a cosigned list account: error = %v", err)
	}
}

func TestRekeyListRootComesOnlyFromGeneration(t *testing.T) {
	provider := onlyTheseProvider(t)
	request := map[string]string{composeddsa.BoundedRekeyToParameter: rekeyListEntriesParam}
	if err := provider.ValidateCreationParams(request); err != nil {
		t.Fatalf("a request with the list: %v", err)
	}
	withRoot := map[string]string{composeddsa.BoundedRekeyToParameter: rekeyListEntriesParam, boundedmeta.RekeyListRootParameter: strings.Repeat("00", 32)}
	if err := provider.ValidateCreationParams(withRoot); err == nil || !strings.Contains(err.Error(), "unknown parameter") {
		t.Fatalf("a request that sets the root: error = %v", err)
	}
	if _, err := provider.PrepareRekeyList(rekeyListPrivateKey, withRoot); err == nil || !strings.Contains(err.Error(), "set by key generation") {
		t.Fatalf("PrepareRekeyList kept a request's root: %v", err)
	}
	if _, err := provider.GenerateTEAL(rekeyListSpendingKey, request); err == nil || !strings.Contains(err.Error(), "computed at key generation") {
		t.Fatalf("GenerateTEAL rendered without a root: %v", err)
	}
	prepared, err := provider.PrepareRekeyList(rekeyListPrivateKey, request)
	if err != nil {
		t.Fatal(err)
	}
	root, err := composeddsa.RekeyListRootFor(rekeyListPrivateKey, request)
	if err != nil {
		t.Fatal(err)
	}
	if prepared[boundedmeta.RekeyListRootParameter] != hex.EncodeToString(root[:]) {
		t.Fatal("the prepared root is not the list's root")
	}
	otherKey, err := composeddsa.RekeyListRootFor(bytes.Repeat([]byte{0x78}, 64), request)
	if err != nil || otherKey == root {
		t.Fatal("two spending keys give the same root")
	}
	metadata, err := provider.BuildBoundedAuthorizationMetadata(rekeyListSpendingKey, prepared, make([]byte, 3000))
	if err != nil {
		t.Fatal(err)
	}
	if metadata.RekeyList.RootHex != hex.EncodeToString(root[:]) {
		t.Fatalf("stored root %s", metadata.RekeyList.RootHex)
	}
}

// The program, run in the interpreter: a pure rekey reaches a listed address
// with its own proof and nothing else does.
func TestOnlyTheseProgramAdmitsOnlyListedRekeys(t *testing.T) {
	provider := onlyTheseProvider(t)
	request := map[string]string{composeddsa.BoundedRekeyToParameter: rekeyListEntriesParam}
	prepared, err := provider.PrepareRekeyList(rekeyListPrivateKey, request)
	if err != nil {
		t.Fatal(err)
	}
	teal, err := provider.GenerateTEAL(rekeyListSpendingKey, prepared)
	if err != nil {
		t.Fatal(err)
	}
	program, err := avmsim.Assemble(teal)
	if err != nil {
		t.Fatal(err)
	}
	list, err := composeddsa.RekeyListFor(rekeyListPrivateKey, request)
	if err != nil {
		t.Fatal(err)
	}
	defer list.Zero()
	proofA, _ := list.Proof(rekeyListListedA)
	proofB, _ := list.Proof(rekeyListListedB)
	hooks := avmsim.Hooks{Falcon: func(data, sig, key []byte) bool { return bytes.Equal(sig, rekeyListTag(key, data)) }}
	txid := sha256.Sum256([]byte("rekey"))
	rekey := func(target types.Address, amount uint64) avmsim.Txn {
		zero := avmsim.B(make([]byte, 32))
		return avmsim.Txn{
			"TxID": avmsim.B(txid[:]), "Sender": avmsim.B(rekeyListAccount[:]), "Fee": avmsim.U(1000),
			"FirstValid": avmsim.U(1), "LastValid": avmsim.U(100), "TypeEnum": avmsim.U(1),
			"RekeyTo": avmsim.B(bytes.Clone(target[:])), "Receiver": avmsim.B(rekeyListAccount[:]), "Amount": avmsim.U(amount),
			"CloseRemainderTo": zero, "AssetCloseTo": zero, "AssetSender": zero,
			"XferAsset": avmsim.U(0), "AssetAmount": avmsim.U(0), "AssetReceiver": zero,
		}
	}
	signature := rekeyListTag(rekeyListSpendingKey, txid[:])
	for _, test := range []struct {
		name   string
		txn    avmsim.Txn
		proof  []byte
		accept bool
	}{
		{"listed address, its proof", rekey(rekeyListListedA, 0), proofA, true},
		{"second listed address, its proof", rekey(rekeyListListedB, 0), proofB, true},
		{"listed address, the other entry's proof", rekey(rekeyListListedA, 0), proofB, false},
		{"unlisted address", rekey(rekeyListUnlisted, 0), proofA, false},
		{"no proof", rekey(rekeyListListedA, 0), nil, false},
		{"short proof", rekey(rekeyListListedA, 0), proofA[:rekeylist.ProofSize-1], false},
		{"a rekey that also pays", rekey(rekeyListListedA, 1), proofA, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			accepted, err := program.Run(test.txn, [][]byte{signature, test.proof}, hooks)
			if _, unsupported := err.(*avmsim.UnsupportedError); unsupported {
				t.Fatal(err)
			}
			if accepted != test.accept {
				t.Fatalf("accepted = %v (%v), want %v", accepted, err, test.accept)
			}
		})
	}
	root := list.Root()
	if strings.Count(teal, hex.EncodeToString(root[:])) != 1 {
		t.Fatal("the program does not compile the list's root exactly once")
	}
}

func rekeyListTag(key, data []byte) []byte {
	sum := sha256.Sum256(append(append([]byte("rekey-list-test/"), key...), data...))
	return sum[:]
}

// A framework policy with no author TEAL accounts for every parameter it is
// given; the injected rekey_to is the envelope's, not Layer 3's, so it must not
// count as unused.
func TestOnlyTheseWithAFrameworkPolicy(t *testing.T) {
	const yaml = `schema_version: 2
derivation_version: 3
template_type: composed
base_key_type: aplane.falcon1024.v1
template_mode: strict
publisher: test
family: only-these-allowlist
version: 1
display_name: "Only These Allowlist"
max_opcode_cost: 20000

bounded:
  contract: bounded2
  spend_effects: [pay]
  max_fee: 10000
  rekey: only_these
  layer3:
    policy: fixed_allowlist
    recipients_parameter: recipients

parameters:
  - name: recipients
    type: address[]
    required: true
    min_items: 1
    max_items: 30
`
	provider := authorAllowlistProvider(t, yaml)
	if provider.BoundedAuthorizationMetadata() == nil {
		t.Fatal("the framework-policy list account has no metadata")
	}
	request := map[string]string{"recipients": rekeyListListedB.String(), composeddsa.BoundedRekeyToParameter: rekeyListListedA.String()}
	prepared, err := provider.PrepareRekeyList(rekeyListPrivateKey, request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.GenerateTEAL(rekeyListSpendingKey, prepared); err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}
}

// The program commits only to the list's salted root, so no author TEAL may read
// the entries: not a strict variable, which would compile their unsalted Merkle
// root, nor a generated template's substitution or range.
func TestAuthorTEALCannotReadTheRekeyToList(t *testing.T) {
	// A template may declare the injected parameter itself, so it can name it.
	declared := strings.Replace(onlyTheseTemplateYAML, "template_variables: []\n", `parameters:
  - name: rekey_to
    type: address[]
    required: true
    min_items: 1
    max_items: 16
template_variables: []
`, 1)
	strictVariable := strings.Replace(declared, "template_variables: []\n", `template_variables:
  - name: listed
    source: parameter
    parameter: rekey_to
    type: address[]
    constant: byte
`, 1)
	strictVariable = strings.Replace(strictVariable, "  pushint 1\n  assert\n", "  $listed\n  pop\n  pushint 1\n  assert\n", 1)
	generated := strings.Replace(declared, "template_mode: strict", "template_mode: generated", 1)
	generated = strings.Replace(generated, "template_variables: []\n", "", 1)
	substituted := strings.Replace(generated, "  pushint 1\n  assert\n", "  txn Receiver\n  addr @rekey_to\n  ==\n  assert\n", 1)
	ranged := strings.Replace(generated, "  pushint 1\n  assert\n", "  {{range @rekey_to}}\n  txn Receiver\n  addr {{.}}\n  ==\n  assert\n  {{end}}\n", 1)
	params := map[string]string{composeddsa.BoundedRekeyToParameter: rekeyListEntriesParam, boundedmeta.RekeyListRootParameter: strings.Repeat("00", 32)}
	for name, yaml := range map[string]string{"strict variable": strictVariable, "substitution": substituted, "range": ranged} {
		t.Run(name, func(t *testing.T) {
			composer, err := noneComposer(yaml)
			if err == nil {
				var teal string
				teal, err = composer.GenerateTEAL(rekeyListSpendingKey, params)
				if err == nil && (strings.Contains(teal, rekeyListListedA.String()) || strings.Contains(teal, rekeyListListedB.String())) {
					t.Fatal("the program carries a listed address")
				}
			}
			if err == nil || !strings.Contains(err.Error(), "private rekey-to list") {
				t.Fatalf("error = %v, want a refusal naming the private list", err)
			}
		})
	}
}
