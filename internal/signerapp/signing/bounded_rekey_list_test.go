// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/rekeylist"
	"github.com/aplane-algo/aplane/internal/signerapp/approvalpolicy"
	coresigning "github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

var (
	listTestPrivateKey = bytes.Repeat([]byte{0x66}, 64)
	listTestTarget     = types.Address{0x51}
	listTestOther      = types.Address{0x52}
)

// listTestAccount is an "only these" account with listTestTarget on its list,
// as the signer's snapshot holds it.
func listTestAccount(t *testing.T) (*boundedmeta.Metadata, map[string]string) {
	t.Helper()
	params := map[string]string{boundedmeta.RekeyListEntriesParameter: listTestTarget.String()}
	list, err := rekeylist.FromSpendingKey(listTestPrivateKey, []types.Address{listTestTarget})
	if err != nil {
		t.Fatal(err)
	}
	root := list.Root()
	list.Zero()
	layout := boundedmeta.SignatureArgLayout{Count: 1, MaxSizes: []int{1280}}
	slots := append(boundedmeta.BaseArgumentLayout(layout), boundedmeta.ArgumentSlot{
		Index: 1, Name: "rekey_list_proof", Source: boundedmeta.ArgSourceDerived, MaxSize: boundedmeta.RekeyListProofSize,
		Paths: boundedmeta.ArgumentPathMask{Spend: boundedmeta.ArgForbidden, SpendingRekey: boundedmeta.ArgForbidden, ListedRekey: boundedmeta.ArgRequired},
	})
	metadata := &boundedmeta.Metadata{
		Contract: boundedmeta.Contract, BaseSignatureArgLayout: layout, ArgumentLayout: slots,
		SpendEffects: []string{"pay"}, MaxFee: 5_000, Rekey: boundedmeta.RekeyRefused, Layer3Policy: boundedmeta.Layer3PolicyCustom,
		RekeyList: &boundedmeta.RekeyList{Contract: boundedmeta.RekeyListContractV1, Depth: rekeylist.Depth, RootHex: hex.EncodeToString(root[:])},
		DerivedArgs: []boundedmeta.DerivedArg{{
			Name: "rekey_list_proof", Kind: boundedmeta.DerivedArgRekeyListProof,
			Parameter: boundedmeta.RekeyListEntriesParameter, MaxSize: boundedmeta.RekeyListProofSize,
		}},
	}
	if err := metadata.Validate(); err != nil {
		t.Fatalf("list metadata invalid: %v", err)
	}
	return metadata, params
}

func listTestRekey(target types.Address) types.Transaction {
	txn := testBoundedRekey()
	txn.RekeyTo = target
	return txn
}

// The planner sends a rekey to a listed target down the listed path, and refuses
// any other rekey with a named error before anything is signed.
func TestPlannerTakesTheListedPathOnlyForAListedTarget(t *testing.T) {
	metadata, params := listTestAccount(t)
	snapshot := PlannerRuntimeSnapshot{KeyMetadata: map[string]PlannerKeyMetadata{
		"ACCOUNT": {PublicKeyHex: "01", BaseKeyType: "aplane.falcon1024.v1", Parameters: params, BoundedAuthorization: metadata},
	}}
	request := []signerapi.SignRequest{{AuthAddress: "ACCOUNT"}}
	items, err := resolveBoundedPlanItems(snapshot, request, []types.Transaction{listTestRekey(listTestTarget)}, nil, nil)
	if err != nil {
		t.Fatalf("listed target: %+v", err)
	}
	if items[0].Path != boundedPathListedRekey || !items[0].ListedRekeyTargets[listTestTarget.String()] {
		t.Fatalf("item = %+v", items[0])
	}
	_, err = resolveBoundedPlanItems(snapshot, request, []types.Transaction{listTestRekey(listTestOther)}, nil, nil)
	if err == nil || err.Kind != ErrorBoundedRekeyNotListed || err.Code() != signerapi.ErrCodeBoundedRekeyTargetNotListed ||
		!strings.Contains(err.Message, "not on this account's rekey-to list") {
		t.Fatalf("unlisted target: error = %+v", err)
	}
	if path, err := logicSigAuthorizationPath(boundedPathListedRekey); err != nil || path != lsigresource.PathListedRekey {
		t.Fatalf("resource path = %v, %v", path, err)
	}
}

// The proof is the one the account's own list gives for the target, and the
// stored root must match the list the signer rebuilds.
func TestListedRekeyDerivesTheListProof(t *testing.T) {
	metadata, params := listTestAccount(t)
	key := &coresigning.KeyMaterial{Value: &coresigning.LsigKeyMaterial{PrivateKey: listTestPrivateKey}, Parameters: params}
	values, err := boundedDerivedArgs(listTestRekey(listTestTarget), key, metadata, boundedPathListedRekey)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := hex.DecodeString(metadata.RekeyList.RootHex)
	var root32 [32]byte
	copy(root32[:], root)
	if len(values) != 1 || !rekeylist.Verify(listTestTarget, values[0], root32) {
		t.Fatalf("derived proof does not verify: %x", values)
	}
	tampered := boundedmeta.Clone(metadata)
	tampered.RekeyList.RootHex = strings.Repeat("00", 32)
	if _, err := boundedDerivedArgs(listTestRekey(listTestTarget), key, tampered, boundedPathListedRekey); err == nil || !strings.Contains(err.Message, "does not match the account's stored root") {
		t.Fatalf("mismatched root: error = %+v", err)
	}
	if values, err := boundedDerivedArgs(testBoundedPayment(), key, metadata, boundedPathPureSpend); err != nil || len(values[0]) != 0 {
		t.Fatalf("a spend carries a list proof: %x, %+v", values, err)
	}
}

// A listed rekey hands the account over, so the warning says so, and says when
// the target leaves this signer's custody.
func TestListedRekeyWarningNamesTheHandover(t *testing.T) {
	listed := map[string]bool{listTestTarget.String(): true}
	unheld := approvalpolicy.CheckDecodedTxnWarningsIn(listTestRekey(listTestTarget), approvalpolicy.Context{ListedRekeyTargets: listed})
	if len(unheld) != 1 || !strings.Contains(unheld[0].Message, "rekey-to list") || !strings.Contains(unheld[0].Message, "LEAVES THIS SIGNER'S CUSTODY") {
		t.Fatalf("unheld listed target warning = %+v", unheld)
	}
	held := approvalpolicy.CheckDecodedTxnWarningsIn(listTestRekey(listTestTarget), approvalpolicy.Context{
		ListedRekeyTargets: listed, KnownAddresses: listed,
	})
	if len(held) != 1 || !strings.Contains(held[0].Message, "You possess the keys") {
		t.Fatalf("held listed target warning = %+v", held)
	}
}
