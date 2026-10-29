// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package clientsign

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

var (
	hotAccount = types.Address{6}
	hotSigner  = types.Address{7}
)

// hotPayment is an ordinary account's transaction to group with the
// rotating spend.
func hotPayment() types.Transaction {
	return types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender: hotAccount, Fee: 1000, FirstValid: 1000, LastValid: 1100,
			GenesisID: "testnet-v1.0", GenesisHash: types.Digest{9},
		},
		PaymentTxnFields: types.PaymentTxnFields{Receiver: rotatingAccount, Amount: 50},
	}
}

// ownedGroup is the hot payment followed by the rotating spend, so the
// rotating transaction sits at a nonzero index.
func ownedGroup() []types.Transaction {
	return []types.Transaction{hotPayment(), rotatingOriginal()}
}

func TestValidatePreparedRotatingGroupAcceptsOwnedSlots(t *testing.T) {
	original := ownedGroup()
	txns, err := ValidatePreparedRotatingGroup(original, 1, preparedGroupFor(t, original, 1, rotatingTarget, nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(txns) != 3 || txns[1].RekeyTo != rotatingTarget || !txns[0].RekeyTo.IsZero() {
		t.Fatalf("validated group: %d txns, rotating rekey %s, owned rekey %s", len(txns), txns[1].RekeyTo, txns[0].RekeyTo)
	}
	// Under the ordinary allocator any slot may pay the dummy deficit: an
	// owned slot whose raised fee is reported is honest.
	crossSubsidy := preparedGroupFor(t, original, 1, rotatingTarget, func(tx []types.Transaction) {
		tx[0].Fee = 2500
	})
	crossSubsidy.Mutations.FeesModified = []int{1, 0}
	crossSubsidy.Mutations.TotalFeesDelta += 1500
	if _, err := ValidatePreparedRotatingGroup(original, 1, crossSubsidy); err != nil {
		t.Fatalf("reported fee raise on an owned slot refused: %v", err)
	}
}

func TestValidatePreparedRotatingGroupRejectsOwnedTampering(t *testing.T) {
	original := ownedGroup()
	tests := []struct {
		name string
		resp func() *signerapi.RotatingPrepareResponse
		want string
	}{
		{name: "owned receiver changed", resp: func() *signerapi.RotatingPrepareResponse {
			return preparedGroupFor(t, original, 1, rotatingTarget, func(tx []types.Transaction) { tx[0].Receiver = types.Address{8} })
		}, want: "other than fee and group on transaction 1"},
		{name: "owned slot rekeyed", resp: func() *signerapi.RotatingPrepareResponse {
			return preparedGroupFor(t, original, 1, rotatingTarget, func(tx []types.Transaction) { tx[0].RekeyTo = types.Address{8} })
		}, want: "other than fee and group on transaction 1"},
		{name: "owned fee raised without a report", resp: func() *signerapi.RotatingPrepareResponse {
			return preparedGroupFor(t, original, 1, rotatingTarget, func(tx []types.Transaction) { tx[0].Fee = 2000 })
		}, want: "without reporting"},
		{name: "slots reordered", resp: func() *signerapi.RotatingPrepareResponse {
			return preparedGroupFor(t, original, 1, rotatingTarget, func(tx []types.Transaction) { tx[0], tx[1] = tx[1], tx[0] })
		}, want: "transaction 1"},
		{name: "owned indexes misreported", resp: func() *signerapi.RotatingPrepareResponse {
			r := preparedGroupFor(t, original, 1, rotatingTarget, nil)
			r.OwnedIndexes = []int{}
			return r
		}, want: "owned_indexes"},
		{name: "rotation at the wrong index", resp: func() *signerapi.RotatingPrepareResponse {
			r := preparedGroupFor(t, original, 1, rotatingTarget, nil)
			r.Rotations[0].Index = 0
			return r
		}, want: "is at transaction 1"},
		{name: "owned slot dropped", resp: func() *signerapi.RotatingPrepareResponse {
			r := preparedGroupFor(t, original[1:], 0, rotatingTarget, nil)
			r.OwnedIndexes = []int{0}
			r.Rotations[0].Index = 1
			return r
		}, want: "original_count"},
		{name: "foreign slot reported", resp: func() *signerapi.RotatingPrepareResponse {
			r := preparedGroupFor(t, original, 1, rotatingTarget, nil)
			r.Mutations.ForeignCount = 1
			return r
		}, want: "passthrough or foreign"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidatePreparedRotatingGroup(original, 1, tt.resp())
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestRotatingSlotRequestsCarryOrdinaryAuthorization(t *testing.T) {
	authCache := cache.NewAuthAddressCache()
	authCache.AuthAddresses[hotAccount.String()] = hotSigner.String()
	opts := SubmitOptions{
		LsigArgsMap: []map[string][]byte{{"secret": {0xab}}, nil},
		AppCallInfo: []*signerapi.AppCallInfo{{Method: "pay"}, {Method: "withdraw(uint64)"}},
	}
	slots := rotatingSlotRequests(ownedGroup(), 1, &authCache, opts)
	owned, rotating := slots[0], slots[1]
	if owned.AuthAddress != hotSigner.String() {
		t.Fatalf("owned slot signs with %s, want its effective signer %s", owned.AuthAddress, hotSigner)
	}
	if owned.LsigArgs["secret"] != "ab" || owned.AppCallInfo == nil || owned.AppCallInfo.Method != "pay" {
		t.Fatalf("owned slot lost its LogicSig arguments or app-call info: %+v", owned)
	}
	if rotating.AuthAddress != "" || rotating.LsigArgs != nil || rotating.TxnSender != rotatingAccount.String() {
		t.Fatalf("rotating slot carries authorization context: %+v", rotating)
	}
	if rotating.AppCallInfo == nil || rotating.AppCallInfo.Method != "withdraw(uint64)" {
		t.Fatalf("rotating slot lost its app-call info for the approval prompt: %+v", rotating.AppCallInfo)
	}
	// Without an auth cache every owned slot signs with its sender.
	if got := rotatingSlotRequests(ownedGroup(), 1, nil, SubmitOptions{})[0].AuthAddress; got != hotAccount.String() {
		t.Fatalf("owned slot without an auth cache signs with %s", got)
	}
}

// TestSignAndSubmitRotatingGroupAlignsWindows sends a group whose owned
// transaction has a longer window than the rotating spend accepts. The
// client must cap the rotating window, align the owned one to it, send the
// group form with the owned slot's effective signer, and simulate the whole
// prepared group.
func TestSignAndSubmitRotatingGroupAlignsWindows(t *testing.T) {
	const round = 1000
	var seen signerapi.RotatingPrepareRequest
	signerClient := signerclient.NewSignerClient("http://signer.test")
	signerClient.Client = &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/sign/rotating/prepare" {
			return jsonResponse(r, http.StatusNotFound, map[string]string{"error": "not found"})
		}
		if err := json.NewDecoder(r.Body).Decode(&seen); err != nil {
			t.Errorf("decode prepare request: %v", err)
		}
		sent := make([]types.Transaction, len(seen.Requests))
		for i, slot := range seen.Requests {
			txn, err := txnutil.DecodePrefixedHex(slot.TxnBytesHex)
			if err != nil {
				t.Errorf("decode slot %d: %v", i, err)
			}
			sent[i] = txn
		}
		return jsonResponse(r, http.StatusOK, preparedGroupFor(t, sent, 1, rotatingTarget, nil))
	})}
	var simulated []types.Transaction
	algodClient := fakeAlgod(t, round, &simulated)

	group := ownedGroup()
	group[0].LastValid = group[0].FirstValid + 1000
	group[1].LastValid = group[1].FirstValid + 1000
	authCache := cache.NewAuthAddressCache()
	authCache.AuthAddresses[hotAccount.String()] = hotSigner.String()
	txIDs, prepared, err := SignAndSubmitRotating(group, 1, &authCache, signerClient, algodClient, RotatingOptions{SubmitOptions: SubmitOptions{Simulate: true}})
	if err != nil {
		t.Fatal(err)
	}
	if seen.TxnBytesHex != "" || len(seen.Requests) != 2 {
		t.Fatalf("client sent %d slots (single form %q); want the group form with 2", len(seen.Requests), seen.TxnBytesHex)
	}
	if seen.Requests[0].AuthAddress != hotSigner.String() || seen.Requests[1].AuthAddress != "" {
		t.Fatalf("slot authorization: owned %q, rotating %q", seen.Requests[0].AuthAddress, seen.Requests[1].AuthAddress)
	}
	for i := range prepared[:2] {
		if prepared[i].FirstValid != 1000 || prepared[i].LastValid != 1100 {
			t.Fatalf("transaction %d validity %d-%d, want the capped rotating window 1000-1100", i+1, prepared[i].FirstValid, prepared[i].LastValid)
		}
	}
	if group[0].LastValid != 2000 {
		t.Fatal("the caller's transactions were modified")
	}
	if len(txIDs) != 3 || len(simulated) != 3 {
		t.Fatalf("simulated %d txns, ids %d; want the 3-transaction prepared group", len(simulated), len(txIDs))
	}
}

func TestSignAndSubmitRotatingRefusesMisshapenGroups(t *testing.T) {
	signerClient := signerclient.NewSignerClient("http://signer.test")
	var simulated []types.Transaction
	algodClient := fakeAlgod(t, 1000, &simulated)
	rekeyed := ownedGroup()
	rekeyed[0].RekeyTo = types.Address{8}
	grouped := ownedGroup()
	grouped[0].Group = types.Digest{1}
	for name, tc := range map[string]struct {
		txns     []types.Transaction
		rotating int
		want     string
	}{
		"owned rekey":        {rekeyed, 1, "must not set rekey_to"},
		"pre-grouped":        {grouped, 1, "ungrouped"},
		"index out of range": {ownedGroup(), 2, "outside the group"},
		"empty":              {nil, 0, "1 to 16"},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := SignAndSubmitRotating(tc.txns, tc.rotating, nil, signerClient, algodClient, RotatingOptions{})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
	if len(simulated) != 0 {
		t.Fatal("a refused group reached simulation")
	}
}

func TestWithTxnBytesKeepsAuthorization(t *testing.T) {
	slots := []signerapi.SignRequest{{AuthAddress: hotSigner.String(), LsigArgs: map[string]string{"a": "01"}}, {}}
	txns := ownedGroup()
	out := withTxnBytes(slots, txns)
	if out[0].AuthAddress != hotSigner.String() || out[0].LsigArgs["a"] != "01" {
		t.Fatal("authorization context lost")
	}
	if out[1].TxnBytesHex != hex.EncodeToString(txnutil.EncodeWithPrefix(txns[1])) || slots[1].TxnBytesHex != "" {
		t.Fatal("bytes not filled per request, or the template was modified")
	}
}
