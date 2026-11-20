// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	sdkcrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/appresult"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// useGroupSigner points f's engine at a signer that signs whatever it is
// sent, giving a group its group ID and reporting that it did.
func useGroupSigner(t *testing.T, f *argsFixture) {
	t.Helper()
	signer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sign" {
			http.Error(w, "test signer", http.StatusServiceUnavailable)
			return
		}
		var req signerapi.GroupSignRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode /sign request: %v", err)
		}
		txns := make([]types.Transaction, len(req.Requests))
		for i, request := range req.Requests {
			txn, err := txnutil.DecodePrefixedHex(request.TxnBytesHex)
			if err != nil {
				t.Errorf("decode sign request %d: %v", i, err)
			}
			txns[i] = txn
		}
		var mutations *signerapi.MutationReport
		if len(txns) > 1 {
			gid, err := sdkcrypto.ComputeGroupID(txns)
			if err != nil {
				t.Errorf("compute group ID: %v", err)
			}
			for i := range txns {
				txns[i].Group = gid
			}
			mutations = &signerapi.MutationReport{GroupIDChanged: true, OriginalCount: len(txns), FinalCount: len(txns)}
		}
		signed := make([]string, len(txns))
		for i := range txns {
			signed[i] = hex.EncodeToString(msgpack.Encode(types.SignedTxn{Txn: txns[i], Sig: types.Signature{1}}))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(signerapi.GroupSignResponse{Signed: signed, Mutations: mutations})
	}))
	t.Cleanup(signer.Close)
	f.eng.Connection.SignerClient = signerclient.NewSignerClient(signer.URL)
}

// Both forms of app call submit alike: alone, the call is the one
// transaction; with a companion payment, the payment goes first in a group
// with it. A failure names the form.
func TestAppCallSubmission(t *testing.T) {
	abi := filepath.Join(t.TempDir(), "contract.json")
	if err := os.WriteFile(abi, []byte(`{"name":"t","methods":[{"name":"ping","args":[],"returns":{"type":"void"}}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		structured appresult.AppCall
		confirmed  []string
		output     string
	}
	calls := map[string]func(f *argsFixture, pay uint64) (outcome, error){
		"raw": func(f *argsFixture, pay uint64) (outcome, error) {
			req := AppCallRawRequest{AppID: 1234, From: "nat"}
			req.PayAmount, req.Wait = pay, true
			result, err := f.app.AppCallRaw(context.Background(), req)
			if err != nil {
				return outcome{}, err
			}
			return outcome{result.Structured, result.ConfirmedLines, result.Output}, nil
		},
		"method": func(f *argsFixture, pay uint64) (outcome, error) {
			req := AppCallMethodRequest{AppID: 1234, Method: "ping", ABIPath: abi, From: "nat"}
			req.PayAmount, req.Wait = pay, true
			result, err := f.app.AppCallMethod(context.Background(), req)
			if err != nil {
				return outcome{}, err
			}
			return outcome{result.Structured, result.ConfirmedLines, result.Output}, nil
		},
	}
	tests := []struct {
		form, name string
		pay        uint64
		grouped    bool
		confirmed  string
		failure    string
	}{
		{form: "raw", name: "alone", confirmed: "Confirmed raw app call to app 1234", failure: "raw app call failed: "},
		{form: "raw", name: "with payment", pay: 1000, grouped: true, confirmed: "Confirmed grouped raw app call on app 1234", failure: "grouped raw app call failed: "},
		{form: "method", name: "alone", confirmed: "Confirmed app call ping()void on app 1234", failure: "app call failed: "},
		{form: "method", name: "with payment", pay: 1000, grouped: true, confirmed: "Confirmed grouped app call ping()void on app 1234", failure: "grouped app call failed: "},
	}
	for _, tt := range tests {
		t.Run(tt.form+" "+tt.name, func(t *testing.T) {
			f := newArgsFixture(t)
			f.signsFor = map[string]bool{argsNative: true}
			f.confirms = true
			useGroupSigner(t, f)
			got, err := calls[tt.form](f, tt.pay)
			if err != nil {
				t.Fatalf("app call error = %v", err)
			}
			want := 1
			if tt.grouped {
				want = 2
			}
			s := got.structured
			if s.Grouped != tt.grouped || len(s.TxIDs) != want || !s.Confirmed || s.AppID != 1234 {
				t.Fatalf("structured = %+v, want grouped=%v with %d transaction(s), confirmed", s, tt.grouped, want)
			}
			if tt.grouped && s.TxID != "" || !tt.grouped && s.TxID != s.TxIDs[0] {
				t.Fatalf("TxID = %q with TxIDs %v", s.TxID, s.TxIDs)
			}
			if !reflect.DeepEqual(got.confirmed, []string{tt.confirmed}) {
				t.Fatalf("confirmed lines = %q, want %q", got.confirmed, tt.confirmed)
			}
			for _, txID := range s.TxIDs {
				if !strings.Contains(got.output, txID) {
					t.Fatalf("output %q does not name %s", got.output, txID)
				}
			}

			refused := newArgsFixture(t)
			if _, err := calls[tt.form](refused, tt.pay); err == nil || !strings.HasPrefix(err.Error(), tt.failure) {
				t.Fatalf("refused app call error = %v, want it to start %q", err, tt.failure)
			}
		})
	}
}
