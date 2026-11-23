// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/sourcetokens"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// signPaymentForTest asks /sign, as an enrolled client, for a payment from
// address, and returns the status the signer answered.
func signPaymentForTest(t *testing.T, server *Signer, address string) int {
	t.Helper()
	sp := types.SuggestedParams{
		Fee:             types.MicroAlgos(1000),
		GenesisHash:     testnetGenesisHashBytes(t),
		GenesisID:       "testnet-v1.0",
		FirstRoundValid: 100,
		LastRoundValid:  200,
	}
	txn, err := transaction.MakePaymentTxn(address, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ", 12345, nil, "", sp)
	if err != nil {
		t.Fatal(err)
	}
	reqJSON, err := json.Marshal(signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{{AuthAddress: address, TxnBytesHex: txnutil.EncodeWithPrefixHex(txn)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := enrollTestClient(t, server, "second-unlock-client")
	r := httptest.NewRequest(http.MethodPost, "/sign", bytes.NewReader(reqJSON))
	r = r.WithContext(auth.ContextWithConnIdentity(r.Context(), auth.ConnIdentity{KeyFingerprint: fingerprint}))
	w := httptest.NewRecorder()
	server.requireAuth(auth.ActionSignRequest, auth.Resource{Type: "transaction"}, server.handleSign)(w, r)
	return w.Code
}

// An unlock request on a signer already unlocked once ran a full reload under
// the session in service. The reload replaced the keyring, and one that then
// failed, here its policy verification after the keyring had opened, closed
// it again: the request answered a failed unlock and nothing locked or
// entered recovery, so the signer said unlocked and could not sign. The
// request now checks the passphrase and answers from the session, which keeps
// its keyring, its keys and its policy, and goes on signing.
func TestASecondUnlockKeepsTheSessionInService(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ir := server.productRuntime()
	server.config.UserAutoApprove = true
	ir.Config().SetUserAutoApprove(true)
	address := generateTestKey(t, server, "ed25519")
	if code := signPaymentForTest(t, server, address); code != http.StatusOK {
		t.Fatalf("/sign before the second unlock = %d, want 200", code)
	}
	generation, unlocked := ir.UnlockedGeneration()
	if !unlocked {
		t.Fatal("the signer is not unlocked")
	}
	keys, revision, nodePolicy := ir.KeyCount(), ir.KeysetRevision(), ir.NodePolicy()

	// A load from here fails after it has opened the keyring: the networks
	// the configuration names no longer pass policy verification.
	server.config.GenesisHashNetworks = map[string]string{"not-a-genesis-hash": "lab"}
	success, keyCount, errMsg, code := server.adminServices().UnlockIdentity(testPassphrase)
	server.config.GenesisHashNetworks = nil

	if !success || errMsg != "" || code != "" || keyCount != keys {
		t.Fatalf("second UnlockIdentity() = (%v, %d, %q, %q), want a success with the session's %d key(s)", success, keyCount, errMsg, code, keys)
	}
	if !ir.IsUnlockedIn(generation) {
		t.Fatalf("the second unlock ended the session in service; state %v", ir.GetState())
	}
	if err := ir.WithKeyring(func(*crypto.Keyring) error { return nil }); err != nil {
		t.Fatalf("the session's keyring is closed: %v", err)
	}
	if ir.KeyCount() != keys || ir.KeysetRevision() != revision || ir.NodePolicy() != nodePolicy {
		t.Fatal("the second unlock republished the key maps or the policy")
	}
	if code := signPaymentForTest(t, server, address); code != http.StatusOK {
		t.Fatalf("/sign after the second unlock = %d, want 200", code)
	}
}

// requireTokenFilesHold checks the source token files of selector: the token
// they hold for the "screening" source, "" for none.
func requireTokenFilesHold(t *testing.T, server *Signer, selector, want string) {
	t.Helper()
	ir := server.productRuntime()
	active, err := ir.ActivePaths()
	if err != nil {
		t.Fatal(err)
	}
	var onDisk *sourcetokens.Index
	if err := ir.WithKeyring(func(kr *crypto.Keyring) error {
		var loadErr error
		onDisk, loadErr = sourcetokens.LoadIndex(active, ir.NodeRole(), kr)
		return loadErr
	}); err != nil {
		t.Fatal(err)
	}
	got, ok := onDisk.TokenFor(selector, "screening")
	if (want == "") == ok || got != want {
		t.Fatalf("the token files of %s hold %q, %v; want %q", selector, got, ok, want)
	}
}

// A source token set or remove beside a second unlock once lost to the
// unlock's reload: the reload read the token files, the change on another
// connection wrote the file and published its index, and the reload then
// published the index it had read. A removed token stayed in memory and went
// on being sent; a token just set was missing. The token directory is not
// watched, so nothing corrected it. A second unlock now loads nothing, and
// the index the change published is the one that stands, matching the files.
//
// The real reload reads the token files and publishes them a few lines apart,
// with nothing a test can stop between. The reload here does what it did
// around the change: it reads the files when it starts, the change lands, and
// it publishes what it read when it ends.
func TestATokenChangeBesideASecondUnlockStands(t *testing.T) {
	for _, tc := range []struct {
		name          string
		before, after string // the token before and after the change
	}{
		{name: "remove", before: "tok-removed-77b1", after: ""},
		{name: "set", before: "", after: "tok-set-2e90"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, cleanup := setupTestNode(t, noderole.RoleCosigner, cosignerDefaultWithSources(t))
			defer cleanup()
			ir := server.productRuntime()
			key := generateTestKey(t, server, witness.Falcon1024V1)
			if tc.before != "" {
				setTokenForBackupTest(t, server, policy.DefaultKey, tc.before)
			}
			change := func() {
				var result adminproto.SourceTokenChangeResult
				if tc.after == "" {
					result = server.adminServices().keyApp().RemoveSourceToken(adminproto.RemoveSourceTokenRequest{
						Selector: policy.DefaultKey, Source: "screening",
					})
				} else {
					result = server.adminServices().keyApp().SetSourceToken(adminproto.SetSourceTokenRequest{
						Selector: policy.DefaultKey, Source: "screening", Token: []byte(tc.after),
					})
				}
				if !result.Success {
					t.Fatalf("source token %s = %+v", tc.name, result)
				}
			}

			_, loads := countBuilds(server)
			if success, _, errMsg, _ := server.adminServices().UnlockIdentity(testPassphrase); !success {
				t.Fatalf("second UnlockIdentity() failed: %s", errMsg)
			}
			if loads.Load() != 0 {
				t.Fatalf("the second unlock loaded %d time(s), want none", loads.Load())
			}
			// The unlock loaded nothing, so the change lands after it.
			change()
			requireTokenFilesHold(t, server, policy.DefaultKey, tc.after)
			requireServedToken(t, server, policy.DefaultKey, tc.after)
			if _, err := ir.FindKeyFile(key); err != nil {
				t.Fatalf("the cosigner key is gone from the key maps: %v", err)
			}
		})
	}
}
