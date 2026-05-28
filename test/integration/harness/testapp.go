// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package harness

import (
	"context"
	"crypto/ed25519"
	crand "crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/abi"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

const (
	// testAppFixtureDir is the path to the test app fixture relative to project root.
	testAppFixtureDir = "test/fixtures/testapp"

	// testAppABIFile is the ARC-4 ABI JSON filename.
	testAppABIFile = "aplane_test.json"
)

// TestApp represents a deployed test application instance.
type TestApp struct {
	AppID      uint64
	AppAddress string
	ABIPath    string // absolute path to ARC-4 ABI JSON
	Creator    string
	client     *algod.Client
	t          *testing.T
}

// DeployTestApp deploys the test contract and returns a TestApp handle.
// Uses direct SDK signing — deployment is test infrastructure, not the thing being tested.
func DeployTestApp(t *testing.T, client *algod.Client, creatorAddr string, creatorSK ed25519.PrivateKey) (*TestApp, error) {
	t.Helper()

	projectRoot, err := findProjectRoot()
	if err != nil {
		return nil, fmt.Errorf("failed to find project root: %w", err)
	}
	fixtureDir := filepath.Join(projectRoot, testAppFixtureDir)
	abiPath := filepath.Join(fixtureDir, testAppABIFile)

	// Read TEAL source files
	approvalSrc, err := os.ReadFile(filepath.Join(fixtureDir, "approval.teal"))
	if err != nil {
		return nil, fmt.Errorf("failed to read approval.teal: %w", err)
	}
	clearSrc, err := os.ReadFile(filepath.Join(fixtureDir, "clear.teal"))
	if err != nil {
		return nil, fmt.Errorf("failed to read clear.teal: %w", err)
	}

	ctx := context.Background()

	// Compile TEAL via algod
	approvalResult, err := client.TealCompile(approvalSrc).Do(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to compile approval.teal: %w", err)
	}
	approvalBytes, err := base64.StdEncoding.DecodeString(approvalResult.Result)
	if err != nil {
		return nil, fmt.Errorf("failed to decode compiled approval program: %w", err)
	}

	clearResult, err := client.TealCompile(clearSrc).Do(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to compile clear.teal: %w", err)
	}
	clearBytes, err := base64.StdEncoding.DecodeString(clearResult.Result)
	if err != nil {
		return nil, fmt.Errorf("failed to decode compiled clear program: %w", err)
	}

	// Get suggested params
	sp, err := client.SuggestedParams().Do(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get suggested params: %w", err)
	}

	lease, err := randomLease()
	if err != nil {
		return nil, fmt.Errorf("failed to generate lease: %w", err)
	}

	// Build application create transaction
	sender, err := types.DecodeAddress(creatorAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid creator address: %w", err)
	}

	txn, err := transaction.MakeApplicationCallTx(
		0, // appIdx 0 = create
		nil,
		nil,
		nil,
		nil,
		types.NoOpOC,
		approvalBytes,
		clearBytes,
		types.StateSchema{NumUint: 2, NumByteSlice: 2}, // global: counter(uint) + admin(bytes) + headroom
		types.StateSchema{NumUint: 2},                  // local: balance(uint) + headroom
		sp,
		sender,
		nil,             // note
		types.Digest{},  // group
		lease,           // lease
		types.Address{}, // rekeyTo
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create app create transaction: %w", err)
	}

	// Sign and submit
	_, stxnBytes, err := crypto.SignTransaction(creatorSK, txn)
	if err != nil {
		return nil, fmt.Errorf("failed to sign app create transaction: %w", err)
	}

	txid, err := client.SendRawTransaction(stxnBytes).Do(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to submit app create transaction: %w", err)
	}

	// Wait for confirmation
	confirmedTxn, err := transaction.WaitForConfirmation(client, txid, 10, ctx)
	if err != nil {
		return nil, fmt.Errorf("app create transaction not confirmed: %w", err)
	}

	appID := confirmedTxn.ApplicationIndex
	if appID == 0 {
		return nil, fmt.Errorf("app create confirmed but returned appID 0")
	}

	appAddr := crypto.GetApplicationAddress(appID)

	t.Logf("Deployed test app: ID=%d, address=%s", appID, appAddr)

	return &TestApp{
		AppID:      appID,
		AppAddress: appAddr.String(),
		ABIPath:    abiPath,
		Creator:    creatorAddr,
		client:     client,
		t:          t,
	}, nil
}

// FundApp sends ALGO to the app address. Needed for box MBR and deposit tests.
// Amount is in microAlgos.
func (app *TestApp) FundApp(funder *FundTestAccount, amountMicroAlgos uint64) error {
	app.t.Helper()
	return funder.FundMicroAlgosAndWait(app.AppAddress, amountMicroAlgos)
}

// OptIn opts an account into the app via direct SDK signing.
// For use in test fixture setup only — not for testing opt-in through apsigner.
func (app *TestApp) OptIn(addr string, sk ed25519.PrivateKey) error {
	app.t.Helper()

	sp, err := app.client.SuggestedParams().Do(context.Background())
	if err != nil {
		return fmt.Errorf("failed to get suggested params: %w", err)
	}

	lease, err := randomLease()
	if err != nil {
		return fmt.Errorf("failed to generate lease: %w", err)
	}

	sender, err := types.DecodeAddress(addr)
	if err != nil {
		return fmt.Errorf("invalid address: %w", err)
	}

	txn, err := transaction.MakeApplicationCallTx(
		app.AppID,
		nil, nil, nil, nil,
		types.OptInOC,
		nil, nil,
		types.StateSchema{}, types.StateSchema{},
		sp, sender,
		nil, types.Digest{}, lease, types.Address{},
	)
	if err != nil {
		return fmt.Errorf("failed to create opt-in transaction: %w", err)
	}

	_, stxnBytes, err := crypto.SignTransaction(sk, txn)
	if err != nil {
		return fmt.Errorf("failed to sign opt-in transaction: %w", err)
	}

	txid, err := app.client.SendRawTransaction(stxnBytes).Do(context.Background())
	if err != nil {
		return fmt.Errorf("failed to submit opt-in transaction: %w", err)
	}

	_, err = transaction.WaitForConfirmation(app.client, txid, 10, context.Background())
	if err != nil {
		return fmt.Errorf("opt-in transaction not confirmed: %w", err)
	}

	return nil
}

// CallMethod calls an ARC-4 method via direct SDK signing.
// appArgs should include the method selector as the first element.
// For use in test fixture setup only.
func (app *TestApp) CallMethod(appArgs [][]byte, sender string, sk ed25519.PrivateKey, boxes []types.AppBoxReference) error {
	app.t.Helper()

	sp, err := app.client.SuggestedParams().Do(context.Background())
	if err != nil {
		return fmt.Errorf("failed to get suggested params: %w", err)
	}
	sp.FlatFee = true
	sp.Fee = 2000

	lease, err := randomLease()
	if err != nil {
		return fmt.Errorf("failed to generate lease: %w", err)
	}

	senderAddr, err := types.DecodeAddress(sender)
	if err != nil {
		return fmt.Errorf("invalid sender address: %w", err)
	}

	txn, err := transaction.MakeApplicationCallTxWithBoxes(
		app.AppID,
		appArgs,
		nil,   // accounts
		nil,   // foreign apps
		nil,   // foreign assets
		boxes, // box references
		types.NoOpOC,
		nil, nil,
		types.StateSchema{}, types.StateSchema{},
		0, // extra pages
		sp, senderAddr,
		nil, types.Digest{}, lease, types.Address{},
	)
	if err != nil {
		return fmt.Errorf("failed to create app call transaction: %w", err)
	}

	_, stxnBytes, err := crypto.SignTransaction(sk, txn)
	if err != nil {
		return fmt.Errorf("failed to sign app call transaction: %w", err)
	}

	txid, err := app.client.SendRawTransaction(stxnBytes).Do(context.Background())
	if err != nil {
		return fmt.Errorf("failed to submit app call transaction: %w", err)
	}

	_, err = transaction.WaitForConfirmation(app.client, txid, 10, context.Background())
	if err != nil {
		return fmt.Errorf("app call transaction not confirmed: %w", err)
	}

	return nil
}

// ReadGlobalState reads the app's global state directly via algod.
// Returns a map of key → value (uint64 or []byte).
func (app *TestApp) ReadGlobalState() (map[string]interface{}, error) {
	ctx := context.Background()
	appInfo, err := app.client.GetApplicationByID(app.AppID).Do(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get application info: %w", err)
	}

	result := make(map[string]interface{})
	for _, kv := range appInfo.Params.GlobalState {
		keyBytes, err := base64.StdEncoding.DecodeString(kv.Key)
		if err != nil {
			continue
		}
		key := string(keyBytes)
		if kv.Value.Type == 2 {
			result[key] = kv.Value.Uint
		} else {
			valBytes, _ := base64.StdEncoding.DecodeString(kv.Value.Bytes)
			result[key] = valBytes
		}
	}
	return result, nil
}

// ReadLocalState reads an account's local state for this app directly via algod.
func (app *TestApp) ReadLocalState(addr string) (map[string]interface{}, error) {
	ctx := context.Background()
	acctAppInfo, err := app.client.AccountApplicationInformation(addr, app.AppID).Do(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get account app info: %w", err)
	}

	result := make(map[string]interface{})
	for _, kv := range acctAppInfo.AppLocalState.KeyValue {
		keyBytes, err := base64.StdEncoding.DecodeString(kv.Key)
		if err != nil {
			continue
		}
		key := string(keyBytes)
		if kv.Value.Type == 2 {
			result[key] = kv.Value.Uint
		} else {
			valBytes, _ := base64.StdEncoding.DecodeString(kv.Value.Bytes)
			result[key] = valBytes
		}
	}
	return result, nil
}

// ClearState removes an account's local state for the app via direct SDK signing.
// Clear state cannot be rejected by the approval program, so it is safer than
// close-out for test cleanup.
func (app *TestApp) ClearState(addr string, sk ed25519.PrivateKey) error {
	app.t.Helper()

	sp, err := app.client.SuggestedParams().Do(context.Background())
	if err != nil {
		return fmt.Errorf("failed to get suggested params: %w", err)
	}

	lease, err := randomLease()
	if err != nil {
		return fmt.Errorf("failed to generate lease: %w", err)
	}

	sender, err := types.DecodeAddress(addr)
	if err != nil {
		return fmt.Errorf("invalid address: %w", err)
	}

	txn, err := transaction.MakeApplicationClearStateTx(
		app.AppID,
		nil,
		nil,
		nil,
		nil,
		sp,
		sender,
		nil,
		types.Digest{},
		lease,
		types.Address{},
	)
	if err != nil {
		return fmt.Errorf("failed to create clear-state transaction: %w", err)
	}

	_, stxnBytes, err := crypto.SignTransaction(sk, txn)
	if err != nil {
		return fmt.Errorf("failed to sign close-out transaction: %w", err)
	}

	txid, err := app.client.SendRawTransaction(stxnBytes).Do(context.Background())
	if err != nil {
		return fmt.Errorf("failed to submit clear-state transaction: %w", err)
	}

	_, err = transaction.WaitForConfirmation(app.client, txid, 10, context.Background())
	if err != nil {
		return fmt.Errorf("clear-state transaction not confirmed: %w", err)
	}

	return nil
}

// DestroyTestApp clears the creator's local state (if any), deletes all
// boxes via the app's delete_box method, then deletes the application.
func (app *TestApp) DestroyTestApp(creatorSK ed25519.PrivateKey) error {
	app.t.Helper()

	// Best-effort clear-state before delete. Ignore errors — the creator may
	// not be opted in. ClearState cannot be rejected by the approval program.
	_ = app.ClearState(app.Creator, creatorSK)

	// Delete all boxes before the app delete so the AVM doesn't reject
	// with "outstanding boxes". This is a test-only account running one
	// integration test at a time, so all discovered boxes are safe to remove.
	if err := app.deleteAllBoxes(creatorSK); err != nil {
		return fmt.Errorf("failed to delete app boxes before destroy: %w", err)
	}

	boxRefs, err := app.deleteBoxRefs()
	if err != nil {
		return fmt.Errorf("failed to collect app boxes for delete: %w", err)
	}

	sp, err := app.client.SuggestedParams().Do(context.Background())
	if err != nil {
		return fmt.Errorf("failed to get suggested params: %w", err)
	}

	lease, err := randomLease()
	if err != nil {
		return fmt.Errorf("failed to generate lease: %w", err)
	}

	sender, err := types.DecodeAddress(app.Creator)
	if err != nil {
		return fmt.Errorf("invalid creator address: %w", err)
	}
	txn, err := transaction.MakeApplicationCallTxWithBoxes(
		app.AppID,
		nil, // app args
		[]string{app.AppAddress},
		nil, // foreign apps
		nil, // foreign assets
		boxRefs,
		types.DeleteApplicationOC,
		nil, nil,
		types.StateSchema{}, types.StateSchema{},
		0,
		sp, sender,
		nil, types.Digest{}, lease, types.Address{},
	)
	if err != nil {
		return fmt.Errorf("failed to create app delete transaction: %w", err)
	}

	_, stxnBytes, err := crypto.SignTransaction(creatorSK, txn)
	if err != nil {
		return fmt.Errorf("failed to sign app delete transaction: %w", err)
	}

	txid, err := app.client.SendRawTransaction(stxnBytes).Do(context.Background())
	if err != nil {
		return fmt.Errorf("failed to submit app delete transaction: %w", err)
	}

	_, err = transaction.WaitForConfirmation(app.client, txid, 10, context.Background())
	if err != nil {
		return fmt.Errorf("app delete transaction not confirmed: %w", err)
	}

	app.t.Logf("Destroyed test app: ID=%d", app.AppID)
	return nil
}

func (app *TestApp) deleteBoxRefs() ([]types.AppBoxReference, error) {
	app.t.Helper()

	resp, err := app.client.GetApplicationBoxes(app.AppID).Do(context.Background())
	if err != nil {
		return nil, err
	}

	seen := map[string]struct{}{
		"config":   {},
		"settings": {},
	}
	refs := []types.AppBoxReference{
		{AppID: app.AppID, Name: []byte("config")},
		{AppID: app.AppID, Name: []byte("settings")},
	}
	for _, box := range resp.Boxes {
		name := string(box.Name)
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		refs = append(refs, types.AppBoxReference{AppID: app.AppID, Name: box.Name})
	}

	sort.Slice(refs, func(i, j int) bool {
		return string(refs[i].Name) < string(refs[j].Name)
	})
	return refs, nil
}

// deleteAllBoxes calls the app's delete_box(byte[])void method for each
// box discovered via the algod boxes endpoint.
func (app *TestApp) deleteAllBoxes(sk ed25519.PrivateKey) error {
	app.t.Helper()

	resp, err := app.client.GetApplicationBoxes(app.AppID).Do(context.Background())
	if err != nil {
		return err
	}
	if len(resp.Boxes) == 0 {
		return nil
	}

	sender, err := types.DecodeAddress(app.Creator)
	if err != nil {
		return fmt.Errorf("invalid creator address: %w", err)
	}

	for _, box := range resp.Boxes {
		sp, err := app.client.SuggestedParams().Do(context.Background())
		if err != nil {
			return fmt.Errorf("failed to get suggested params: %w", err)
		}
		lease, err := randomLease()
		if err != nil {
			return err
		}

		// ABI-encode the box name: 2-byte big-endian length prefix + name bytes
		nameBytes := box.Name
		abiName := make([]byte, 2+len(nameBytes))
		abiName[0] = byte(len(nameBytes) >> 8)
		abiName[1] = byte(len(nameBytes))
		copy(abiName[2:], nameBytes)

		selector, _ := abi.MethodFromSignature("delete_box(byte[])void")

		txn, err := transaction.MakeApplicationCallTxWithBoxes(
			app.AppID,
			[][]byte{selector.GetSelector(), abiName},
			nil, nil, nil,
			[]types.AppBoxReference{{AppID: app.AppID, Name: nameBytes}},
			types.NoOpOC,
			nil, nil,
			types.StateSchema{}, types.StateSchema{},
			0,
			sp, sender,
			nil, types.Digest{}, lease, types.Address{},
		)
		if err != nil {
			return fmt.Errorf("failed to build delete_box call for %q: %w", string(nameBytes), err)
		}

		_, stxnBytes, err := crypto.SignTransaction(sk, txn)
		if err != nil {
			return fmt.Errorf("failed to sign delete_box call: %w", err)
		}
		txid, err := app.client.SendRawTransaction(stxnBytes).Do(context.Background())
		if err != nil {
			return fmt.Errorf("failed to submit delete_box for %q: %w", string(nameBytes), err)
		}
		_, err = transaction.WaitForConfirmation(app.client, txid, 10, context.Background())
		if err != nil {
			return fmt.Errorf("delete_box for %q not confirmed: %w", string(nameBytes), err)
		}
	}
	return nil
}

// DestroyApp deletes an application by ID using direct SDK signing.
// This is used by integration tests that create apps through apshell rather than DeployTestApp.
func DestroyApp(t *testing.T, client *algod.Client, appID uint64, creatorAddr string, creatorSK ed25519.PrivateKey) error {
	t.Helper()

	app := &TestApp{
		AppID:      appID,
		AppAddress: crypto.GetApplicationAddress(appID).String(),
		Creator:    creatorAddr,
		client:     client,
		t:          t,
	}
	return app.DestroyTestApp(creatorSK)
}

// SubmitGroupedPaymentAndAppCall submits a payment + app call as an atomic group.
// Used for testing the deposit() method. Uses direct SDK signing.
func (app *TestApp) SubmitGroupedPaymentAndAppCall(
	sender string, sk ed25519.PrivateKey,
	paymentAmount uint64, appArgs [][]byte,
) error {
	app.t.Helper()

	sp, err := app.client.SuggestedParams().Do(context.Background())
	if err != nil {
		return fmt.Errorf("failed to get suggested params: %w", err)
	}

	payLease, err := randomLease()
	if err != nil {
		return fmt.Errorf("failed to generate payment lease: %w", err)
	}
	callLease, err := randomLease()
	if err != nil {
		return fmt.Errorf("failed to generate app call lease: %w", err)
	}

	senderAddr, err := types.DecodeAddress(sender)
	if err != nil {
		return fmt.Errorf("invalid sender address: %w", err)
	}

	// Build payment to app address
	payTxn, err := transaction.MakePaymentTxn(sender, app.AppAddress, paymentAmount, nil, "", sp)
	if err != nil {
		return fmt.Errorf("failed to create payment transaction: %w", err)
	}
	payTxn.Lease = payLease

	// Build app call
	callTxn, err := transaction.MakeApplicationCallTx(
		app.AppID,
		appArgs,
		nil, nil, nil,
		types.NoOpOC,
		nil, nil,
		types.StateSchema{}, types.StateSchema{},
		sp, senderAddr,
		nil, types.Digest{}, callLease, types.Address{},
	)
	if err != nil {
		return fmt.Errorf("failed to create app call transaction: %w", err)
	}

	// Assign group ID
	gid, err := crypto.ComputeGroupID([]types.Transaction{payTxn, callTxn})
	if err != nil {
		return fmt.Errorf("failed to compute group ID: %w", err)
	}
	payTxn.Group = gid
	callTxn.Group = gid

	// Sign both
	_, stxn1Bytes, err := crypto.SignTransaction(sk, payTxn)
	if err != nil {
		return fmt.Errorf("failed to sign payment transaction: %w", err)
	}
	_, stxn2Bytes, err := crypto.SignTransaction(sk, callTxn)
	if err != nil {
		return fmt.Errorf("failed to sign app call transaction: %w", err)
	}

	// Submit group
	var groupBytes []byte
	groupBytes = append(groupBytes, stxn1Bytes...)
	groupBytes = append(groupBytes, stxn2Bytes...)

	txid, err := app.client.SendRawTransaction(groupBytes).Do(context.Background())
	if err != nil {
		return fmt.Errorf("failed to submit transaction group: %w", err)
	}

	_, err = transaction.WaitForConfirmation(app.client, txid, 10, context.Background())
	if err != nil {
		return fmt.Errorf("grouped transaction not confirmed: %w", err)
	}

	return nil
}

func randomLease() ([32]byte, error) {
	var lease [32]byte
	_, err := crand.Read(lease[:])
	return lease, err
}

// --- ARC-4 method selectors ---

// IncrementSelector returns the 4-byte ARC-4 method selector for increment(uint64)void.
func IncrementSelector() []byte {
	return []byte{0x82, 0x96, 0xda, 0x2e}
}

// SetBoxSelector returns the 4-byte ARC-4 method selector for set_box(byte[],byte[])void.
func SetBoxSelector() []byte {
	return []byte{0x6e, 0xb6, 0x6b, 0x06}
}

// OptInSelector returns the 4-byte ARC-4 method selector for optin()void.
func OptInSelector() []byte {
	return []byte{0xdc, 0x0d, 0xe7, 0xeb}
}

// DepositSelector returns the 4-byte ARC-4 method selector for deposit()void.
func DepositSelector() []byte {
	return []byte{0x92, 0xe0, 0x3b, 0x1c}
}

// --- ABI encoding helpers ---

// EncodeUint64 ABI-encodes a uint64 as 8 bytes big-endian.
func EncodeUint64(v uint64) []byte {
	b := make([]byte, 8)
	b[0] = byte(v >> 56)
	b[1] = byte(v >> 48)
	b[2] = byte(v >> 40)
	b[3] = byte(v >> 32)
	b[4] = byte(v >> 24)
	b[5] = byte(v >> 16)
	b[6] = byte(v >> 8)
	b[7] = byte(v)
	return b
}

// EncodeBytes ABI-encodes a byte slice with a 2-byte length prefix.
func EncodeBytes(data []byte) []byte {
	length := len(data)
	encoded := make([]byte, 2+length)
	encoded[0] = byte(length >> 8)
	encoded[1] = byte(length)
	copy(encoded[2:], data)
	return encoded
}
