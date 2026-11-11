// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package txnreview

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestDescribeApplicationCallTx(t *testing.T) {
	sender, err := types.DecodeAddress("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ")
	if err != nil {
		t.Fatalf("decode sender: %v", err)
	}
	account, err := types.DecodeAddress("7777777777777777777777777777777777777777777777777774MSJUVU")
	if err != nil {
		t.Fatalf("decode account: %v", err)
	}

	txn := types.Transaction{
		Type: types.ApplicationCallTx,
		Header: types.Header{
			Sender: sender,
		},
		ApplicationFields: types.ApplicationFields{
			ApplicationCallTxnFields: types.ApplicationCallTxnFields{
				ApplicationID: 123,
				OnCompletion:  types.NoOpOC,
				ApplicationArgs: [][]byte{
					{0x82, 0x96, 0xda, 0x2e},
					[]byte("hello"),
					[]byte("0123456789abcdefg"),
				},
				Accounts:      []types.Address{account},
				ForeignApps:   []types.AppIndex{456, 789},
				ForeignAssets: []types.AssetIndex{31566704},
				BoxReferences: []types.BoxReference{
					{ForeignAppIdx: 0, Name: []byte("cfg")},
					{ForeignAppIdx: 1, Name: []byte{0xde, 0xad, 0xbe, 0xef}},
				},
			},
		},
	}

	desc := describeApplicationCallTx(txn, View{})

	for _, want := range []string{
		"App Call: #123 (NoOp)",
		"From: " + sender.String(),
		"Args: 3 argument(s)",
		`[0]: 0x8296da2e`,
		`[1]: "hello"`,
		`[2]: "0123456789abcdefg"`,
		"Accounts: 1",
		account.String(),
		"Foreign Apps: 2",
		"[0]: 456",
		"Foreign Assets: 1",
		"[0]: 31566704",
		"Boxes: 2",
		`[0]: app 123 / "cfg"`,
		`[1]: app 456 / 0xdeadbeef`,
	} {
		if !strings.Contains(desc, want) {
			t.Fatalf("description missing %q:\n%s", want, desc)
		}
	}
}

func TestDescribeApplicationCallTx_OnCompletionVariants(t *testing.T) {
	sender, err := types.DecodeAddress("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ")
	if err != nil {
		t.Fatalf("decode sender: %v", err)
	}

	tests := []struct {
		onComp types.OnCompletion
		want   string
	}{
		{onComp: types.OptInOC, want: "App Call: #77 (OptIn)"},
		{onComp: types.CloseOutOC, want: "App Call: #77 (CloseOut)"},
		{onComp: types.ClearStateOC, want: "App Call: #77 (ClearState)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			txn := types.Transaction{
				Type: types.ApplicationCallTx,
				Header: types.Header{
					Sender: sender,
				},
				ApplicationFields: types.ApplicationFields{
					ApplicationCallTxnFields: types.ApplicationCallTxnFields{
						ApplicationID: 77,
						OnCompletion:  tt.onComp,
					},
				},
			}

			desc := describeApplicationCallTx(txn, View{})
			if !strings.Contains(desc, tt.want) {
				t.Fatalf("description missing %q:\n%s", tt.want, desc)
			}
		})
	}
}

func TestDescribeApplicationCallTx_ShowsAllArgsAndReferences(t *testing.T) {
	sender, err := types.DecodeAddress("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ")
	if err != nil {
		t.Fatalf("decode sender: %v", err)
	}
	accountA, err := types.DecodeAddress("7777777777777777777777777777777777777777777777777774MSJUVU")
	if err != nil {
		t.Fatalf("decode accountA: %v", err)
	}
	var accountB types.Address
	accountB[0] = 1
	accountB[31] = 2

	txn := types.Transaction{
		Type: types.ApplicationCallTx,
		Header: types.Header{
			Sender: sender,
		},
		ApplicationFields: types.ApplicationFields{
			ApplicationCallTxnFields: types.ApplicationCallTxnFields{
				ApplicationID: 999,
				OnCompletion:  types.NoOpOC,
				ApplicationArgs: [][]byte{
					{0x82, 0x96, 0xda, 0x2e},
					[]byte("hello"),
					{0xde, 0xad, 0xbe, 0xef},
					[]byte("third"),
					[]byte("fifth-arg-visible"),
				},
				Accounts:      []types.Address{accountA, accountB},
				ForeignApps:   []types.AppIndex{1, 2, 3, 4, 5},
				ForeignAssets: []types.AssetIndex{10, 20, 30, 40, 50},
				BoxReferences: []types.BoxReference{
					{ForeignAppIdx: 0, Name: []byte("cfg")},
					{ForeignAppIdx: 2, Name: []byte("fifth-box")},
				},
			},
		},
	}

	desc := describeApplicationCallTx(txn, View{})
	for _, want := range []string{
		`[2]: 0xdeadbeef`,
		`[4]: "fifth-arg-visible"`,
		accountB.String(),
		`[4]: 5`,
		`[4]: 50`,
		`[1]: app 2 / "fifth-box"`,
	} {
		if !strings.Contains(desc, want) {
			t.Fatalf("description missing %q:\n%s", want, desc)
		}
	}
	if strings.Contains(desc, "... (") {
		t.Fatalf("description still contains truncation marker:\n%s", desc)
	}
}

func TestDescribeApplicationCallTx_ShowsProgramHashesAndSchema(t *testing.T) {
	sender, err := types.DecodeAddress("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ")
	if err != nil {
		t.Fatalf("decode sender: %v", err)
	}
	approvalProgram := []byte{0x01, 0x20, 0x01, 0x01, 0x22}
	clearProgram := []byte{0x01, 0x01, 0x22}
	approvalHash := sha256.Sum256(approvalProgram)
	clearHash := sha256.Sum256(clearProgram)

	txn := types.Transaction{
		Type: types.ApplicationCallTx,
		Header: types.Header{
			Sender: sender,
		},
		ApplicationFields: types.ApplicationFields{
			ApplicationCallTxnFields: types.ApplicationCallTxnFields{
				OnCompletion:      types.NoOpOC,
				ApprovalProgram:   approvalProgram,
				ClearStateProgram: clearProgram,
				GlobalStateSchema: types.StateSchema{NumUint: 2, NumByteSlice: 3},
				LocalStateSchema:  types.StateSchema{NumUint: 1, NumByteSlice: 4},
				ExtraProgramPages: 2,
			},
		},
	}

	desc := describeApplicationCallTx(txn, View{})
	for _, want := range []string{
		"App Create (NoOp)",
		"Approval Program: 5 bytes, sha256=" + hex.EncodeToString(approvalHash[:]),
		"Clear Program: 3 bytes, sha256=" + hex.EncodeToString(clearHash[:]),
		"Global Schema: 2 uint, 3 bytes",
		"Local Schema: 1 uint, 4 bytes",
		"Extra Program Pages: 2",
	} {
		if !strings.Contains(desc, want) {
			t.Fatalf("description missing %q:\n%s", want, desc)
		}
	}
}

func TestDescribeAssetConfigTx_ShowsAuthorities(t *testing.T) {
	var sender types.Address
	sender[0] = 2
	var manager types.Address
	manager[0] = 3
	var reserve types.Address
	reserve[0] = 4
	var freeze types.Address
	freeze[0] = 5
	var clawback types.Address
	clawback[0] = 6

	var metadataHash [32]byte
	copy(metadataHash[:], []byte("metadata-hash-contents-1234567890"))

	createTxn := types.Transaction{
		Type: types.AssetConfigTx,
		Header: types.Header{
			Sender: sender,
		},
		AssetConfigTxnFields: types.AssetConfigTxnFields{
			ConfigAsset: 0,
			AssetParams: types.AssetParams{
				AssetName:     "Example",
				UnitName:      "EX",
				Total:         1000,
				Decimals:      2,
				DefaultFrozen: true,
				Manager:       manager,
				Reserve:       reserve,
				Freeze:        freeze,
				Clawback:      clawback,
				URL:           "https://example.test/asa",
				MetadataHash:  metadataHash,
			},
		},
	}

	createDesc := describeAssetConfigTx(createTxn, View{})
	for _, want := range []string{
		"Asset Creation",
		"From: " + sender.String(),
		"Default Frozen: true",
		"Manager: " + manager.String(),
		"Reserve: " + reserve.String(),
		"Freeze: " + freeze.String(),
		"Clawback: " + clawback.String(),
		"URL: https://example.test/asa",
		"Metadata Hash: " + hex.EncodeToString(metadataHash[:]),
	} {
		if !strings.Contains(createDesc, want) {
			t.Fatalf("asset creation description missing %q:\n%s", want, createDesc)
		}
	}

	reconfigTxn := types.Transaction{
		Type: types.AssetConfigTx,
		Header: types.Header{
			Sender: sender,
		},
		AssetConfigTxnFields: types.AssetConfigTxnFields{
			ConfigAsset: 42,
			AssetParams: types.AssetParams{
				Manager: manager,
			},
		},
	}

	reconfigDesc := describeAssetConfigTx(reconfigTxn, View{})
	for _, want := range []string{
		"Asset Reconfiguration: asset #42",
		"From: " + sender.String(),
		"Manager: " + manager.String(),
		"Reserve: (zero address / disabled)",
		"Freeze: (zero address / disabled)",
		"Clawback: (zero address / disabled)",
	} {
		if !strings.Contains(reconfigDesc, want) {
			t.Fatalf("asset reconfiguration description missing %q:\n%s", want, reconfigDesc)
		}
	}

	destroyTxn := types.Transaction{
		Type: types.AssetConfigTx,
		Header: types.Header{
			Sender: sender,
		},
		AssetConfigTxnFields: types.AssetConfigTxnFields{
			ConfigAsset: 42,
		},
	}

	destroyDesc := describeAssetConfigTx(destroyTxn, View{})
	if !strings.Contains(destroyDesc, "Asset Destroy: asset #42") {
		t.Fatalf("asset destroy description missing destroy label:\n%s", destroyDesc)
	}
	if !strings.Contains(destroyDesc, "From: "+sender.String()) {
		t.Fatalf("asset destroy description missing sender:\n%s", destroyDesc)
	}
	if strings.Contains(destroyDesc, "Asset Reconfiguration") {
		t.Fatalf("asset destroy description mislabeled as reconfiguration:\n%s", destroyDesc)
	}
}

func TestDescribeAssetFreezeTx_ShowsSender(t *testing.T) {
	var sender types.Address
	sender[0] = 7
	var target types.Address
	target[0] = 8
	txn := types.Transaction{
		Type: types.AssetFreezeTx,
		Header: types.Header{
			Sender: sender,
		},
		AssetFreezeTxnFields: types.AssetFreezeTxnFields{
			FreezeAccount: target,
			FreezeAsset:   99,
			AssetFrozen:   true,
		},
	}

	desc := describeAssetFreezeTx(txn, View{})
	for _, want := range []string{
		"Asset Freeze: asset #99",
		"From: " + sender.String(),
		"Account: " + target.String(),
		"Action: FREEZE",
	} {
		if !strings.Contains(desc, want) {
			t.Fatalf("asset freeze description missing %q:\n%s", want, desc)
		}
	}
}

func TestDescribeKeyRegistrationTx_ShowsParticipationDetails(t *testing.T) {
	var sender types.Address
	sender[0] = 9
	var votePK types.VotePK
	votePK[0] = 0xaa
	var selectionPK types.VRFPK
	selectionPK[0] = 0xbb
	var stateProofPK types.MerkleVerifier
	stateProofPK[0] = 0xcc

	onlineTxn := types.Transaction{
		Type: types.KeyRegistrationTx,
		Header: types.Header{
			Sender: sender,
		},
		KeyregTxnFields: types.KeyregTxnFields{
			VotePK:          votePK,
			SelectionPK:     selectionPK,
			StateProofPK:    stateProofPK,
			VoteFirst:       100,
			VoteLast:        200,
			VoteKeyDilution: 50,
		},
	}

	onlineDesc := describeKeyRegistrationTx(onlineTxn, View{})
	for _, want := range []string{
		"Key Registration: Go ONLINE",
		"From: " + sender.String(),
		"VoteFirst: 100",
		"VoteLast: 200",
		"VoteKeyDilution: 50",
		// Whole keys, in base64, not a prefix.
		"VotePK: " + base64.StdEncoding.EncodeToString(votePK[:]),
		"SelectionPK: " + base64.StdEncoding.EncodeToString(selectionPK[:]),
		"StateProofPK: " + base64.StdEncoding.EncodeToString(stateProofPK[:]),
	} {
		if !strings.Contains(onlineDesc, want) {
			t.Fatalf("online keyreg description missing %q:\n%s", want, onlineDesc)
		}
	}

	nonpartTxn := types.Transaction{
		Type: types.KeyRegistrationTx,
		Header: types.Header{
			Sender: sender,
		},
		KeyregTxnFields: types.KeyregTxnFields{
			Nonparticipation: true,
		},
	}

	nonpartDesc := describeKeyRegistrationTx(nonpartTxn, View{})
	if !strings.Contains(nonpartDesc, "Key Registration: Go NONPARTICIPATING") {
		t.Fatalf("nonparticipation keyreg description missing nonparticipation state:\n%s", nonpartDesc)
	}
	if !strings.Contains(nonpartDesc, "From: "+sender.String()) {
		t.Fatalf("nonparticipation keyreg description missing sender:\n%s", nonpartDesc)
	}
}

func TestDescribeApplicationCallTx_LongOpaqueArgShowsDigest(t *testing.T) {
	sender, err := types.DecodeAddress("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ")
	if err != nil {
		t.Fatalf("decode sender: %v", err)
	}
	longArg := bytes.Repeat([]byte{0xab}, 80)
	sum := sha256.Sum256(longArg)

	txn := types.Transaction{
		Type: types.ApplicationCallTx,
		Header: types.Header{
			Sender: sender,
		},
		ApplicationFields: types.ApplicationFields{
			ApplicationCallTxnFields: types.ApplicationCallTxnFields{
				ApplicationID: 321,
				OnCompletion:  types.NoOpOC,
				ApplicationArgs: [][]byte{
					{0x82, 0x96, 0xda, 0x2e},
					longArg,
				},
			},
		},
	}

	desc := describeApplicationCallTx(txn, View{})
	want := "(80 bytes, sha256=" + hex.EncodeToString(sum[:]) + ")"
	if !strings.Contains(desc, want) {
		t.Fatalf("description missing opaque arg digest:\n%s", desc)
	}
}

func TestGenerateTransactionDescriptionFromTxn_LongBinaryNoteShowsDigest(t *testing.T) {
	sender, err := types.DecodeAddress("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ")
	if err != nil {
		t.Fatalf("decode sender: %v", err)
	}
	receiver, err := types.DecodeAddress("7777777777777777777777777777777777777777777777777774MSJUVU")
	if err != nil {
		t.Fatalf("decode receiver: %v", err)
	}
	note := bytes.Repeat([]byte{0xcd}, 96)
	sum := sha256.Sum256(note)

	txn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender: sender,
			Note:   note,
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: receiver,
			Amount:   1,
		},
	}

	desc := Describe(txn, View{})
	want := "(96 bytes, sha256=" + hex.EncodeToString(sum[:]) + ")"
	if !strings.Contains(desc, want) {
		t.Fatalf("description missing note digest:\n%s", desc)
	}
}

func TestDescribeEscapesIssuerAndClientText(t *testing.T) {
	const hostile = "X\x1b[2J\x1b[H\r\n  To:   ATTACKER\u202e\xff"
	sender := types.Address{2}
	describeLines := func(txn types.Transaction) []string {
		t.Helper()
		desc := Describe(txn, View{})
		for i := 0; i < len(desc); i++ {
			if c := desc[i]; c < 0x20 && c != '\n' || c == 0x7f {
				t.Fatalf("description holds raw byte 0x%02x:\n%q", c, desc)
			}
		}
		if strings.ContainsRune(desc, '\u202e') || strings.ContainsRune(desc, '\ufffd') {
			t.Fatalf("description holds a format or invalid character:\n%q", desc)
		}
		return strings.Split(desc, "\n")
	}

	clean := types.Transaction{
		Type:   types.AssetConfigTx,
		Header: types.Header{Sender: sender, GenesisID: "testnet-v1.0"},
		AssetConfigTxnFields: types.AssetConfigTxnFields{AssetParams: types.AssetParams{
			AssetName: "Example", UnitName: "EX", URL: "https://example.test", Total: 1,
		}},
	}
	hostileTxn := clean
	hostileTxn.GenesisID = hostile
	hostileTxn.AssetParams.AssetName = hostile
	hostileTxn.AssetParams.UnitName = hostile
	hostileTxn.AssetParams.URL = hostile

	cleanLines, hostileLines := describeLines(clean), describeLines(hostileTxn)
	if len(hostileLines) != len(cleanLines) {
		t.Fatalf("hostile text changed the line count from %d to %d:\n%s", len(cleanLines), len(hostileLines), strings.Join(hostileLines, "\n"))
	}
	const escaped = `X\x1b[2J\x1b[H\r\n  To:   ATTACKER\u202e\xff`
	for _, label := range []string{"Name", "Unit", "URL", "GenesisID"} {
		want := "  " + label + ": " + escaped
		found := false
		for _, line := range hostileLines {
			found = found || line == want
		}
		if !found {
			t.Errorf("description has no line %q:\n%s", want, strings.Join(hostileLines, "\n"))
		}
	}

	unknown := describeLines(types.Transaction{Type: types.TxType(hostile), Header: types.Header{Sender: sender}})
	if unknown[0] != "Transaction Type: "+escaped {
		t.Errorf("unknown type line = %q, want it escaped", unknown[0])
	}
}

func TestDescribeApplicationCallTx_ShowsAccessListAndRejectVersion(t *testing.T) {
	var payout types.Address
	payout[0] = 9
	txn := types.Transaction{
		Type: types.ApplicationCallTx,
		ApplicationFields: types.ApplicationFields{
			ApplicationCallTxnFields: types.ApplicationCallTxnFields{
				ApplicationID: 123,
				Access: []types.ResourceRef{
					{Address: payout},
					{Asset: 31566704},
					{App: 456},
					{Holding: types.HoldingRef{Address: 1, Asset: 2}},
					{Holding: types.HoldingRef{Address: 0, Asset: 2}},
					{Locals: types.LocalsRef{Address: 1, App: 3}},
					{Locals: types.LocalsRef{Address: 0, App: 3}},
					{Box: types.BoxReference{ForeignAppIdx: 3, Name: []byte("vault")}},
					{Box: types.BoxReference{Name: []byte("own")}},
					{Holding: types.HoldingRef{Address: 2, Asset: 9}},
					{Address: payout, Asset: 7},
					{},
					{Locals: types.LocalsRef{Address: 40, App: 3}},
				},
				RejectVersion: 4,
			},
		},
	}

	desc := describeApplicationCallTx(txn, View{})
	for _, want := range []string{
		"Access: 13",
		"[12]: local state of ?[39] (no such entry) in app 456",
		"[0]: account " + payout.String(),
		"[1]: asset 31566704",
		"[2]: app 456",
		"[3]: holding of asset 31566704 by account " + payout.String(),
		"[4]: holding of asset 31566704 by the sender",
		"[5]: local state of account " + payout.String() + " in app 456",
		"[6]: local state of the sender in app 456",
		"[7]: box app 456 / ",
		"[8]: box app 123 (the called app) / ",
		"[9]: holding of ?[8] (not an asset) by ?[1] (not an account)",
		"[10]: MALFORMED, more than one kind: account " + payout.String() + "; asset 7",
		"[11]: (empty entry: adds box read/write budget)",
		"Reject Version: 4 (the call fails if the app's version is 4 or higher)",
	} {
		if !strings.Contains(desc, want) {
			t.Errorf("description missing %q:\n%s", want, desc)
		}
	}

	plain := describeApplicationCallTx(types.Transaction{
		Type: types.ApplicationCallTx,
		ApplicationFields: types.ApplicationFields{
			ApplicationCallTxnFields: types.ApplicationCallTxnFields{ApplicationID: 123},
		},
	}, View{})
	if strings.Contains(plain, "Access") || strings.Contains(plain, "Reject Version") {
		t.Errorf("a call with neither field mentions one:\n%s", plain)
	}
}

func TestDescribeApplicationCallTx_NamesTheAppBeingCreated(t *testing.T) {
	desc := describeApplicationCallTx(types.Transaction{
		Type: types.ApplicationCallTx,
		ApplicationFields: types.ApplicationFields{
			ApplicationCallTxnFields: types.ApplicationCallTxnFields{
				BoxReferences: []types.BoxReference{{Name: []byte("legacy")}},
				Access:        []types.ResourceRef{{Box: types.BoxReference{Name: []byte("vault")}}},
			},
		},
	}, View{})
	for _, want := range []string{
		"[0]: app (the app being created) / ",
		"[0]: box app (the app being created) / ",
	} {
		if !strings.Contains(desc, want) {
			t.Errorf("description missing %q:\n%s", want, desc)
		}
	}
	if strings.Contains(desc, "app 0") {
		t.Errorf("an app create is shown as app 0:\n%s", desc)
	}
}

// findingFields names the fields Findings reports for txn, in order.
func findingFields(txn types.Transaction) []string {
	var fields []string
	for _, finding := range Findings(txn, FindingContext{}) {
		fields = append(fields, finding.Field)
	}
	return fields
}

func TestFindingsCoverEveryHandoverAndUseOfAuthority(t *testing.T) {
	var sender, other types.Address
	sender[0], other[0] = 1, 2
	appCall := func(id uint64, oc types.OnCompletion) types.Transaction {
		return types.Transaction{
			Type: types.ApplicationCallTx, Header: types.Header{Sender: sender},
			ApplicationFields: types.ApplicationFields{ApplicationCallTxnFields: types.ApplicationCallTxnFields{
				ApplicationID: types.AppIndex(id), OnCompletion: oc,
			}},
		}
	}

	cases := []struct {
		name string
		txn  types.Transaction
		want []string
	}{
		{"plain payment", types.Transaction{
			Type: types.PaymentTx, Header: types.Header{Sender: sender, Fee: 1000},
			PaymentTxnFields: types.PaymentTxnFields{Receiver: other, Amount: 5},
		}, nil},
		{"zero self-payment that rekeys", types.Transaction{
			Type: types.PaymentTx, Header: types.Header{Sender: sender, RekeyTo: other},
			PaymentTxnFields: types.PaymentTxnFields{Receiver: sender},
		}, []string{"RekeyTo"}},
		{"payment that closes", types.Transaction{
			Type: types.PaymentTx, Header: types.Header{Sender: sender},
			PaymentTxnFields: types.PaymentTxnFields{Receiver: sender, CloseRemainderTo: other},
		}, []string{"CloseRemainderTo"}},
		{"asset close and clawback", types.Transaction{
			Type: types.AssetTransferTx, Header: types.Header{Sender: sender},
			AssetTransferTxnFields: types.AssetTransferTxnFields{XferAsset: 7, AssetCloseTo: other, AssetSender: other},
		}, []string{"AssetCloseTo", "AssetSender"}},
		{"asset sender is the sender", types.Transaction{
			Type: types.AssetTransferTx, Header: types.Header{Sender: sender},
			AssetTransferTxnFields: types.AssetTransferTxnFields{XferAsset: 7, AssetSender: sender},
		}, nil},
		{"app no-op", appCall(9, types.NoOpOC), nil},
		{"app update", appCall(9, types.UpdateApplicationOC), []string{"OnCompletion"}},
		{"app delete", appCall(9, types.DeleteApplicationOC), []string{"OnCompletion"}},
		{"app clear state", appCall(9, types.ClearStateOC), []string{"OnCompletion"}},
		{"asset create", types.Transaction{
			Type: types.AssetConfigTx, Header: types.Header{Sender: sender},
			AssetConfigTxnFields: types.AssetConfigTxnFields{AssetParams: types.AssetParams{Total: 1, Manager: sender}},
		}, nil},
		{"asset destroy", types.Transaction{
			Type: types.AssetConfigTx, Header: types.Header{Sender: sender},
			AssetConfigTxnFields: types.AssetConfigTxnFields{ConfigAsset: 5},
		}, []string{"ConfigAsset"}},
		{"asset reconfigure", types.Transaction{
			Type: types.AssetConfigTx, Header: types.Header{Sender: sender},
			AssetConfigTxnFields: types.AssetConfigTxnFields{ConfigAsset: 5, AssetParams: types.AssetParams{Manager: other}},
		}, []string{"ConfigAsset"}},
		{"asset freeze", types.Transaction{
			Type: types.AssetFreezeTx, Header: types.Header{Sender: sender},
			AssetFreezeTxnFields: types.AssetFreezeTxnFields{FreezeAsset: 5, FreezeAccount: other, AssetFrozen: true},
		}, []string{"FreezeAccount"}},
		{"keyreg offline", types.Transaction{
			Type: types.KeyRegistrationTx, Header: types.Header{Sender: sender},
		}, nil},
		{"keyreg online with both keys", types.Transaction{
			Type: types.KeyRegistrationTx, Header: types.Header{Sender: sender},
			KeyregTxnFields: types.KeyregTxnFields{VotePK: types.VotePK{1}, SelectionPK: types.VRFPK{2}},
		}, nil},
		{"keyreg nonparticipating", types.Transaction{
			Type: types.KeyRegistrationTx, Header: types.Header{Sender: sender},
			KeyregTxnFields: types.KeyregTxnFields{Nonparticipation: true},
		}, []string{"Nonparticipation"}},
		{"keyreg with only a selection key", types.Transaction{
			Type: types.KeyRegistrationTx, Header: types.Header{Sender: sender},
			KeyregTxnFields: types.KeyregTxnFields{SelectionPK: types.VRFPK{2}},
		}, []string{"KeyRegistration"}},
		{"fee above one ALGO", types.Transaction{
			Type: types.PaymentTx, Header: types.Header{Sender: sender, Fee: 5_000_000_000},
			PaymentTxnFields: types.PaymentTxnFields{Receiver: other},
		}, []string{"Fee"}},
		{"unknown type that rekeys", types.Transaction{
			Type: types.TxType("zzz"), Header: types.Header{Sender: sender, RekeyTo: other},
		}, []string{"RekeyTo"}},
	}
	for _, tc := range cases {
		if got := findingFields(tc.txn); strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("%s: findings %q, want %q", tc.name, got, tc.want)
		}
	}
}

// A finding's value is the address, asset or action it is about. The
// description of the same transaction must show that value too, so a review
// that prints both never warns about something it does not display.
func TestEveryFindingIsAlsoShownInTheDescription(t *testing.T) {
	var sender, other types.Address
	sender[0], other[0] = 1, 2
	for name, txn := range map[string]types.Transaction{
		"rekey and close": {
			Type: types.PaymentTx, Header: types.Header{Sender: sender, RekeyTo: other},
			PaymentTxnFields: types.PaymentTxnFields{Receiver: sender, CloseRemainderTo: other},
		},
		"asset close and clawback": {
			Type: types.AssetTransferTx, Header: types.Header{Sender: sender},
			AssetTransferTxnFields: types.AssetTransferTxnFields{XferAsset: 7, AssetCloseTo: other, AssetSender: other},
		},
		"asset reconfigure": {
			Type: types.AssetConfigTx, Header: types.Header{Sender: sender},
			AssetConfigTxnFields: types.AssetConfigTxnFields{ConfigAsset: 5, AssetParams: types.AssetParams{Manager: other}},
		},
		"asset freeze": {
			Type: types.AssetFreezeTx, Header: types.Header{Sender: sender},
			AssetFreezeTxnFields: types.AssetFreezeTxnFields{FreezeAsset: 5, FreezeAccount: other, AssetFrozen: true},
		},
	} {
		desc := Describe(txn, View{})
		findings := Findings(txn, FindingContext{})
		if len(findings) == 0 {
			t.Errorf("%s: no findings", name)
		}
		for _, finding := range findings {
			shown := finding.Value
			if finding.Field == "ConfigAsset" {
				shown = "asset #" + finding.Value
			}
			if !strings.Contains(desc, shown) {
				t.Errorf("%s: finding %s = %s is not in the description:\n%s", name, finding.Field, finding.Value, desc)
			}
		}
	}
}

func TestDescribeShowsWhatAReviewerNeedsToCompare(t *testing.T) {
	var sender types.Address
	sender[0] = 1

	// Participation keys in base64, the form an operator has them in; a
	// missing key named as missing, not printed as zeros.
	online := Describe(types.Transaction{
		Type: types.KeyRegistrationTx, Header: types.Header{Sender: sender},
		KeyregTxnFields: types.KeyregTxnFields{VotePK: types.VotePK{1}},
	}, View{})
	for _, want := range []string{
		"VotePK: " + base64.StdEncoding.EncodeToString(append([]byte{1}, make([]byte, 31)...)),
		"SelectionPK: (none)",
		"StateProofPK: (none)",
	} {
		if !strings.Contains(online, want) {
			t.Errorf("online keyreg missing %q:\n%s", want, online)
		}
	}

	lease := [32]byte{7}
	leased := Describe(types.Transaction{
		Type: types.PaymentTx, Header: types.Header{Sender: sender, Lease: lease},
		PaymentTxnFields: types.PaymentTxnFields{Receiver: sender},
	}, View{})
	if !strings.Contains(leased, "Lease: "+base64.StdEncoding.EncodeToString(lease[:])) {
		t.Errorf("a lease is not shown:\n%s", leased)
	}

	unknown := Describe(types.Transaction{Type: types.TxType("hb"), Header: types.Header{Sender: sender}}, View{})
	if !strings.Contains(unknown, "NOT shown") {
		t.Errorf("an unknown type reads as a complete description:\n%s", unknown)
	}

	transfer := Describe(types.Transaction{
		Type: types.AssetTransferTx, Header: types.Header{Sender: sender},
		AssetTransferTxnFields: types.AssetTransferTxnFields{XferAsset: 7, AssetReceiver: sender},
	}, View{Network: "net\x1b[2J"})
	if strings.Contains(transfer, "\x1b") {
		t.Errorf("the network token is printed unescaped:\n%q", transfer)
	}
}

// A transfer naming its own sender as the account it takes from is a
// clawback of the sender's own holding, and is described as one. It is not a
// finding: the clawback warning is for taking from someone else. A clawback
// from another account and a plain transfer are described as before.
func TestDescribeSelfClawback(t *testing.T) {
	sender, other := types.Address{1}, types.Address{2}
	transfer := func(assetSender types.Address) types.Transaction {
		return types.Transaction{
			Type:   types.AssetTransferTx,
			Header: types.Header{Sender: sender},
			AssetTransferTxnFields: types.AssetTransferTxnFields{
				XferAsset: 7, AssetAmount: 5, AssetReceiver: other, AssetSender: assetSender,
			},
		}
	}

	self := Describe(transfer(sender), View{})
	if want := "\n  Moves the sender's own holding by clawback authority, even if frozen"; !strings.Contains(self, want) {
		t.Fatalf("self clawback description missing %q:\n%s", want, self)
	}
	// A description line, not the warning a clawback from someone else gets.
	if strings.Contains(self, "⚠") || strings.Contains(self, "CLAWBACK") {
		t.Fatalf("self clawback reads as the clawback warning:\n%s", self)
	}
	if findings := Findings(transfer(sender), FindingContext{}); len(findings) != 0 {
		t.Fatalf("self clawback findings = %+v, want none", findings)
	}

	fromOther := Describe(transfer(other), View{})
	if !strings.Contains(fromOther, "CLAWBACK FROM: "+other.String()) || strings.Contains(fromOther, "own holding") {
		t.Fatalf("clawback from another account:\n%s", fromOther)
	}
	if plain := Describe(transfer(types.Address{}), View{}); strings.Contains(plain, "CLAWBACK") {
		t.Fatalf("plain transfer described as a clawback:\n%s", plain)
	}
}
