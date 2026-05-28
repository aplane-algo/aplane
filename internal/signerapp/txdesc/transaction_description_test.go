// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package txdesc

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	apconfig "github.com/aplane-algo/aplane/internal/config"
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

	desc := describeApplicationCallTx(txn)

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

			desc := describeApplicationCallTx(txn)
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

	desc := describeApplicationCallTx(txn)
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

	desc := describeApplicationCallTx(txn)
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

	createDesc := describeAssetConfigTx(createTxn)
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

	reconfigDesc := describeAssetConfigTx(reconfigTxn)
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

	destroyDesc := describeAssetConfigTx(destroyTxn)
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

	desc := describeAssetFreezeTx(txn)
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

	onlineDesc := describeKeyRegistrationTx(onlineTxn)
	for _, want := range []string{
		"Key Registration: Go ONLINE",
		"From: " + sender.String(),
		"VoteFirst: 100",
		"VoteLast: 200",
		"VoteKeyDilution: 50",
		"StateProofPK: cc00000000000000...",
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

	nonpartDesc := describeKeyRegistrationTx(nonpartTxn)
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

	desc := describeApplicationCallTx(txn)
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

	desc := DescribeTxn(txn)
	want := "(96 bytes, sha256=" + hex.EncodeToString(sum[:]) + ")"
	if !strings.Contains(desc, want) {
		t.Fatalf("description missing note digest:\n%s", desc)
	}
}

func TestGenerateTransactionDescriptionFromTxn_ShowsResolvedNetwork(t *testing.T) {
	genesisHash, err := base64.StdEncoding.DecodeString(apconfig.AlgorandTestnetGenesisHash)
	if err != nil {
		t.Fatalf("decode genesis hash: %v", err)
	}
	sender, err := types.DecodeAddress("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ")
	if err != nil {
		t.Fatalf("decode sender: %v", err)
	}
	receiver, err := types.DecodeAddress("7777777777777777777777777777777777777777777777777774MSJUVU")
	if err != nil {
		t.Fatalf("decode receiver: %v", err)
	}
	var digest types.Digest
	copy(digest[:], genesisHash)
	txn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender:      sender,
			GenesisHash: digest,
			GenesisID:   "testnet-v1.0",
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: receiver,
			Amount:   1,
		},
	}

	desc := DescribeTxn(txn)
	for _, want := range []string{
		"Network: testnet",
		"GenesisID: testnet-v1.0",
	} {
		if !strings.Contains(desc, want) {
			t.Fatalf("description missing %q:\n%s", want, desc)
		}
	}
}
