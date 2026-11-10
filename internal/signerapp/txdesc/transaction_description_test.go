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

	"github.com/aplane-algo/aplane/internal/asaset"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policycontext"
	"time"
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

	desc := describeApplicationCallTx(txn, chainView{})

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

			desc := describeApplicationCallTx(txn, chainView{})
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

	desc := describeApplicationCallTx(txn, chainView{})
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

	desc := describeApplicationCallTx(txn, chainView{})
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

	createDesc := describeAssetConfigTx(createTxn, chainView{})
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

	reconfigDesc := describeAssetConfigTx(reconfigTxn, chainView{})
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

	destroyDesc := describeAssetConfigTx(destroyTxn, chainView{})
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

	desc := describeAssetFreezeTx(txn, chainView{})
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

	onlineDesc := describeKeyRegistrationTx(onlineTxn, chainView{})
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

	nonpartDesc := describeKeyRegistrationTx(nonpartTxn, chainView{})
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

	desc := describeApplicationCallTx(txn, chainView{})
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

// describeContext is a signer that maps private-dev and has confirmed asset
// 9 on it with 2 decimals.
func describeContext(t *testing.T) (*policycontext.Context, types.Digest) {
	t.Helper()
	const hash = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	networks, err := apconfig.NewGenesisHashNetworkResolver(map[string]string{hash: "private-dev"})
	if err != nil {
		t.Fatal(err)
	}
	genesis, err := asaset.ParseGenesisHash(hash)
	if err != nil {
		t.Fatal(err)
	}
	set, err := asaset.New([]asaset.Entry{{
		Identity: asaset.Identity{Genesis: genesis, AssetID: 9}, UnitName: "XYZ", Decimals: 2,
		Creator: types.Address{1}.String(), ConfirmedAt: time.Unix(1_700_000_000, 0), NetworkAtConfirmation: "private-dev",
	}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := policycontext.New(noderole.RoleSigner, networks, set)
	if err != nil {
		t.Fatal(err)
	}
	return ctx, types.Digest(genesis)
}

func TestDescribeInContextLabelsKnownAssets(t *testing.T) {
	ctx, genesis := describeContext(t)
	transfer := func(id uint64) types.Transaction {
		return types.Transaction{Type: types.AssetTransferTx, Header: types.Header{GenesisHash: genesis},
			AssetTransferTxnFields: types.AssetTransferTxnFields{XferAsset: types.AssetIndex(id), AssetAmount: 150}}
	}
	known := DescribeTxnInContext(transfer(9), ctx)
	if !strings.Contains(known, "ASA Transfer: 1.5 XYZ (150 base units), asset #9, private-dev") || strings.Contains(known, "Not in this node's ASA set") {
		t.Fatalf("known asset:\n%s", known)
	}
	unknown := DescribeTxnInContext(transfer(10), ctx)
	if !strings.Contains(unknown, "ASA Transfer: 150 base units, asset #10, private-dev\n  Not in this node's ASA set") {
		t.Fatalf("unknown asset:\n%s", unknown)
	}
	// The same ID on another chain is another asset.
	elsewhere := transfer(9)
	elsewhere.GenesisHash = types.Digest{7}
	if other := DescribeTxnInContext(elsewhere, ctx); !strings.Contains(other, "ASA Transfer: 150 base units, asset #9\n  Not in this node's ASA set") {
		t.Fatalf("asset 9 on another chain:\n%s", other)
	}
	freeze := types.Transaction{Type: types.AssetFreezeTx, Header: types.Header{GenesisHash: genesis},
		AssetFreezeTxnFields: types.AssetFreezeTxnFields{FreezeAsset: 9}}
	if got := DescribeTxnInContext(freeze, ctx); !strings.Contains(got, "Asset Freeze: asset #9 (XYZ)") {
		t.Fatalf("freeze:\n%s", got)
	}
	// Without a context, the description says only what the bytes say.
	if plain := DescribeTxnWithResolver(transfer(9), apconfig.DefaultGenesisHashNetworkResolver()); !strings.Contains(plain, "ASA Transfer: 150 base units, asset #9") || strings.Contains(plain, "ASA set") {
		t.Fatalf("without a context:\n%s", plain)
	}
}

// An asset's name, unit and URL, and a transaction's genesis ID and type, are
// whatever bytes the issuer or the client chose. A description shows them
// escaped, so none of them can clear the operator's screen, move the cursor
// over lines already printed, start a new line of its own, or reorder text.
func TestDescribeEscapesIssuerAndClientText(t *testing.T) {
	const hostile = "X\x1b[2J\x1b[H\r\n  To:   ATTACKER\u202e\xff"
	sender := types.Address{2}
	describeLines := func(txn types.Transaction) []string {
		t.Helper()
		desc := DescribeTxn(txn)
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

	desc := describeApplicationCallTx(txn, chainView{})
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
	}, chainView{})
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
	}, chainView{})
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
