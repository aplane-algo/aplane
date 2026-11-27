// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"bytes"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/hostmeta"
	"github.com/aplane-algo/aplane/internal/merkleallowlist"
	coresigning "github.com/aplane-algo/aplane/internal/signing"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestDecodeHexRuntimeArgs(t *testing.T) {
	decoded, err := decodeHexRuntimeArgs(map[string]string{
		"recipient": "001122",
		"secret":    "aabbcc",
	})
	if err != nil {
		t.Fatalf("decodeHexRuntimeArgs: %v", err)
	}
	if got := decoded["recipient"]; !bytes.Equal(got, []byte{0x00, 0x11, 0x22}) {
		t.Fatalf("recipient = %x, want 001122", got)
	}
	if got := decoded["secret"]; !bytes.Equal(got, []byte{0xaa, 0xbb, 0xcc}) {
		t.Fatalf("secret = %x, want aabbcc", got)
	}
}

func TestDecodeHexRuntimeArgsEmpty(t *testing.T) {
	decoded, err := decodeHexRuntimeArgs(nil)
	if err != nil {
		t.Fatalf("decodeHexRuntimeArgs(nil): %v", err)
	}
	if decoded != nil {
		t.Fatalf("decodeHexRuntimeArgs(nil) = %#v, want nil", decoded)
	}

	decoded, err = decodeHexRuntimeArgs(map[string]string{})
	if err != nil {
		t.Fatalf("decodeHexRuntimeArgs(empty): %v", err)
	}
	if decoded != nil {
		t.Fatalf("decodeHexRuntimeArgs(empty) = %#v, want nil", decoded)
	}
}

// An argument that isn't hex is named, and nothing of its value is quoted:
// the decoder's error names the byte it stopped at, and an argument is a
// secret until it is spent.
func TestDecodeHexRuntimeArgsReportsArgumentName(t *testing.T) {
	_, err := decodeHexRuntimeArgs(map[string]string{"recipient": "s3cretzz"})
	if err == nil {
		t.Fatal("expected invalid hex error")
	}
	if !strings.Contains(err.Error(), "recipient") {
		t.Fatalf("error %q does not include argument name", err)
	}
	for _, part := range []string{"s3cret", "'s'", "'z'", "U+", "invalid byte"} {
		if strings.Contains(err.Error(), part) {
			t.Fatalf("error %q quotes the value (%q)", err, part)
		}
	}
}

// An odd number of digits says so: that error names no part of the value.
func TestDecodeHexRuntimeArgsReportsAnOddLength(t *testing.T) {
	_, err := decodeHexRuntimeArgs(map[string]string{"recipient": "abc"})
	if err == nil || !strings.Contains(err.Error(), "recipient") || !strings.Contains(err.Error(), "odd length") {
		t.Fatalf("error = %v, want the argument named and the odd length", err)
	}
}

func TestHostDerivedArgsMerkleProof(t *testing.T) {
	sender := types.Address{1}
	receiver := types.Address{2}
	secondReceiver := types.Address{3}
	recipients := strings.Join([]string{secondReceiver.String(), receiver.String()}, ",")
	root, err := merkleallowlist.RootFromRecipientsParam(recipients)
	if err != nil {
		t.Fatalf("RootFromRecipientsParam() error = %v", err)
	}
	keyMaterial := &coresigning.KeyMaterial{
		Parameters: map[string]string{"recipients": recipients},
	}
	metadata := merkleDerivedMetadata()

	for _, tc := range []struct {
		name string
		txn  types.Transaction
	}{
		{
			name: "payment",
			txn: types.Transaction{
				Type:   types.PaymentTx,
				Header: types.Header{Sender: sender},
				PaymentTxnFields: types.PaymentTxnFields{
					Receiver: receiver,
				},
			},
		},
		{
			name: "asset transfer",
			txn: types.Transaction{
				Type:   types.AssetTransferTx,
				Header: types.Header{Sender: sender},
				AssetTransferTxnFields: types.AssetTransferTxnFields{
					AssetReceiver: receiver,
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args, signErr := hostDerivedArgs(tc.txn, keyMaterial, metadata, hostPathPureSpend)
			if signErr != nil {
				t.Fatalf("hostDerivedArgs() error = %v", signErr)
			}
			if len(args) != 1 {
				t.Fatalf("hostDerivedArgs() len = %d, want 1", len(args))
			}
			if len(args["merkle_proof"]) != merkleallowlist.ProofSize {
				t.Fatalf("proof length = %d, want %d", len(args["merkle_proof"]), merkleallowlist.ProofSize)
			}
			if !merkleallowlist.Verify(receiver, args["merkle_proof"], root) {
				t.Fatalf("generated proof did not verify for %s", receiver.String())
			}
		})
	}
}

func TestHostDerivedArgsMerkleProofSkipsSelfTransfer(t *testing.T) {
	sender := types.Address{1}
	keyMaterial := &coresigning.KeyMaterial{
		Parameters: map[string]string{"recipients": sender.String()},
	}
	args, signErr := hostDerivedArgs(types.Transaction{
		Type:   types.PaymentTx,
		Header: types.Header{Sender: sender},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: sender,
		},
	}, keyMaterial, merkleDerivedMetadata(), hostPathPureSpend)
	if signErr != nil {
		t.Fatalf("hostDerivedArgs() error = %v", signErr)
	}
	if proof, ok := args["merkle_proof"]; len(args) != 1 || !ok || proof != nil {
		t.Fatalf("hostDerivedArgs() = %#v, want one empty derived slot", args)
	}
}

func TestHostDerivedArgsMerkleProofRejectsNonMember(t *testing.T) {
	sender := types.Address{1}
	receiver := types.Address{2}
	keyMaterial := &coresigning.KeyMaterial{
		Parameters: map[string]string{"recipients": types.Address{3}.String()},
	}
	_, signErr := hostDerivedArgs(types.Transaction{
		Type:   types.PaymentTx,
		Header: types.Header{Sender: sender},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: receiver,
		},
	}, keyMaterial, merkleDerivedMetadata(), hostPathPureSpend)
	if signErr == nil {
		t.Fatal("hostDerivedArgs() error = nil, want rejection")
		return
	}
	if signErr.Kind != ErrorBadRequest {
		t.Fatalf("error kind = %q, want %q", signErr.Kind, ErrorBadRequest)
	}
	if !strings.Contains(signErr.Message, "not in allowlist") {
		t.Fatalf("error message = %q, want allowlist context", signErr.Message)
	}
}

func TestHostDerivedArgsMerkleProofForbiddenOnRekey(t *testing.T) {
	args, err := hostDerivedArgs(types.Transaction{}, &coresigning.KeyMaterial{}, merkleDerivedMetadata(), hostPathSpendingKeyRekey)
	if err != nil {
		t.Fatalf("hostDerivedArgs() error = %v", err)
	}
	if proof, ok := args["merkle_proof"]; len(args) != 1 || !ok || proof != nil {
		t.Fatalf("hostDerivedArgs() = %#v, want one empty derived slot", args)
	}
}

func merkleDerivedMetadata() *hostmeta.Metadata {
	return &hostmeta.Metadata{DerivedArgs: []hostmeta.DerivedArg{{
		Name: "merkle_proof", Kind: hostmeta.DerivedArgMerkleProof,
		Parameter: "recipients", MaxSize: hostmeta.MerkleProofSize,
	}}}
}
