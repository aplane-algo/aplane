// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"bytes"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/merkleallowlist"
	coresigning "github.com/aplane-algo/aplane/internal/signing"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestDecodeHexRuntimeArgs(t *testing.T) {
	decoded, err := DecodeHexRuntimeArgs(map[string]string{
		"recipient": "001122",
		"secret":    "aabbcc",
	})
	if err != nil {
		t.Fatalf("DecodeHexRuntimeArgs: %v", err)
	}
	if got := decoded["recipient"]; !bytes.Equal(got, []byte{0x00, 0x11, 0x22}) {
		t.Fatalf("recipient = %x, want 001122", got)
	}
	if got := decoded["secret"]; !bytes.Equal(got, []byte{0xaa, 0xbb, 0xcc}) {
		t.Fatalf("secret = %x, want aabbcc", got)
	}
}

func TestDecodeHexRuntimeArgsEmpty(t *testing.T) {
	decoded, err := DecodeHexRuntimeArgs(nil)
	if err != nil {
		t.Fatalf("DecodeHexRuntimeArgs(nil): %v", err)
	}
	if decoded != nil {
		t.Fatalf("DecodeHexRuntimeArgs(nil) = %#v, want nil", decoded)
	}

	decoded, err = DecodeHexRuntimeArgs(map[string]string{})
	if err != nil {
		t.Fatalf("DecodeHexRuntimeArgs(empty): %v", err)
	}
	if decoded != nil {
		t.Fatalf("DecodeHexRuntimeArgs(empty) = %#v, want nil", decoded)
	}
}

func TestDecodeHexRuntimeArgsReportsArgumentName(t *testing.T) {
	_, err := DecodeHexRuntimeArgs(map[string]string{"recipient": "not-hex"})
	if err == nil {
		t.Fatal("expected invalid hex error")
	}
	if !strings.Contains(err.Error(), "recipient") {
		t.Fatalf("error %q does not include argument name", err)
	}
	if !strings.Contains(err.Error(), "invalid byte") {
		t.Fatalf("error %q does not include hex decode context", err)
	}
}

func TestSignerGeneratedDSAArgsFalconAllowlistV2Proof(t *testing.T) {
	sender := types.Address{1}
	receiver := types.Address{2}
	secondReceiver := types.Address{3}
	recipients := strings.Join([]string{secondReceiver.String(), receiver.String()}, ",")
	root, err := merkleallowlist.RootFromRecipientsParam(recipients)
	if err != nil {
		t.Fatalf("RootFromRecipientsParam() error = %v", err)
	}
	keyMaterial := &coresigning.KeyMaterial{
		Type:       falcon1024AllowlistV2KeyType,
		Parameters: map[string]string{"recipients": recipients},
	}

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
			args, signErr := signerGeneratedDSAArgs(tc.txn, keyMaterial)
			if signErr != nil {
				t.Fatalf("signerGeneratedDSAArgs() error = %v", signErr)
			}
			if len(args) != 1 {
				t.Fatalf("signerGeneratedDSAArgs() len = %d, want 1", len(args))
			}
			if len(args[0]) != merkleallowlist.ProofSize {
				t.Fatalf("proof length = %d, want %d", len(args[0]), merkleallowlist.ProofSize)
			}
			if !merkleallowlist.Verify(receiver, args[0], root) {
				t.Fatalf("generated proof did not verify for %s", receiver.String())
			}
		})
	}
}

func TestSignerGeneratedDSAArgsFalconAllowlistV2SkipsSelfTransfer(t *testing.T) {
	sender := types.Address{1}
	keyMaterial := &coresigning.KeyMaterial{
		Type:       falcon1024AllowlistV2KeyType,
		Parameters: map[string]string{"recipients": sender.String()},
	}
	args, signErr := signerGeneratedDSAArgs(types.Transaction{
		Type:   types.PaymentTx,
		Header: types.Header{Sender: sender},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: sender,
		},
	}, keyMaterial)
	if signErr != nil {
		t.Fatalf("signerGeneratedDSAArgs() error = %v", signErr)
	}
	if args != nil {
		t.Fatalf("signerGeneratedDSAArgs() = %#v, want nil", args)
	}
}

func TestSignerGeneratedDSAArgsFalconAllowlistV2RejectsNonMember(t *testing.T) {
	sender := types.Address{1}
	receiver := types.Address{2}
	keyMaterial := &coresigning.KeyMaterial{
		Type:       falcon1024AllowlistV2KeyType,
		Parameters: map[string]string{"recipients": types.Address{3}.String()},
	}
	_, signErr := signerGeneratedDSAArgs(types.Transaction{
		Type:   types.PaymentTx,
		Header: types.Header{Sender: sender},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: receiver,
		},
	}, keyMaterial)
	if signErr == nil {
		t.Fatal("signerGeneratedDSAArgs() error = nil, want rejection")
	}
	if signErr.Kind != ErrorBadRequest {
		t.Fatalf("error kind = %q, want %q", signErr.Kind, ErrorBadRequest)
	}
	if !strings.Contains(signErr.Message, "not in allowlist") {
		t.Fatalf("error message = %q, want allowlist context", signErr.Message)
	}
}
