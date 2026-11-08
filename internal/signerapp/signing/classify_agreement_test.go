// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/txeffects"
	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/lsig/boundedaccount"
	falcon "github.com/aplane-algo/aplane/lsig/falcon1024"
)

// The planner moves to txeffects.ClassifyFor later. Until then this pins that the
// declaration-driven classifier makes the same decision as today's signer
// classifier, with the same refusal text, for every shape of the general grammar
// on every transaction type and danger-field combination.
func TestClassifyForAgreesWithTheSignerClassifier(t *testing.T) {
	falcon.RegisterClient()
	provider, err := boundedaccount.NewProvider()
	if err != nil {
		t.Fatal(err)
	}
	metadata := map[string]*boundedmeta.Metadata{
		"custom/refused":      testBoundedMetadata(t, ""),
		"custom/spending key": testBoundedMetadata(t, boundedmeta.AdminAuthorizationSpend),
	}
	for _, shape := range boundedaccount.Shapes() {
		spend := make([]string, len(shape.Spend))
		for i, effect := range shape.Spend {
			spend[i] = string(effect)
		}
		params := map[string]string{
			boundedaccount.ParameterSpendEffects:   strings.Join(spend, ","),
			boundedaccount.ParameterRekeyAuthority: shape.Rekey,
		}
		if shape.Encoding != "" {
			params[boundedaccount.ParameterListEncoding] = shape.Encoding
			params[boundedaccount.ParameterRecipients] = types.Address{1}.String()
		}
		if shape.Timelock {
			params[boundedaccount.ParameterUnlockRound] = "5"
		}
		if shape.Cosigner {
			params[boundedmeta.CosignerPublicKeyParameter] = strings.Repeat("41", boundedmeta.CosignerPublicKeySizeV1)
		}
		instance, err := provider.ResolveInstance(params)
		if err != nil {
			t.Fatalf("%s: %v", shape.Descriptor(), err)
		}
		md := boundedmeta.Clone(instance.Bounded)
		if md.Cosigner != nil {
			// Generation fills in the cosigner's key; the signer validates it.
			publicKey := bytes.Repeat([]byte{0x41}, boundedmeta.CosignerPublicKeySizeV1)
			md.Cosigner.PublicKeyHex = hex.EncodeToString(publicKey)
			if md.Cosigner.ComponentKeyID, err = witness.ID(md.Cosigner.ComponentKeyType, publicKey); err != nil {
				t.Fatal(err)
			}
		}
		metadata[shape.Descriptor()] = md
	}

	paths := map[boundedPath]txeffects.Path{
		boundedPathPureSpend:        txeffects.PathSpend,
		boundedPathSpendingKeyRekey: txeffects.PathSpendingRekey,
	}
	var sender, other types.Address
	sender[0], other[0] = 0x51, 0x52
	txTypes := []types.TxType{"", types.PaymentTx, types.KeyRegistrationTx, types.AssetConfigTx,
		types.AssetTransferTx, types.AssetFreezeTx, types.ApplicationCallTx, types.StateProofTx, types.HeartbeatTx}
	for name, md := range metadata {
		declaration, err := md.Declaration()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, txType := range txTypes {
			for _, self := range []bool{true, false} {
				for mask := 0; mask < 16; mask++ {
					for _, fee := range []uint64{1_000, md.MaxFee + 1} {
						txn := types.Transaction{Type: txType}
						txn.Sender, txn.Fee = sender, types.MicroAlgos(fee)
						if self {
							txn.Receiver, txn.AssetReceiver = sender, sender
						} else {
							txn.Receiver, txn.AssetReceiver, txn.Amount, txn.AssetAmount = other, other, 1_000, 1
						}
						if mask&1 != 0 {
							txn.RekeyTo = other
						}
						if mask&2 != 0 {
							txn.CloseRemainderTo = other
						}
						if mask&4 != 0 {
							txn.AssetCloseTo = other
						}
						if mask&8 != 0 {
							txn.AssetSender = other
						}
						label := fmt.Sprintf("%s / %q self=%v effects=%04b fee=%d", name, txType, self, mask, fee)
						path, signerErr := classifyBoundedPath(txn, md)
						decision, err := txeffects.ClassifyFor(txn, declaration)
						if err != nil {
							t.Fatalf("%s: ClassifyFor error %v", label, err)
						}
						if signerErr != nil {
							if signerErr.Kind != ErrorBadRequest || decision.Path != txeffects.PathRefused || decision.Reason != signerErr.Message {
								t.Fatalf("%s: signer refused %q (%s), ClassifyFor took %s with %q", label, signerErr.Message, signerErr.Kind, decision.Path, decision.Reason)
							}
							continue
						}
						if want, ok := paths[path]; !ok || decision.Path != want {
							t.Fatalf("%s: signer path %q, ClassifyFor path %q", label, path, decision.Path)
						}
					}
				}
			}
		}
	}
}
