// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"bytes"
	"testing"

	boundedmessage "github.com/aplane-algo/aplane/internal/boundedadmin/message"
	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/cosigner/message"
	"github.com/aplane-algo/aplane/internal/sigconstruction"
	sigverify "github.com/aplane-algo/aplane/internal/sigconstruction/verify"
	coresigning "github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/lsig/falcon1024/signerops"
)

// Every role signs its own transcript for the same transaction, and a valid
// signature for one is refused for every other. The messages come from the
// production builders, so a change that made two of them collide, or that checked a
// proof against another role's message, fails here.
func TestBoundedTranscriptsAreRoleSeparated(t *testing.T) {
	ops := signerops.New(nil)
	keypair := func(first byte) ([]byte, []byte) {
		t.Helper()
		seed := make([]byte, 48)
		seed[0] = first
		public, private, err := ops.GenerateKeypair(seed)
		if err != nil {
			t.Fatal(err)
		}
		return public, private
	}
	spendingPublic, spendingPrivate := keypair(1)
	cosignerPublic, cosignerPrivate := keypair(2)
	adminPublic, adminPrivate := keypair(3)

	var txID [32]byte
	for i := range txID {
		txID[i] = byte(i + 1)
	}
	metadata := &boundedmeta.Metadata{Contract: boundedmeta.ContractV1, BaseSignatureArgLayout: layoutOf(sigconstruction.Falcon1024())}
	receipt, err := boundedAssemblyReceiptMessage("ACCOUNT", txID[:], metadata, nil)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := boundedmessage.AdminMessage(boundedmessage.OperationRekey, bytes.Repeat([]byte{0x5a}, boundedmeta.ProgramBindingSize), txID[:])
	if err != nil {
		t.Fatal(err)
	}
	userComponent := message.ComponentMessage(message.RoleUser, txID)
	cosignerComponent := message.ComponentMessage(message.RoleCosigner, txID)
	transcripts := map[string][]byte{
		"spend":              txID[:],
		"assembly receipt":   receipt[:],
		"user component":     userComponent[:],
		"cosigner component": cosignerComponent[:],
		"admin":              admin[:],
	}
	seen := map[string]string{}
	for name, transcript := range transcripts {
		if other, ok := seen[string(transcript)]; ok {
			t.Fatalf("%s and %s transcripts are the same bytes", name, other)
		}
		seen[string(transcript)] = name
	}

	sign := func(private []byte, transcript []byte) []byte {
		t.Helper()
		signature, err := ops.Sign(private, transcript)
		if err != nil {
			t.Fatal(err)
		}
		return signature
	}
	spending := &coresigning.KeyMaterial{BaseKeyType: plainFalcon1024LsigKeyType, PublicKey: spendingPublic, BoundedAuthorization: metadata}
	verifiers := map[string]func(transcript, signature []byte) bool{
		// The spending key signs the transaction and the assembly receipt; both are
		// checked by boundedSpendingProofVerifies.
		"spend": func(transcript, signature []byte) bool {
			return boundedSpendingProofVerifies(spending, boundedWorkflowCosigner, transcript, signature)
		},
		"assembly receipt": func(transcript, signature []byte) bool {
			return boundedSpendingProofVerifies(spending, boundedWorkflowCosigner, transcript, signature)
		},
		"cosigner component": func(transcript, signature []byte) bool {
			return verifyCosignerAssemblySignature(witness.Falcon1024V1, cosignerPublic, transcript, signature) == nil
		},
		// The admin signature is checked outside the signer, as the
		// external-admin authorization does: Falcon over the admin message.
		"admin": func(transcript, signature []byte) bool {
			return sigverify.Verify(sigconstruction.Falcon1024(), adminPublic, transcript, signature) == nil
		},
	}
	signers := map[string][]byte{
		"spend":              spendingPrivate,
		"assembly receipt":   spendingPrivate,
		"cosigner component": cosignerPrivate,
		"admin":              adminPrivate,
	}
	for role, verify := range verifiers {
		signature := sign(signers[role], transcripts[role])
		if !verify(transcripts[role], signature) {
			t.Fatalf("%s: a valid signature over its own transcript was refused", role)
		}
		for other, transcript := range transcripts {
			if other == role {
				continue
			}
			if verify(transcript, signature) {
				t.Errorf("%s signature verified as a %s transcript", role, other)
			}
		}
	}
}
