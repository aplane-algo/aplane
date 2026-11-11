// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/cosigner/canonical"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/sigconstruction"
	sigverify "github.com/aplane-algo/aplane/internal/sigconstruction/verify"
	"github.com/aplane-algo/aplane/pkg/signerapi"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

func assembleDecoded(ctx context.Context, req signerapi.AssemblyRequest, group *canonical.Group, session componentKeyGetter) (*AssemblyResult, *ServiceError) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, canceledSignRequest(err)
	}
	if group == nil {
		return nil, internal("cosigned assembly group is nil")
	}
	if err := req.Validate(); err != nil {
		return nil, badRequest(err.Error())
	}
	if len(group.Entries) != len(req.GroupBytesHex) {
		return nil, internal("cosigned assembly group length does not match request")
	}
	if session == nil {
		return nil, internal("key session is nil")
	}

	signedGroup := make([]string, len(group.Entries))
	for _, target := range req.Targets {
		var signedTxnHex string
		var err *ServiceError
		switch target.Kind {
		case signerapi.AssemblyTargetKindBoundedCosigner:
			signedTxnHex, err = assembleBoundedTarget(ctx, target, group.Entries[target.TargetIndex], session)
		default:
			return nil, badRequest("unsupported assembly target kind")
		}
		if err != nil {
			return nil, err
		}
		signedGroup[target.TargetIndex] = signedTxnHex
	}
	for _, passthrough := range req.Passthrough {
		signedTxnHex, err := validateCosignedPassthrough(ctx, passthrough, group.Entries[passthrough.TargetIndex], session)
		if err != nil {
			return nil, err
		}
		signedGroup[passthrough.TargetIndex] = signedTxnHex
	}

	return &AssemblyResult{
		RequestID:   req.RequestID,
		SignedGroup: signedGroup,
	}, nil
}

func validateCosignedPassthrough(ctx context.Context, passthrough signerapi.AssemblyPassthroughItem, entry canonical.Txn, session componentKeyGetter) (string, *ServiceError) {
	signedTxnBytes, err := decodeAssemblySignatureHex(passthrough.SignedTxnHex, "signed_txn_hex")
	if err != nil {
		return "", err
	}

	// One rule for forwarded signed bytes, shared with /sign passthrough:
	// they must be the canonical encoding of what they decode to. The decoder
	// reports that here; the refusal for it stays last, after the checks
	// below, so the order of refusals is unchanged.
	stxn, decodeErr := canonical.DecodeSignedTxn(signedTxnBytes)
	notCanonical := errors.Is(decodeErr, canonical.ErrNotCanonical)
	if decodeErr != nil && !notCanonical {
		return "", badRequest(fmt.Sprintf("passthrough index %d: invalid signed transaction msgpack", passthrough.TargetIndex))
	}
	txID := algocrypto.TransactionID(stxn.Txn)
	if !bytes.Equal(txID[:], entry.TxID[:]) {
		return "", badRequest(fmt.Sprintf("passthrough index %d signed transaction does not match group transaction", passthrough.TargetIndex))
	}
	// A cosigned account this signer holds must be authorized through the
	// component and assembly flow (spending key and cosigner), never slipped in
	// as a passthrough that bypasses that verification. Reject if the
	// passthrough's effective signer is a locally held cosigned account.
	if err := rejectLocalCosignedPassthrough(ctx, stxn, passthrough.TargetIndex, session); err != nil {
		return "", err
	}
	// A passthrough slot must carry a real signature: the signer contributes no
	// authority of its own, so an unsigned SignedTxn{Txn:...} would assemble a
	// group leg nobody authorized. Reject any blank-signature passthrough.
	if !signedTxnHasSignature(stxn) {
		return "", badRequest(fmt.Sprintf("passthrough index %d signed transaction carries no signature", passthrough.TargetIndex))
	}
	// A non-canonical SignedTxn cannot be submitted.
	if notCanonical {
		return "", badRequest(fmt.Sprintf("passthrough index %d signed transaction bytes are not canonical", passthrough.TargetIndex))
	}
	return hex.EncodeToString(signedTxnBytes), nil
}

// rejectLocalCosignedPassthrough rejects a passthrough whose effective signer
// (sender, or AuthAddr when rekeyed) is a cosigned account this signer holds:
// such an account must be authorized through component signing and assembly,
// not forwarded as an already-signed passthrough. Accounts this signer does
// not hold (the common passthrough case) are left alone.
func rejectLocalCosignedPassthrough(ctx context.Context, stxn types.SignedTxn, targetIndex int, session componentKeyGetter) *ServiceError {
	var zero types.Address
	candidates := []types.Address{stxn.Txn.Sender}
	if stxn.AuthAddr != zero {
		candidates = append(candidates, stxn.AuthAddr)
	}
	for _, addr := range candidates {
		if addr == zero {
			continue
		}
		km, err := session.GetKeyWithContext(ctx, addr.String())
		if err != nil {
			// Only a genuine not-found means this is a foreign passthrough. Any
			// other error (locked session, decrypt/storage failure) must fail
			// closed: treating it as "not held" would let a cosigned account slip
			// through as passthrough during exactly the conditions this check
			// guards against.
			if errors.Is(err, keystore.ErrKeyNotFound) {
				continue
			}
			return internal(fmt.Sprintf("passthrough index %d: failed to resolve key for %s: %v", targetIndex, addr.String(), err))
		}
		if km == nil {
			continue // not held by this signer — a legitimate foreign passthrough
		}
		cosigned := km.BoundedAuthorization != nil && km.BoundedAuthorization.Cosigner != nil
		zeroLoadedKeyMaterial(km)
		if cosigned {
			return badRequest(fmt.Sprintf("passthrough index %d requires component assembly and cannot be supplied as passthrough", targetIndex))
		}
	}
	return nil
}

// signedTxnHasSignature reports whether a SignedTxn carries any authorization
// proof, including native PQ authorization at the top level or inside a
// delegated LogicSig. /sign and /plan passthrough and /sign/assemble
// passthrough all ask it. A multisig, at the top level or delegating a
// LogicSig, counts only when at least one subsig is signed: one with none can
// never meet its threshold on chain. A LogicSig with a program and nothing
// else is an escrow (contract account) LogicSig and counts.
func signedTxnHasSignature(stxn types.SignedTxn) bool {
	if multisigWithoutSignature(stxn.Msig) || multisigWithoutSignature(stxn.Lsig.Msig) || multisigWithoutSignature(stxn.Lsig.LMsig) {
		return false
	}
	if stxn.Sig != (types.Signature{}) {
		return true
	}
	if len(stxn.Lsig.Logic) > 0 {
		return true
	}
	if !stxn.Msig.Blank() {
		return true
	}
	if !stxn.PQsig.Blank() || !stxn.Lsig.PQsig.Blank() {
		return true
	}
	return false
}

// multisigWithoutSignature reports whether msig is present but none of its
// subsigs carries a signature.
func multisigWithoutSignature(msig types.MultisigSig) bool {
	if msig.Blank() {
		return false
	}
	for _, subsig := range msig.Subsigs {
		if subsig.Sig != (types.Signature{}) {
			return false
		}
	}
	return true
}

func verifyCosignerAssemblySignature(componentKeyType string, publicKey, msg, signature []byte) error {
	construction, ok := sigconstruction.ForWitnessKeyType(componentKeyType)
	if !ok {
		return fmt.Errorf("key type %q is not a cosigner key type", componentKeyType)
	}
	return sigverify.Verify(construction, publicKey, msg, signature)
}

func decodeAssemblySignatureHex(value, field string) ([]byte, *ServiceError) {
	decoded, err := decodeHexBytes(value, -1, field)
	if err != nil {
		return nil, badRequest(err.Error())
	}
	return decoded, nil
}

func decodeHexBytes(value string, wantLen int, field string) ([]byte, error) {
	raw := strings.TrimSpace(value)
	raw = strings.TrimPrefix(strings.TrimPrefix(raw, "0x"), "0X")
	decoded, err := hex.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("%s must be hex: %w", field, err)
	}
	if wantLen >= 0 && len(decoded) != wantLen {
		return nil, fmt.Errorf("%s length %d invalid (expected %d bytes)", field, len(decoded), wantLen)
	}
	return decoded, nil
}
