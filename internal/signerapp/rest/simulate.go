// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rest

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	signersigning "github.com/aplane-algo/aplane/internal/signerapp/signing"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

func (s Service) Simulate(ctx context.Context, ir *identity.Runtime, req signerapi.GroupSignRequest) (*signerapi.GroupSimulateResponse, *signersigning.ServiceError) {
	ctx, preErr := ensureSignable(ctx, ir)
	if preErr != nil {
		return nil, preErr
	}
	if roleErr := requireAccountSigningRole(ir, "simulation signing"); roleErr != nil {
		return nil, roleErr
	}
	if s.Deps.NewSigningService == nil {
		return nil, notConfigured("signing service")
	}
	if s.Deps.EncodeTxnHex == nil {
		return nil, notConfigured("transaction encoder")
	}
	if s.Deps.SimulateSignedGroup == nil {
		return nil, notConfigured("simulation service")
	}

	session := ir.SnapshotKeySession()
	result, err := s.Deps.NewSigningService(ir).SignGroupForSimulationWithContext(ctx, ir.ID(), req, session)
	if err != nil {
		return nil, err
	}
	if result.Mutations != nil && result.Mutations.ForeignCount > 0 {
		return nil, &signersigning.ServiceError{
			Kind:    signersigning.ErrorBadRequest,
			Message: fmt.Sprintf("/simulate cannot execute %d unsigned foreign placeholder slot(s); provide signed passthrough entries instead", result.Mutations.ForeignCount),
		}
	}

	signedTxns, finalTxnHexes, decErr := decodeSignedTxnHexes(result.Signed, s.Deps.EncodeTxnHex)
	if decErr != nil {
		return nil, &signersigning.ServiceError{Kind: signersigning.ErrorInternal, Message: decErr.Error()}
	}

	txIDs, output, failed, err := s.Deps.SimulateSignedGroup(ctx, signedTxns)
	if err != nil {
		return nil, err
	}

	return &signerapi.GroupSimulateResponse{
		TxIDs:        txIDs,
		Transactions: finalTxnHexes,
		Mutations:    result.Mutations,
		Output:       output,
		Failed:       failed,
	}, nil
}

// SimulateGuarded runs the contained guarded simulation flow: user component
// signatures are produced and consumed inside the signer, the assembled group
// is simulated against the signer's algod, and only transaction IDs, final
// unsigned transactions, and the simulation report are returned.
func (s Service) SimulateGuarded(ctx context.Context, ir *identity.Runtime, req signerapi.GuardedSimulateRequest) (*signerapi.GuardedSimulateResponse, *signersigning.ServiceError) {
	ctx, preErr := ensureSignable(ctx, ir)
	if preErr != nil {
		return nil, preErr
	}
	if roleErr := requireAccountSigningRole(ir, "guarded simulation signing"); roleErr != nil {
		return nil, roleErr
	}
	if s.Deps.NewSigningService == nil {
		return nil, notConfigured("signing service")
	}
	if s.Deps.EncodeTxnHex == nil {
		return nil, notConfigured("transaction encoder")
	}
	if s.Deps.SimulateSignedGroup == nil {
		return nil, notConfigured("simulation service")
	}

	session := ir.SnapshotKeySession()
	assembly, err := s.Deps.NewSigningService(ir).AssembleGuardedForSimulationWithContext(ctx, ir.ID(), req, session)
	if err != nil {
		return nil, err
	}

	signedTxns, finalTxnHexes, decErr := decodeSignedTxnHexes(assembly.SignedGroup, s.Deps.EncodeTxnHex)
	if decErr != nil {
		return nil, &signersigning.ServiceError{Kind: signersigning.ErrorInternal, Message: decErr.Error()}
	}

	txIDs, output, failed, err := s.Deps.SimulateSignedGroup(ctx, signedTxns)
	if err != nil {
		return nil, err
	}

	return &signerapi.GuardedSimulateResponse{
		RequestID:    assembly.RequestID,
		TxIDs:        txIDs,
		Transactions: finalTxnHexes,
		Output:       output,
		Failed:       failed,
	}, nil
}

func decodeSignedTxnHexes(signedHexes []string, encodeTxnHex func(types.Transaction) string) ([]types.SignedTxn, []string, error) {
	signedTxns := make([]types.SignedTxn, len(signedHexes))
	txnHexes := make([]string, len(signedHexes))
	for i, signedHex := range signedHexes {
		raw, err := hex.DecodeString(signedHex)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode signed transaction %d: %w", i+1, err)
		}
		var signedTxn types.SignedTxn
		if err := msgpack.Decode(raw, &signedTxn); err != nil {
			return nil, nil, fmt.Errorf("failed to decode signed transaction %d: %w", i+1, err)
		}
		signedTxns[i] = signedTxn
		txnHexes[i] = encodeTxnHex(signedTxn.Txn)
	}
	return signedTxns, txnHexes, nil
}
