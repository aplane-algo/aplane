// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"context"

	signersigning "github.com/aplane-algo/aplane/internal/signerapp/signing"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

func (fs *Signer) simulateSignedGroup(ctx context.Context, signedTxns []types.SignedTxn) ([]string, string, bool, *signersigning.ServiceError) {
	return fs.simulator().SimulateSignedGroup(ctx, signedTxns)
}

func (fs *Signer) simulator() signersigning.Simulator {
	return signersigning.Simulator{
		Config:    fs.ConfigSnapshot,
		MakeAlgod: fs.makeAlgod,
	}
}
