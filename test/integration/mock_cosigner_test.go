// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/aplane-algo/aplane/internal/cosigner/canonical"
	"github.com/aplane-algo/aplane/internal/cosigner/message"
	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/lsig/falcon1024/signerops"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// mockCosignerEndpoint behaves like a cosigner node for one cosigner key: it
// advertises the Witness Key ID on /keys (so the client's
// endpoint-advertisement check passes) and produces real cosigner-role
// component signatures on /sign/component using the test-held private key.
// The handler is served behind an in-process SSH node, as a real cosigner is.
func mockCosignerEndpoint(
	t *testing.T,
	publicKey, privateKey []byte,
	discoveryCalls *atomic.Int32,
) http.Handler {
	t.Helper()
	componentSelector, err := witness.ID(witness.Falcon1024V1, publicKey)
	if err != nil {
		t.Fatalf("Failed to derive Witness Key ID: %v", err)
	}
	publicKeyHex := hex.EncodeToString(publicKey)

	mux := http.NewServeMux()
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		discoveryCalls.Add(1)
		_ = json.NewEncoder(w).Encode(signerapi.KeysResponse{
			Count: 1,
			Keys: []signerapi.KeyInfo{{
				Address:      componentSelector,
				PublicKeyHex: publicKeyHex,
				KeyType:      witness.Falcon1024V1,
				IsWitnessKey: true,
			}},
		})
	})
	mux.HandleFunc("/sign/component", func(w http.ResponseWriter, r *http.Request) {
		var req signerapi.ComponentRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.TargetKind() != signerapi.ComponentTargetKindCosigner || len(req.Targets) == 0 || req.Targets[0].ComponentKey != componentSelector {
			http.Error(w, "wrong Witness Key ID", http.StatusBadRequest)
			return
		}
		group, err := canonical.DecodeGroupHex(req.GroupBytesHex)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp := signerapi.ComponentResponse{
			RequestID:  req.RequestID,
			Components: make([]signerapi.Component, 0, len(req.Targets)),
		}
		for _, target := range req.Targets {
			index := target.TargetIndex
			if index < 0 || index >= len(group.Entries) {
				http.Error(w, "target index out of range", http.StatusBadRequest)
				return
			}
			msg := message.ComponentMessage(message.RoleCosigner, group.Entries[index].TxID)
			signature, err := signerops.New(nil).Sign(privateKey, msg[:])
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			resp.Components = append(resp.Components, signerapi.Component{
				TargetIndex:     index,
				Kind:            signerapi.ComponentTargetKindCosigner,
				SignatureScheme: witness.Falcon1024V1,
				Signature:       hex.EncodeToString(signature),
			})
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	return mux
}
