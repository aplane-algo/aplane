// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rest

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/cosigner/cosignerrefs"
	"github.com/aplane-algo/aplane/internal/cosigner/keytypes"
	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/lsig/boundedaccount"
)

// A per-key type has no contract of its own to report, and its cosigner is
// optional, so a store with references must not turn the field into a required
// selector with a default: that would add a cosigner to every account.
func TestPerKeyTypeKeepsItsCosignerOptional(t *testing.T) {
	boundedaccount.RegisterClient()
	ir := setupProductRuntime(t, false)
	publicKey := strings.Repeat("61", 1793)
	raw, err := hex.DecodeString(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := witness.ID(witness.Falcon1024V1, raw)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := cosignerrefs.NewExportEnvelope(keyID, witness.Falcon1024V1, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cosignerrefs.Import(ir.KeyPaths(), "ops", data); err != nil {
		t.Fatal(err)
	}

	infos := Service{}.buildKeyTypes([]string{boundedaccount.KeyTypeV1}, nil)
	applyCosignerReferenceParams(ir, infos)
	if len(infos) != 1 {
		t.Fatalf("buildKeyTypes() = %+v", infos)
	}
	info := infos[0]
	if !info.PerKeyContract || info.SigningFlow != "" || info.BoundedAuthorization != nil {
		t.Fatalf("per-key type reports a fixed contract: %+v", info)
	}
	if info.CosignerComponentKeyType != witness.Falcon1024V1 {
		t.Fatalf("cosigner component = %q", info.CosignerComponentKeyType)
	}
	for _, param := range info.CreationParams {
		if param.Name == cosignerrefs.ParamCosignerName {
			t.Fatalf("the cosigner became a selector: %+v", param)
		}
		if param.Name == keytypes.ParameterCosignerPublicKey && param.Required {
			t.Fatal("the cosigner became required")
		}
	}
}
