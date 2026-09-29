// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/witness"
)

func TestRenderGenerateDisplayLabelsCosignerKey(t *testing.T) {
	rendered := stripANSI(Model{
		initialNodeRole: "cosigner",
		forms:           formsState{generatedAddress: "COSIGNERKEY", generatedKeyType: witness.Falcon1024V1},
	}.renderGenerateDisplay())
	if !strings.Contains(rendered, "Cosigner Key: COSIGNERKEY") {
		t.Fatalf("renderGenerateDisplay() missing cosigner key label:\n%s", rendered)
	}
	if strings.Contains(rendered, "Address: COSIGNERKEY") {
		t.Fatalf("renderGenerateDisplay() used address label in cosigner mode:\n%s", rendered)
	}
}

func TestRenderGenerateDisplayLabelsSignerAddress(t *testing.T) {
	rendered := stripANSI(Model{forms: formsState{generatedAddress: "ADDR", generatedKeyType: "ed25519"}}.renderGenerateDisplay())
	if !strings.Contains(rendered, "Address: ADDR") {
		t.Fatalf("renderGenerateDisplay() missing address label:\n%s", rendered)
	}
}
