// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
)

func TestRenderGenerateDisplayLabelsSentryKey(t *testing.T) {
	rendered := stripANSI(Model{
		initialNodeRole: "sentry",
		forms:           formsState{generatedAddress: "SENTRYKEY", generatedKeyType: keytypes.SentryComponentFalcon1024V1},
	}.renderGenerateDisplay())
	if !strings.Contains(rendered, "Sentry Key: SENTRYKEY") {
		t.Fatalf("renderGenerateDisplay() missing sentry key label:\n%s", rendered)
	}
	if strings.Contains(rendered, "Address: SENTRYKEY") {
		t.Fatalf("renderGenerateDisplay() used address label in sentry mode:\n%s", rendered)
	}
}

func TestRenderGenerateDisplayLabelsSignerAddress(t *testing.T) {
	rendered := stripANSI(Model{forms: formsState{generatedAddress: "ADDR", generatedKeyType: "ed25519"}}.renderGenerateDisplay())
	if !strings.Contains(rendered, "Address: ADDR") {
		t.Fatalf("renderGenerateDisplay() missing address label:\n%s", rendered)
	}
}
