// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/aplocalnet"
)

func TestModelViewShowsConfiguredKMDURL(t *testing.T) {
	m := newModel(aplocalnet.Options{
		AlgodURL: "http://localhost:4001",
		KMDURL:   "http://localhost:4012",
	})
	m.busy = false

	view := m.View()
	if !strings.Contains(view, "http://localhost:4012") {
		t.Fatalf("view missing KMD URL:\n%s", view)
	}
	if strings.Contains(view, "u algod URL") {
		t.Fatalf("view still advertises interactive algod URL edit:\n%s", view)
	}
	if !strings.Contains(view, "apply") || strings.Contains(view, "enter setup") {
		t.Fatalf("view should label the primary action as apply:\n%s", view)
	}
}

func TestApplyTargetSpecifiedUsesFlagsOrEnv(t *testing.T) {
	t.Setenv("APCLIENT_DATA", "")
	t.Setenv("APSIGNER_DATA", "")
	if clientTargetSpecified("") {
		t.Fatal("client target unexpectedly specified")
	}
	if signerTargetSpecified("") {
		t.Fatal("signer target unexpectedly specified")
	}
	if !clientTargetSpecified("/tmp/client") {
		t.Fatal("client flag should specify a client target")
	}
	if !signerTargetSpecified("/tmp/signer") {
		t.Fatal("signer flag should specify a signer target")
	}

	t.Setenv("APCLIENT_DATA", "/tmp/client-env")
	t.Setenv("APSIGNER_DATA", "/tmp/signer-env")
	if !clientTargetSpecified("") {
		t.Fatal("APCLIENT_DATA should specify a client target")
	}
	if !signerTargetSpecified("") {
		t.Fatal("APSIGNER_DATA should specify a signer target")
	}
}
