// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signingargs

import (
	"encoding/json"
	"testing"

	"github.com/aplane-algo/aplane/internal/lsigprovider"
)

func TestRuntimeDefProjectionRoundTrip(t *testing.T) {
	defs := []lsigprovider.RuntimeArgDef{{
		Name:        "preimage",
		Label:       "Preimage",
		Description: "Hash preimage",
		Type:        "bytes",
		Required:    true,
		ByteLength:  32,
	}}

	info := FromRuntimeDefs(defs)
	if len(info) != 1 {
		t.Fatalf("FromRuntimeDefs returned %d args, want 1", len(info))
	}
	if info[0].Name != defs[0].Name || info[0].ByteLength != defs[0].ByteLength {
		t.Fatalf("projected info = %#v, want %#v", info[0], defs[0])
	}

	got := ToRuntimeDefs(info)
	if len(got) != 1 || got[0] != defs[0] {
		t.Fatalf("ToRuntimeDefs = %#v, want %#v", got, defs)
	}
}

func TestInfoJSONShape(t *testing.T) {
	b, err := json.Marshal(Info{Name: "secret", Type: "bytes"})
	if err != nil {
		t.Fatalf("Marshal error = %v", err)
	}
	const want = `{"name":"secret","type":"bytes"}`
	if string(b) != want {
		t.Fatalf("JSON = %s, want %s", b, want)
	}

	var got Info
	if err := json.Unmarshal([]byte(`{"name":"secret","label":"Secret","type":"bytes","required":true,"byte_length":32}`), &got); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}
	wantInfo := Info{Name: "secret", Label: "Secret", Type: "bytes", Required: true, ByteLength: 32}
	if got != wantInfo {
		t.Fatalf("Info = %#v, want %#v", got, wantInfo)
	}
}
