// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package stage

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/algo"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
)

func placeholderKeys() *PublicKeys {
	keys := &PublicKeys{}
	for i := range keys.Ed25519 {
		keys.Ed25519[i] = fillEd25519
	}
	for i := range keys.Seed {
		keys.Seed[i], keys.Root[i] = fillSeed, fillRoot
	}
	for i := range keys.Falcon {
		keys.Falcon[i] = fillFalcon
	}
	return keys
}

// compile assembles source with algod's stock assembler.
func compile(t *testing.T, source string) []byte {
	t.Helper()
	client, err := algod.MakeClient(algo.ResolveTEALCompileAlgodURL(), algo.ResolveTEALCompileAlgodToken())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	result, err := client.TealCompile([]byte(source)).Do(ctx)
	if err != nil {
		t.Fatalf("TealCompile: %v", err)
	}
	got, err := base64.StdEncoding.DecodeString(result.Result)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// TestDumpTemplate regenerates template.go from algod's assembler when
// WOTSC_TEMPLATE_DIR names the stage package directory to write into, after a
// change to the verifier source:
//
//	WOTSC_TEMPLATE_DIR=$PWD/lsig/rotatingtriplewotsc/stage \
//	  go test ./lsig/rotatingtriplewotsc/stage/ -run TestDumpTemplate
//
// It needs an algod (ALGOD_URL or TEAL_COMPILE_ALGOD_URL).
func TestDumpTemplate(t *testing.T) {
	dir := os.Getenv("WOTSC_TEMPLATE_DIR")
	if dir == "" {
		t.Skip("WOTSC_TEMPLATE_DIR not set")
	}
	got := compile(t, TEALSource(placeholderKeys()))
	// The v13 assembler salts an on-curve program with a trailing intcblock.
	if n := len(got); n > 3 && got[n-3] == opIntcblock && got[n-2] == 1 {
		got = got[:n-3]
		t.Log("stripped the assembler's salt tail")
	}
	var b strings.Builder
	b.WriteString("// SPDX-License-Identifier: AGPL-3.0-or-later\n// Copyright (C) 2026 APlane Project LLC\n\npackage stage\n\n")
	b.WriteString("// template is the stock v13 assembly of verifier.teal with placeholder\n")
	b.WriteString("// constants: 0x33.. for the Ed25519 key, 0x44.. for the Falcon key, 0x11..\n")
	b.WriteString("// for the seed, 0x22.. for the root. It is frozen;\n// TestBuildMatchesStockAssembler re-derives it from TEALSource.\n")
	fmt.Fprintf(&b, "var template = []byte{ // %d bytes\n", len(got))
	for i := 0; i < len(got); i += 16 {
		b.WriteString("\t")
		for j := i; j < i+16 && j < len(got); j++ {
			fmt.Fprintf(&b, "0x%02x,", got[j])
			if j+1 < i+16 && j+1 < len(got) {
				b.WriteString(" ")
			}
		}
		b.WriteString("\n")
	}
	b.WriteString("}\n")
	out := filepath.Join(dir, "template.go")
	if err := os.WriteFile(out, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s: %d bytes", out, len(got))
}
