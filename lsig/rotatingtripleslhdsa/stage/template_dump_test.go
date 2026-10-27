// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package stage

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/algo"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
)

// TestDumpTemplate regenerates template_h<height>.go for every supported
// shape from algod's assembler when SLHDSA_TEMPLATE_DIR names the stage
// package directory to write into, after a change to a verifier source:
//
//	SLHDSA_TEMPLATE_DIR=$PWD/lsig/rotatingtripleslhdsa/stage \
//	  go test ./lsig/rotatingtripleslhdsa/stage/ -run TestDumpTemplate
//
// It needs an algod (ALGOD_URL or TEAL_COMPILE_ALGOD_URL). Every shape is
// regenerated, not only the selected one, so the unselected shape's
// template never goes stale.
func TestDumpTemplate(t *testing.T) {
	dir := os.Getenv("SLHDSA_TEMPLATE_DIR")
	if dir == "" {
		t.Skip("SLHDSA_TEMPLATE_DIR not set")
	}
	client, err := algod.MakeClient(algo.ResolveTEALCompileAlgodURL(), algo.ResolveTEALCompileAlgodToken())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
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
	heights := make([]int, 0, len(hypertrees))
	for h := range hypertrees {
		heights = append(heights, h)
	}
	sort.Ints(heights)
	for _, h := range heights {
		src, _ := tealSource(h, keys)
		result, err := client.TealCompile([]byte(src)).Do(ctx)
		if err != nil {
			t.Fatalf("height %d: TealCompile: %v", h, err)
		}
		got, err := base64.StdEncoding.DecodeString(result.Result)
		if err != nil {
			t.Fatal(err)
		}
		// The v13 assembler salts an on-curve program with a trailing intcblock.
		if n := len(got); n > 3 && got[n-3] == opIntcblock && got[n-2] == 1 {
			got = got[:n-3]
			t.Logf("height %d: stripped the assembler's salt tail", h)
		}
		var b strings.Builder
		b.WriteString("// SPDX-License-Identifier: AGPL-3.0-or-later\n// Copyright (C) 2026 APlane Project LLC\n\npackage stage\n\n")
		fmt.Fprintf(&b, "// templateH%d is the stock v13 assembly of verifier_h%d.teal with placeholder\n", h, h)
		b.WriteString("// constants: 0x33.. for the Ed25519 key, 0x44.. for the Falcon key, 0x11..\n// for the seed, 0x22.. for the root. It is frozen;\n// TestBuildMatchesStockAssembler re-derives the selected shape from TEALSource.\n")
		fmt.Fprintf(&b, "var templateH%d = []byte{ // %d bytes\n", h, len(got))
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
		out := filepath.Join(dir, fmt.Sprintf("template_h%d.go", h))
		if err := os.WriteFile(out, []byte(b.String()), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s: %d bytes", out, len(got))
	}
}
