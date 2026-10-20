// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package stage

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/algo"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
)

// TestDumpTemplate regenerates template_bytes.go from algod's assembler when
// XMSS_TEMPLATE_OUT names the file to write, after a change to tealTemplate:
//
//	XMSS_TEMPLATE_OUT=lsig/rotatingxmsstriple/stage/template_bytes.go \\
//	  go test ./lsig/rotatingxmsstriple/stage/ -run TestDumpTemplate
//
// It needs an algod (ALGOD_URL or TEAL_COMPILE_ALGOD_URL).
func TestDumpTemplate(t *testing.T) {
	out := os.Getenv("XMSS_TEMPLATE_OUT")
	if out == "" {
		t.Skip("XMSS_TEMPLATE_OUT not set")
	}
	client, err := algod.MakeClient(algo.ResolveTEALCompileAlgodURL(), algo.ResolveTEALCompileAlgodToken())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	keys := &PublicKeys{}
	for i := range keys.Ed25519 {
		keys.Ed25519[i], keys.Root[i], keys.Seed[i] = fillEd25519, fillRoot, fillSeed
	}
	for i := range keys.Falcon {
		keys.Falcon[i] = fillFalcon
	}
	keys.Lo = binary.BigEndian.Uint64(bytes.Repeat([]byte{fillLo}, 8))
	keys.Hi = binary.BigEndian.Uint64(bytes.Repeat([]byte{fillHi}, 8))
	result, err := client.TealCompile([]byte(TEALSource(keys))).Do(ctx)
	if err != nil {
		t.Fatalf("TealCompile: %v", err)
	}
	got, err := base64.StdEncoding.DecodeString(result.Result)
	if err != nil {
		t.Fatal(err)
	}
	// The v13 assembler salts an on-curve program with a trailing intcblock.
	if n := len(got); n > 3 && got[n-3] == opIntcblock && got[n-2] == 1 {
		got = got[:n-3]
		t.Logf("stripped the assembler's salt tail")
	}
	var b strings.Builder
	b.WriteString("// SPDX-License-Identifier: AGPL-3.0-or-later\n// Copyright (C) 2026 APlane Project LLC\n\npackage stage\n\n")
	b.WriteString("// UnsaltedProgramSize is the size of the frozen template; the salted form\n// adds the three-byte intcblock tail.\n")
	fmt.Fprintf(&b, "const UnsaltedProgramSize = %d\n\n", len(got))
	b.WriteString("// template is the stock v13 assembly of TEALSource with placeholder\n// constants: 0x33.. for the Ed25519 key, 0x44.. for the Falcon key, 0x11..\n// for the seed (inside the toByte(3) || SEED constant), 0x22.. for the root,\n// 0x55.. for the low range bound and 0x66.. for the high one. It is frozen;\n// TestBuildMatchesStockAssembler re-derives it from TEALSource.\n")
	b.WriteString("var template = [UnsaltedProgramSize]byte{\n")
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
	if err := os.WriteFile(out, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s: %d bytes", out, len(got))
}
