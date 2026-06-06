// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"os/exec"
	"strings"
	"testing"
)

func TestGeneratedReferenceHidesLegacyApshellRouting(t *testing.T) {
	cmd := exec.Command("go", "run", ".")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go run . error = %v", err)
	}

	doc := string(out)
	apshellConfig := sectionBetween(t, doc, "## apshell Configuration", "## apshell Endpoint Registry")
	for _, forbidden := range []string{"| `signer_port` |", "| `ssh` |", "| `ssh.host` |"} {
		if strings.Contains(apshellConfig, forbidden) {
			t.Fatalf("apshell config section contains legacy routing field %q\n%s", forbidden, apshellConfig)
		}
	}
	for _, want := range []string{
		"## apshell Endpoint Registry",
		"`endpoints.<alias>.role`",
		"`endpoints.<alias>.token_file`",
		"routing metadata, not trust proof",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("generated reference missing %q", want)
		}
	}
}

func sectionBetween(t *testing.T, s, start, end string) string {
	t.Helper()
	startIdx := strings.Index(s, start)
	if startIdx < 0 {
		t.Fatalf("missing section start %q", start)
	}
	endIdx := strings.Index(s[startIdx+len(start):], end)
	if endIdx < 0 {
		t.Fatalf("missing section end %q", end)
	}
	return s[startIdx : startIdx+len(start)+endIdx]
}
