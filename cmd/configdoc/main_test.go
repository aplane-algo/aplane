// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"os/exec"
	"strings"
	"testing"
)

func TestGeneratedReferenceUsesConnectionOnlyEndpointRegistry(t *testing.T) {
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
		"| `schema_version` | int | `2` |",
		"`endpoints.<alias>.role`",
		"`endpoints.<alias>.identity_file`",
		"`endpoints.<alias>.known_hosts_path`",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("generated reference missing %q", want)
		}
	}
	// The client's SSH key is its credential: no token file is configured,
	// and the enrolled-client registry has a fixed location.
	for _, retired := range []string{"token_file", "authorized_keys_path"} {
		if strings.Contains(doc, retired) {
			t.Fatalf("generated reference contains retired field %q", retired)
		}
	}
	if strings.Contains(doc, "published_cosigners") {
		t.Fatal("generated reference contains retired cosigner inventory field")
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
