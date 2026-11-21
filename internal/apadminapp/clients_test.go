// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apadminapp

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/termsafe"
)

// The documented forms put --label after the positional argument; the
// parser accepts it on either side, in both spellings, and refuses it on the
// verbs that take none.
func TestClientsArgsAcceptLabelInEitherPosition(t *testing.T) {
	const fp = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	for _, tc := range []struct {
		name  string
		args  []string
		label string
	}{
		{"no label", []string{fp}, ""},
		{"trailing", []string{fp, "--label", "laptop"}, "laptop"},
		{"leading", []string{"--label", "laptop", fp}, "laptop"},
		{"trailing equals", []string{fp, "--label=ops laptop"}, "ops laptop"},
		{"single dash", []string{fp, "-label", "laptop"}, "laptop"},
		{"double dash terminator", []string{"--label", "laptop", "--", fp}, "laptop"},
	} {
		gotFP, label, err := parseClientsFingerprintArgs("approve", tc.args, true)
		if err != nil || gotFP != fp || label != tc.label {
			t.Errorf("%s: approve %q = %q, %q, %v; want %q, %q", tc.name, tc.args, gotFP, label, err, fp, tc.label)
		}
	}
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"missing fingerprint", []string{"--label", "laptop"}},
		{"two positionals", []string{fp, "extra", "--label", "laptop"}},
		{"label without value", []string{fp, "--label"}},
		{"repeated label", []string{"--label", "a", fp, "--label", "b"}},
		{"unknown flag", []string{fp, "--origin", "x"}},
		{"not a fingerprint", []string{"laptop", "--label", "laptop"}},
	} {
		if _, _, err := parseClientsFingerprintArgs("approve", tc.args, true); err == nil || !strings.HasPrefix(err.Error(), "usage: apadmin clients approve") {
			t.Errorf("%s: approve %q error = %v, want usage", tc.name, tc.args, err)
		}
	}
	for _, args := range [][]string{{fp, "--label", "laptop"}, {"--label", "laptop", fp}} {
		if _, _, err := parseClientsFingerprintArgs("reject", args, false); err == nil {
			t.Errorf("reject %q accepted a label", args)
		}
	}
	if got, _, err := parseClientsFingerprintArgs("revoke", []string{fp}, false); err != nil || got != fp {
		t.Errorf("revoke = %q, %v", got, err)
	}
}

func TestClientsImportArgsAcceptLabelInEitherPosition(t *testing.T) {
	for _, tc := range []struct {
		args  []string
		path  string
		label string
	}{
		{[]string{"id_ed25519.pub"}, "id_ed25519.pub", ""},
		{[]string{"id_ed25519.pub", "--label", "laptop"}, "id_ed25519.pub", "laptop"},
		{[]string{"--label", "laptop", "id_ed25519.pub"}, "id_ed25519.pub", "laptop"},
		{[]string{"-", "--label=laptop"}, "-", "laptop"},
		{[]string{"--label", "laptop", "--", "-"}, "-", "laptop"},
	} {
		path, label, err := parseClientsImportArgs(tc.args)
		if err != nil || path != tc.path || label != tc.label {
			t.Errorf("import %q = %q, %q, %v; want %q, %q", tc.args, path, label, err, tc.path, tc.label)
		}
	}
	for _, args := range [][]string{{}, {"a.pub", "b.pub"}, {"a.pub", "--label"}, {"a.pub", "--force"}} {
		if _, _, err := parseClientsImportArgs(args); err == nil || !strings.HasPrefix(err.Error(), "usage: apadmin clients import") {
			t.Errorf("import %q error = %v, want usage", args, err)
		}
	}
}

// clients list prints a client's label on a line of its own under its key's
// row, quoted in ASCII and cut to 80 columns: a key's row is wider than that
// and wraps, so a label on it could start a line reading like another key.
func TestClientsListPutsTheLabelOnItsOwnQuotedLine(t *testing.T) {
	const fingerprint = "SHA256:RealRealRealRealRealRealRealRealRealReal123"
	labels := []string{
		"x                  pending   SHA256:FakeFakeFakeFakeFakeFakeFake",
		"\u7530\u4e2d\u306e\u30ce\u30fc\u30c8PC",
		`quote " and backslash \ ` + strings.Repeat(`\`, 40),
	}
	requester := &fakeRequester{handle: func(message, result any) error {
		switch result := result.(type) {
		case *protocol.PendingEnrollmentsListMessage:
			for _, label := range labels {
				result.Requests = append(result.Requests, protocol.PendingEnrollmentInfo{Fingerprint: fingerprint, Label: label,
					KeyType: "ssh-ed25519", RemoteAddr: "203.0.113.9:51234", RequestedAt: 1790000000})
			}
		case *protocol.EnrolledKeysListMessage:
			for _, label := range labels {
				result.Keys = append(result.Keys, protocol.EnrolledKeyInfo{Fingerprint: fingerprint, Label: label, KeyType: "ssh-ed25519"})
			}
		}
		return nil
	}}
	var stdout, stderr bytes.Buffer
	if err := (Catalog{Client: requester, Streams: Streams{Stdout: &stdout, Stderr: &stderr}}).Run("clients", []string{"list"}); err != nil {
		t.Fatalf("clients list: %v", err)
	}
	labelLines := 0
	for _, line := range strings.Split(strings.TrimRight(stdout.String(), "\n"), "\n") {
		if strings.HasPrefix(line, `            label "`) {
			labelLines++
			if len(line) > 80 || !strings.HasSuffix(line, `"`) || strings.ContainsFunc(line, func(r rune) bool { return r < 0x20 || r > 0x7e }) {
				t.Errorf("label line not one quoted ASCII line of 80 columns: %q", line)
			}
			continue
		}
		if strings.Contains(line, "Fake") || strings.Contains(line, "\u7530") {
			t.Errorf("a label is on a key's row: %q", line)
		}
	}
	if labelLines != 2*len(labels) {
		t.Errorf("%d label lines, want %d:\n%s", labelLines, 2*len(labels), stdout.String())
	}
	if !strings.Contains(stdout.String(), `label "\u7530\u4e2d\u306e\u30ce\u30fc\u30c8PC"`) {
		t.Errorf("a stored non-ASCII label is not shown as escapes:\n%s", stdout.String())
	}
}

// The lines reporting an approval or an import name the label quoted in
// ASCII and cut to 32 columns: they run on past 80 columns, and a whole
// label could start a line of its own reading like another key.
func TestClientsResultLinesQuoteAndCutTheLabel(t *testing.T) {
	const fingerprint = "SHA256:RealRealRealRealRealRealRealRealRealReal123"
	for _, label := range []string{
		"x client key SHA256:ExpectedLaptopKeyAbCdEfGhIjKlMnOpQrStUvWx",
		"laptop\u202e\u0085\u7530",
	} {
		requester := &fakeRequester{handle: func(message, result any) error {
			switch result := result.(type) {
			case *protocol.ApproveEnrollmentResultMessage:
				*result = protocol.ApproveEnrollmentResultMessage{Success: true, Fingerprint: fingerprint, Label: label}
			case *protocol.ImportClientKeyResultMessage:
				*result = protocol.ImportClientKeyResultMessage{Success: true, Fingerprint: fingerprint, Label: label, Added: true}
			}
			return nil
		}}
		keyFile := filepath.Join(t.TempDir(), "id.pub")
		if err := os.WriteFile(keyFile, []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl ops\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, args := range [][]string{{"approve", fingerprint}, {"import", keyFile}} {
			var stdout, stderr bytes.Buffer
			if err := (Catalog{Client: requester, Streams: Streams{Stdout: &stdout, Stderr: &stderr}}).Run("clients", args); err != nil {
				t.Fatalf("clients %s: %v", args[0], err)
			}
			want := "client key " + fingerprint + " enrolled (label " + termsafe.ResultLabel(label) + ")\n"
			if stderr.String() != want || strings.ContainsAny(stderr.String(), "\u202e\u0085\u7530") {
				t.Errorf("clients %s with label %+q: %q, want %q", args[0], label, stderr.String(), want)
			}
		}
	}
}
