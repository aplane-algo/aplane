// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apadminapp

import (
	"strings"
	"testing"
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
