// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apadminapp

import (
	"strings"
	"testing"
)

// Every row is one command line: the lock-state mode it needs and, when the
// grammar refuses it, the exact error.
func TestCatalogAuthModeGrammar(t *testing.T) {
	unknown := func(line string) string { return "unknown or malformed apadmin command: " + line }
	const (
		prune   = "usage: apadmin generations prune --confirm <generation-id> [generation-id...]"
		discard = "usage: apadmin generations discard --confirm <generation-id> [generation-id...]"
		archive = "usage: apadmin archive prune --confirm <deleted/path> [deleted/path...]"
	)
	tests := []struct {
		line string
		mode AuthMode
		err  string
	}{
		{"template", AuthUnlock, "usage: apadmin template <list|show|import|remove>"},
		{"template list", AuthUnlock, ""},
		{"template list extra", AuthUnlock, "usage: apadmin template list"},
		{"template show kt --show-sensitive-template", AuthUnlock, ""},
		{"template show kt", AuthUnlock, "usage: apadmin template show <key-type> --show-sensitive-template"},
		{"template show kt --other", AuthUnlock, "usage: apadmin template show <key-type> --show-sensitive-template"},
		{"template import file.yaml", AuthUnlock, ""},
		{"template import", AuthUnlock, "usage: apadmin template import <file-or-key-type>"},
		{"template remove kt", AuthUnlock, ""},
		{"template remove", AuthUnlock, "usage: apadmin template remove <file-or-key-type>"},
		{"template remove a b", AuthUnlock, "usage: apadmin template remove <file-or-key-type>"},
		{"template import a b", AuthUnlock, "usage: apadmin template import <file-or-key-type>"},
		{"template show kt --show-sensitive-template extra", AuthUnlock, "usage: apadmin template show <key-type> --show-sensitive-template"},
		{"template bogus", AuthUnlock, unknown("template bogus")},

		{"keytype enable kt", AuthUnlock, ""},
		{"keytype disable kt", AuthUnlock, ""},
		{"keytype", AuthUnlock, unknown("keytype")},
		{"keytype enable", AuthUnlock, unknown("keytype enable")},
		{"keytype enable a b", AuthUnlock, unknown("keytype enable a b")},
		{"keytype list kt", AuthUnlock, unknown("keytype list kt")},

		{"cosigner", AuthUnlock, "usage: apadmin cosigner <export|import|list|show|remove>"},
		{"cosigner export id", AuthReadOnly, ""},
		{"cosigner export id out.json", AuthReadOnly, ""},
		{"cosigner export", AuthReadOnly, "usage: apadmin cosigner export <cosigner-key-id> [output-json]"},
		{"cosigner export a b c", AuthReadOnly, "usage: apadmin cosigner export <cosigner-key-id> [output-json]"},
		{"cosigner list", AuthReadOnly, ""},
		{"cosigner list extra", AuthReadOnly, "usage: apadmin cosigner list"},
		{"cosigner show name", AuthReadOnly, ""},
		{"cosigner show", AuthReadOnly, "usage: apadmin cosigner show <name>"},
		{"cosigner import file.json name", AuthUnlock, ""},
		{"cosigner import file.json", AuthUnlock, "usage: apadmin cosigner import <public-json|-> <name>"},
		{"cosigner remove name", AuthUnlock, ""},
		{"cosigner remove", AuthUnlock, "usage: apadmin cosigner remove <name>"},
		{"cosigner show a b", AuthReadOnly, "usage: apadmin cosigner show <name>"},
		{"cosigner import a b c", AuthUnlock, "usage: apadmin cosigner import <public-json|-> <name>"},
		{"cosigner remove a b", AuthUnlock, "usage: apadmin cosigner remove <name>"},
		{"cosigner bogus", AuthUnlock, unknown("cosigner bogus")},

		{"clients list", AuthReadOnly, ""},
		{"clients", AuthUnlock, clientsUsage},
		{"clients bogus", AuthUnlock, clientsUsage},
		{"asa list", AuthUnlock, ""},
		{"asa", AuthUnlock, asaUsage},

		{"endpoint export", AuthReadOnly, ""},
		{"endpoint export --host signer.example", AuthReadOnly, ""},
		{"endpoint export --url ssh://signer.example:1127 --out endpoint.json", AuthReadOnly, ""},
		{"endpoint export extra", AuthReadOnly, endpointExportUsage},
		{"endpoint export --bogus", AuthReadOnly, endpointExportUsage},
		{"endpoint export --host=signer.example --out=endpoint.json", AuthReadOnly, ""},
		{"endpoint export -h", AuthReadOnly, endpointExportUsage},
		{"endpoint export --out", AuthReadOnly, endpointExportUsage},
		{"endpoint", AuthUnlock, unknown("endpoint")},
		{"endpoint list", AuthUnlock, unknown("endpoint list")},

		{"generations list", AuthReadOnly, ""},
		{"generations list extra", AuthUnlock, unknown("generations list extra")},
		{"generations prune --confirm gen-1", AuthUnlock, ""},
		{"generations prune gen-1 gen-2", AuthUnlock, ""},
		{"generations prune", AuthUnlock, prune},
		{"generations prune --confirm", AuthUnlock, prune},
		{"generations prune --bogus gen-1", AuthUnlock, prune},
		{"generations prune --confirm=false gen-1", AuthUnlock, ""},
		{"generations prune --confirm=maybe gen-1", AuthUnlock, prune},
		{"generations prune gen-1 --confirm", AuthUnlock, ""},
		{"generations prune -- --confirm", AuthUnlock, ""},
		{"generations prune --", AuthUnlock, prune},
		{"generations prune -h", AuthUnlock, prune},
		{"generations discard --confirm gen-1", AuthUnlock, ""},
		{"generations discard", AuthUnlock, discard},
		{"generations discard --bogus gen-1", AuthUnlock, discard},
		{"generations discard --confirm", AuthUnlock, discard},
		{"generations discard gen-1 gen-2", AuthUnlock, ""},
		{"generations", AuthUnlock, unknown("generations")},
		{"generations bogus", AuthUnlock, unknown("generations bogus")},

		{"archive list", AuthUnlock, ""},
		{"archive list extra", AuthUnlock, unknown("archive list extra")},
		{"archive prune --confirm deleted/a.key", AuthUnlock, ""},
		{"archive prune", AuthUnlock, archive},
		{"archive prune --bogus deleted/a.key", AuthUnlock, archive},
		{"archive prune --confirm", AuthUnlock, archive},
		{"archive prune deleted/a.key deleted/b.key", AuthUnlock, ""},
		{"archive", AuthUnlock, unknown("archive")},
		{"archive bogus", AuthUnlock, unknown("archive bogus")},

		{"bogus", AuthUnlock, unknown("bogus")},
		{"bogus list", AuthUnlock, unknown("bogus list")},
	}
	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			words := strings.Fields(tt.line)
			mode, err := CatalogAuthMode(words[0], words[1:])
			got := ""
			if err != nil {
				got = err.Error()
			}
			if mode != tt.mode || got != tt.err {
				t.Fatalf("CatalogAuthMode(%q) = %v, %q; want %v, %q", tt.line, mode, got, tt.mode, tt.err)
			}
		})
	}

	// Arguments a command line of words cannot spell: none at all, empty
	// ones, and ones that look like format verbs. The unknown-command message
	// joins the words as given and trims the ends.
	direct := []struct {
		command string
		args    []string
		mode    AuthMode
		err     string
	}{
		{"", nil, AuthUnlock, unknown("")},
		{"template", nil, AuthUnlock, "usage: apadmin template <list|show|import|remove>"},
		{"cosigner", []string{}, AuthUnlock, "usage: apadmin cosigner <export|import|list|show|remove>"},
		{"bogus", []string{""}, AuthUnlock, unknown("bogus")},
		{"bogus", []string{"", "x"}, AuthUnlock, unknown("bogus  x")},
		{"bogus", []string{"%d", "%s"}, AuthUnlock, unknown("bogus %d %s")},
		{"keytype", []string{"enable", ""}, AuthUnlock, ""},
		{"template", []string{"import", ""}, AuthUnlock, ""},
		{"template", []string{"%s"}, AuthUnlock, unknown("template %s")},
	}
	for _, tt := range direct {
		mode, err := CatalogAuthMode(tt.command, tt.args)
		got := ""
		if err != nil {
			got = err.Error()
		}
		if mode != tt.mode || got != tt.err {
			t.Errorf("CatalogAuthMode(%q, %q) = %v, %q; want %v, %q", tt.command, tt.args, mode, got, tt.mode, tt.err)
		}
	}
}
