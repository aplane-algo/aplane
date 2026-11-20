// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apadminapp

import (
	"errors"
	"io"
	"strings"
	"testing"
)

// Every row is one command line: the lock-state mode it needs and, when the
// grammar refuses it, the exact error. CatalogAuthMode and Run share one
// grammar, so Run must refuse the same lines with the same error. A refused
// line always reports AuthUnlock.
func TestCatalogAuthModeGrammar(t *testing.T) {
	const (
		templateUsage    = "usage: apadmin template <list|show|import|remove>"
		keytypeUsage     = "usage: apadmin keytype <enable|disable> <key-type>"
		cosignerUsage    = "usage: apadmin cosigner <export|import|list|show|remove>"
		endpointUsage    = "usage: apadmin endpoint <export>"
		generationsUsage = "usage: apadmin generations <list|prune|discard>"
		archiveUsage     = "usage: apadmin archive <list|prune>"

		prune   = "usage: apadmin generations prune --confirm <generation-id> [generation-id...]"
		discard = "usage: apadmin generations discard --confirm <generation-id> [generation-id...]"
		archive = "usage: apadmin archive prune --confirm <deleted/path> [deleted/path...]"
		bogus   = `unknown apadmin command "bogus"`
	)
	tests := []struct {
		line string
		mode AuthMode
		err  string
	}{
		{"template", AuthUnlock, templateUsage},
		{"template list", AuthUnlock, ""},
		{"template list extra", AuthUnlock, "usage: apadmin template list"},
		{"template show kt --show-sensitive-template", AuthUnlock, ""},
		{"template show kt", AuthUnlock, "usage: apadmin template show <key-type> --show-sensitive-template"},
		{"template show kt --other", AuthUnlock, "usage: apadmin template show <key-type> --show-sensitive-template"},
		{"template import file.yaml", AuthUnlock, ""},
		{"template import", AuthUnlock, "usage: apadmin template import <yaml-file>"},
		{"template remove kt", AuthUnlock, ""},
		{"template remove", AuthUnlock, "usage: apadmin template remove <key-type>"},
		{"template remove a b", AuthUnlock, "usage: apadmin template remove <key-type>"},
		{"template import a b", AuthUnlock, "usage: apadmin template import <yaml-file>"},
		{"template show kt --show-sensitive-template extra", AuthUnlock, "usage: apadmin template show <key-type> --show-sensitive-template"},
		{"template bogus", AuthUnlock, templateUsage},

		{"keytype enable kt", AuthUnlock, ""},
		{"keytype disable kt", AuthUnlock, ""},
		{"keytype", AuthUnlock, keytypeUsage},
		{"keytype enable", AuthUnlock, keytypeUsage},
		{"keytype enable a b", AuthUnlock, keytypeUsage},
		{"keytype list kt", AuthUnlock, keytypeUsage},

		{"cosigner", AuthUnlock, cosignerUsage},
		{"cosigner export id", AuthReadOnly, ""},
		{"cosigner export id out.json", AuthReadOnly, ""},
		{"cosigner export", AuthUnlock, "usage: apadmin cosigner export <cosigner-key-id> [output-json]"},
		{"cosigner export a b c", AuthUnlock, "usage: apadmin cosigner export <cosigner-key-id> [output-json]"},
		{"cosigner list", AuthReadOnly, ""},
		{"cosigner list extra", AuthUnlock, "usage: apadmin cosigner list"},
		{"cosigner show name", AuthReadOnly, ""},
		{"cosigner show", AuthUnlock, "usage: apadmin cosigner show <name>"},
		{"cosigner import file.json name", AuthUnlock, ""},
		{"cosigner import file.json", AuthUnlock, "usage: apadmin cosigner import <public-json|-> <name>"},
		{"cosigner remove name", AuthUnlock, ""},
		{"cosigner remove", AuthUnlock, "usage: apadmin cosigner remove <name>"},
		{"cosigner show a b", AuthUnlock, "usage: apadmin cosigner show <name>"},
		{"cosigner import a b c", AuthUnlock, "usage: apadmin cosigner import <public-json|-> <name>"},
		{"cosigner remove a b", AuthUnlock, "usage: apadmin cosigner remove <name>"},
		{"cosigner bogus", AuthUnlock, cosignerUsage},

		{"clients list", AuthReadOnly, ""},
		{"clients list extra", AuthUnlock, "usage: apadmin clients list"},
		{"clients", AuthUnlock, clientsUsage},
		{"clients bogus", AuthUnlock, clientsUsage},
		{"asa list", AuthUnlock, ""},
		{"asa", AuthUnlock, asaUsage},

		{"endpoint export", AuthReadOnly, ""},
		{"endpoint export --host signer.example", AuthReadOnly, ""},
		{"endpoint export --url ssh://signer.example:1127 --out endpoint.json", AuthReadOnly, ""},
		{"endpoint export extra", AuthUnlock, endpointExportUsage},
		{"endpoint export --bogus", AuthUnlock, endpointExportUsage},
		{"endpoint export --host=signer.example --out=endpoint.json", AuthReadOnly, ""},
		{"endpoint export -h", AuthUnlock, endpointExportUsage},
		{"endpoint export --out", AuthUnlock, endpointExportUsage},
		// The retired port flags are refused here, before a connection, as
		// the command itself refuses them.
		{"endpoint export --signer-port 11270", AuthUnlock, endpointExportUsage},
		{"endpoint export --local-port 18080", AuthUnlock, endpointExportUsage},
		{"endpoint", AuthUnlock, endpointUsage},
		{"endpoint list", AuthUnlock, endpointUsage},

		{"generations list", AuthReadOnly, ""},
		{"generations list extra", AuthUnlock, generationsUsage},
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
		{"generations", AuthUnlock, generationsUsage},
		{"generations bogus", AuthUnlock, generationsUsage},

		{"archive list", AuthUnlock, ""},
		{"archive list extra", AuthUnlock, archiveUsage},
		{"archive prune --confirm deleted/a.key", AuthUnlock, ""},
		{"archive prune", AuthUnlock, archive},
		{"archive prune --bogus deleted/a.key", AuthUnlock, archive},
		{"archive prune --confirm", AuthUnlock, archive},
		{"archive prune deleted/a.key deleted/b.key", AuthUnlock, ""},
		{"archive", AuthUnlock, archiveUsage},
		{"archive bogus", AuthUnlock, archiveUsage},

		{"bogus", AuthUnlock, bogus},
		{"bogus list", AuthUnlock, bogus},
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
			if got := runGrammarError(words); got != tt.err {
				t.Fatalf("Run(%q) grammar error = %q; want %q", tt.line, got, tt.err)
			}
		})
	}

	// Arguments a command line of words cannot spell: none at all, empty
	// ones, and ones that look like format verbs.
	direct := []struct {
		command string
		args    []string
		mode    AuthMode
		err     string
	}{
		{"", nil, AuthUnlock, `unknown apadmin command ""`},
		{"template", nil, AuthUnlock, "usage: apadmin template <list|show|import|remove>"},
		{"cosigner", []string{}, AuthUnlock, "usage: apadmin cosigner <export|import|list|show|remove>"},
		{"bogus", []string{""}, AuthUnlock, bogus},
		{"bogus", []string{"", "x"}, AuthUnlock, bogus},
		{"%d", []string{"%s"}, AuthUnlock, `unknown apadmin command "%d"`},
		{"keytype", []string{"enable", ""}, AuthUnlock, ""},
		{"template", []string{"import", ""}, AuthUnlock, ""},
		{"template", []string{"%s"}, AuthUnlock, templateUsage},
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

// runGrammarError runs a command line against a daemon that answers nothing
// and returns its error when the grammar refused the line, or "" when Run got
// past the grammar to a file read, a prompt or a request.
func runGrammarError(words []string) string {
	requester := &fakeRequester{handle: func(any, any) error { return errors.New("request sent") }}
	err := (Catalog{Client: requester, Streams: Streams{Stdout: io.Discard, Stderr: io.Discard}}).Run(words[0], words[1:])
	if err == nil {
		return ""
	}
	if got := err.Error(); strings.HasPrefix(got, "usage: ") || strings.HasPrefix(got, "unknown apadmin command") {
		return got
	}
	return ""
}

// CatalogReadsStdin must agree with Run on every accepted spelling, since
// apadmin reads the passphrase from stdin unless it says the import does.
func TestCatalogReadsStdin(t *testing.T) {
	tests := []struct {
		line string
		want bool
	}{
		{"clients import -", true},
		{"clients import - --label ops", true},
		{"clients import --label ops -", true},
		{"clients import --label=ops -", true},
		{"clients import -label ops -", true},
		{"clients import -- -", true},
		{"cosigner import - lab", true},
		{"clients import client.pub", false},
		{"clients import --label ops client.pub", false},
		{"clients import --label -", false},
		{"clients import - extra", false},
		{"clients import --bogus -", false},
		{"cosigner import cosigner.json -", false},
		{"cosigner import -", false},
		{"cosigner import - lab extra", false},
		{"template import -", false},
		{"clients list", false},
		{"clients", false},
	}
	for _, tt := range tests {
		words := strings.Fields(tt.line)
		if got := CatalogReadsStdin(words[0], words[1:]); got != tt.want {
			t.Errorf("CatalogReadsStdin(%q) = %v, want %v", tt.line, got, tt.want)
		}
	}
}
