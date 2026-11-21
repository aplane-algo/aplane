// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/protocol"
)

// A preview row flags a key whose archive carries source tokens, whether or
// not the preview listed their names.
func TestRestorePreviewFlagsAKeyWithSourceTokens(t *testing.T) {
	for _, key := range []RestoreKeyInfo{
		{Address: "COSIGNER", SourceTokens: []string{"screening"}},
		{Address: "COSIGNER", SourceTokensOmitted: 3},
	} {
		if flags := restorePreviewFlags(key); !strings.Contains(flags, "+tokens") {
			t.Fatalf("restorePreviewFlags(%+v) = %q, want +tokens", key, flags)
		}
	}
	if flags := restorePreviewFlags(RestoreKeyInfo{Address: "PLAIN"}); strings.Contains(flags, "tokens") {
		t.Fatalf("restorePreviewFlags(no tokens) = %q", flags)
	}
}

// The result screen marks each key whose archived source tokens were
// installed, including one whose credential was already identical.
func TestRestoreResultMarksKeysWhoseTokensWereInstalled(t *testing.T) {
	m := Model{viewState: ViewRestoring, restore: restoreState{archivePath: "aplane-backup.tar.gz"}}
	m = updateModel(t, m, RestoreBackupResultMsg{Result: protocol.RestoreBackupResultMessage{
		Success:              true,
		Restored:             []protocol.RestoreCredential{{Selector: "NEWKEY", KeyType: "aplane.cosigner.falcon1024.v1"}},
		SourceTokensRestored: []string{"NEWKEY", "SAMEKEY"},
	}})
	view := squeezeForTest(fitsMinSizeForTest(t, m))
	for _, want := range []string{"NEWKEY [aplane.cosigner.falcon1024.v1] tokens", "SAMEKEY [] tokens"} {
		if !strings.Contains(view, want) {
			t.Fatalf("%q missing from:\n%s", want, view)
		}
	}
	if strings.Count(view, "tokens") != 2 {
		t.Fatalf("want both keys marked with tokens:\n%s", view)
	}
}
