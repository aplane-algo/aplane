// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sourcetokens

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/policycontext"
)

// An export records a selector's source names in a node context file, which
// holds at most as many per document as a token file holds tokens.
func TestAnExportCanRecordEveryTokenOfASelector(t *testing.T) {
	if policycontext.MaxSourceTokenNames != MaxTokens {
		t.Fatalf("policycontext.MaxSourceTokenNames = %d, want MaxTokens = %d", policycontext.MaxSourceTokenNames, MaxTokens)
	}
}
