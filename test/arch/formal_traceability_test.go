// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package arch_test

import (
	"os"
	"strings"
	"testing"
)

// TestFormalTraceabilityPinsLiveSentryResolverAnchors prevents the guarded
// routing traceability row from silently retaining renamed or removed tests.
func TestFormalTraceabilityPinsLiveSentryResolverAnchors(t *testing.T) {
	doc, err := os.ReadFile("../../docs/FORMAL_TRACEABILITY.md")
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile("../../internal/engine/guarded/discovery_resolver_test.go")
	if err != nil {
		t.Fatal(err)
	}

	row := ""
	for _, line := range strings.Split(string(doc), "\n") {
		if strings.HasPrefix(line, "| A9 |") {
			row = line
			break
		}
	}
	if row == "" {
		t.Fatal("FORMAL_TRACEABILITY.md has no A9 row")
	}
	for _, testName := range []string{
		"TestLiveSentryResolverRemovesImplicitPrimarySignerFallback",
		"TestLiveSentryResolverRejectsDuplicateAdvertisers",
		"TestLiveSentryResolverHostKeyMismatchAbortsGlobalSearch",
	} {
		if !strings.Contains(row, testName) {
			t.Errorf("A9 traceability row does not cite %s", testName)
		}
		if !strings.Contains(string(source), "func "+testName+"(") {
			t.Errorf("A9 traceability row cites missing test %s", testName)
		}
	}
}
