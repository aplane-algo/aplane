// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"fmt"
	"slices"
	"testing"
)

func TestNotificationLossReporterAnnouncesOnlyNewLosses(t *testing.T) {
	var total uint64
	var warnings []string
	lost := notificationLossReporter{
		count: func() uint64 { return total },
		warnf: func(format string, args ...any) { warnings = append(warnings, fmt.Sprintf(format, args...)) },
	}

	lost.report()
	total = 2
	lost.report()
	lost.report()
	total = 5
	lost.report()

	want := []string{
		"2 signer notifications lost; an approval request may be missing",
		"5 signer notifications lost; an approval request may be missing",
	}
	if !slices.Equal(warnings, want) {
		t.Fatalf("warnings = %q, want %q", warnings, want)
	}
}
