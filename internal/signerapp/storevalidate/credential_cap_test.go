// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storevalidate

import (
	"errors"
	"fmt"
	"testing"

	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/witness"
)

// TestCredentialReportCapsCosignerCredentials covers every path that adds
// cosigner credentials through a validated generation, such as restore.
func TestCredentialReportCapsCosignerCredentials(t *testing.T) {
	report := &keys.KeyScanReport{Keys: map[string]keys.KeyScanInfo{}}
	for i := range keys.MaxCosignerCredentials {
		report.Keys[fmt.Sprintf("K%d", i)] = keys.KeyScanInfo{KeyType: witness.Falcon1024V1, Category: keys.CategoryWitness}
	}
	if err := validateCredentialReport(noderole.RoleCosigner, report); err != nil {
		t.Fatalf("validateCredentialReport(at the cap) error = %v", err)
	}
	report.Keys["one-more"] = keys.KeyScanInfo{KeyType: witness.Falcon1024V1, Category: keys.CategoryWitness}
	if err := validateCredentialReport(noderole.RoleCosigner, report); !errors.Is(err, keys.ErrCosignerCredentialLimit) {
		t.Fatalf("validateCredentialReport(past the cap) error = %v, want ErrCosignerCredentialLimit", err)
	}
}
