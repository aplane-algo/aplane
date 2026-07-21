// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keyadmin

import (
	"fmt"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/keys"
)

func TestIPCServiceLogGenerateWitnessCredential(t *testing.T) {
	var logged string
	service := IPCService{Logf: func(format string, args ...interface{}) {
		logged = fmt.Sprintf(format, args...)
	}}
	service.logGenerateKey(&GenerateResult{
		Address:      "WITNESSID",
		KeyType:      "aplane.witness-falcon1024.v1",
		IsWitnessKey: true,
	})

	for _, want := range []string{"sentry witness credential", "WITNESSID", "WITNESSID" + keys.SentryCredentialExtension} {
		if !strings.Contains(logged, want) {
			t.Fatalf("log = %q, want %q", logged, want)
		}
	}
}
