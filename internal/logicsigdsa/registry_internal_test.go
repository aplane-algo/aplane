// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package logicsigdsa

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

type brokenDSA struct{}

func (brokenDSA) KeyType() string          { return "broken-v1" }
func (brokenDSA) RoutingFamily() string    { return "broken" }
func (brokenDSA) Version() int             { return 1 }
func (brokenDSA) CryptoSignatureSize() int { return 0 }
func (brokenDSA) MnemonicScheme() string   { return "" }
func (brokenDSA) MnemonicWordCount() int   { return 0 }
func (brokenDSA) DisplayColor() string     { return "" }
func (brokenDSA) DeriveLsig(context.Context, []byte, map[string]string) ([]byte, string, error) {
	return nil, "", nil
}

func TestRegisterPanicsWhenDSAMissesLSigProvider(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("Register() did not panic for non-LSigProvider DSA")
		} else if got := fmt.Sprint(r); !strings.Contains(got, "does not implement lsigprovider.LSigProvider") {
			t.Fatalf("panic = %q, want missing LSigProvider contract", got)
		}
	}()

	Register(brokenDSA{})
}
