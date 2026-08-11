// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package mnemonic

import (
	"bytes"
	"strings"
	"testing"

	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
)

func TestNativeFalconMnemonicEntropyRoundTrip(t *testing.T) {
	handler := &NativeFalconHandler{}
	entropy := make([]byte, nativefalcon.RecoveryEntropySize)
	for i := range entropy {
		entropy[i] = byte(i)
	}
	words, err := handler.EntropyToMnemonic(entropy)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(strings.Fields(words)); got != nativefalcon.MnemonicWordCount {
		t.Fatalf("word count = %d", got)
	}
	recovered, err := handler.MnemonicToEntropy(strings.Fields(words))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recovered, entropy) {
		t.Fatal("mnemonic did not recover original entropy")
	}
}
