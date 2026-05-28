// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"bytes"
	"strings"
	"testing"
)

func TestDecodeHexRuntimeArgs(t *testing.T) {
	decoded, err := DecodeHexRuntimeArgs(map[string]string{
		"recipient": "001122",
		"secret":    "aabbcc",
	})
	if err != nil {
		t.Fatalf("DecodeHexRuntimeArgs: %v", err)
	}
	if got := decoded["recipient"]; !bytes.Equal(got, []byte{0x00, 0x11, 0x22}) {
		t.Fatalf("recipient = %x, want 001122", got)
	}
	if got := decoded["secret"]; !bytes.Equal(got, []byte{0xaa, 0xbb, 0xcc}) {
		t.Fatalf("secret = %x, want aabbcc", got)
	}
}

func TestDecodeHexRuntimeArgsEmpty(t *testing.T) {
	decoded, err := DecodeHexRuntimeArgs(nil)
	if err != nil {
		t.Fatalf("DecodeHexRuntimeArgs(nil): %v", err)
	}
	if decoded != nil {
		t.Fatalf("DecodeHexRuntimeArgs(nil) = %#v, want nil", decoded)
	}

	decoded, err = DecodeHexRuntimeArgs(map[string]string{})
	if err != nil {
		t.Fatalf("DecodeHexRuntimeArgs(empty): %v", err)
	}
	if decoded != nil {
		t.Fatalf("DecodeHexRuntimeArgs(empty) = %#v, want nil", decoded)
	}
}

func TestDecodeHexRuntimeArgsReportsArgumentName(t *testing.T) {
	_, err := DecodeHexRuntimeArgs(map[string]string{"recipient": "not-hex"})
	if err == nil {
		t.Fatal("expected invalid hex error")
	}
	if !strings.Contains(err.Error(), "recipient") {
		t.Fatalf("error %q does not include argument name", err)
	}
	if !strings.Contains(err.Error(), "invalid byte") {
		t.Fatalf("error %q does not include hex decode context", err)
	}
}
