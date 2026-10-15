// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func findingsFor(t *testing.T, src string) []finding {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sample.go")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	return checkFile(path)
}

func TestCheckFileIgnoresCommentsAndStrings(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
		want int
	}{
		{"zeroed", `package p
func use(k *Key) {
	sign(k.PrivateKey)
	crypto.ZeroBytes(k.PrivateKey)
}
`, 0},
		{"commented-out zeroing does not count", `package p
func use(k *Key) {
	sign(k.PrivateKey)
	// crypto.ZeroBytes(k.PrivateKey)
}
`, 1},
		{"block-commented zeroing does not count", `package p
func use(k *Key) {
	sign(k.PrivateKey)
	/* crypto.ZeroBytes(k.PrivateKey) */
}
`, 1},
		{"inline comment does not hide a reference", `package p
func use(k *Key) {
	key := k.PrivateKey // signing input
	sign(key)
}
`, 1},
		{"string mention is not a reference", `package p
func describe() string {
	return "the PrivateKey field is encrypted"
}
`, 0},
		{"braces in strings do not end the function", `package p
func use(k *Key) {
	log.Print("}")
	sign(k.PrivateKey)
}
`, 1},
	} {
		if got := len(findingsFor(t, tc.src)); got != tc.want {
			t.Errorf("%s: %d finding(s), want %d", tc.name, got, tc.want)
		}
	}
}
