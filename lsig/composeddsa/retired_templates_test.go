// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/library/retired"
)

// TestRetiredTemplatesCarryDeprecationComment pins the marker on each retired
// template: above every YAML key, naming its replacement, and outside the
// definition. The bytes below it are the file as it stood when retired, so
// existing stores keep matching, and a retired file does not change again.
func TestRetiredTemplatesCarryDeprecationComment(t *testing.T) {
	for _, test := range []struct {
		file        string
		replacement string
		bodySHA256  string
	}{
		{"aplane.falcon1024-allowlist.v1.yaml", "the Allowlist preset of aplane.falcon1024-b.v1", "ec78337365093494cf36507a327eb5b845fa3e6bfee4fe66262a199fa48c3ff8"},
		{"aplane.falcon1024-allowlist.v2.yaml", "the Allowlist preset of aplane.falcon1024-b.v1", "abcae47883883117dff9d861a33ea545458a079d635569bae460041bec7215c9"},
		{"aplane.falcon1024-allowlist-lock.v1.yaml", "the Locked Allowlist preset of aplane.falcon1024-b.v1", "cfa0dec292fc27a73d2f79a2d4d223e4c6994313efb1ab0f19c8807e8b7a332f"},
		{"aplane.corridor.v1.yaml", "the Corridor preset of aplane.falcon1024-b.v1", "0871035319d12c825a64aad2ca9e34be913bb388bbfdc6411f8865e98c50cd55"},
		{"aplane.falcon1024-timelock.v1.yaml", "the Timelock preset of aplane.falcon1024-b.v1", "4fd2347d691d95bb577567f4582d0bd9146d0297b9c730ef83845fb41e9110b2"},
	} {
		t.Run(test.file, func(t *testing.T) {
			data, err := retired.ReadFile(test.file)
			if err != nil {
				t.Fatal(err)
			}
			var comment []string
			lines := strings.SplitAfter(string(data), "\n")
			for len(lines) > 0 && strings.HasPrefix(lines[0], "#") {
				comment = append(comment, lines[0])
				lines = lines[1:]
			}
			header := strings.ReplaceAll(strings.Join(comment, ""), "\n# ", " ")
			for _, want := range []string{"# DEPRECATED:", test.replacement, "kept to repair existing accounts"} {
				if !strings.Contains(header, want) {
					t.Fatalf("top-of-file comment %q does not contain %q", header, want)
				}
			}
			if len(lines) == 0 || !strings.HasPrefix(lines[0], "schema_version:") {
				t.Fatalf("comment must sit directly above schema_version, next line %q", lines[0])
			}

			body := []byte(strings.Join(lines, ""))
			if got := sha256.Sum256(body); hex.EncodeToString(got[:]) != test.bodySHA256 {
				t.Fatalf("template body changed: sha256 %x, want %s", got, test.bodySHA256)
			}

			marked, err := ParseTemplateSpec(data)
			if err != nil {
				t.Fatal(err)
			}
			unmarked, err := ParseTemplateSpec(body)
			if err != nil {
				t.Fatal(err)
			}
			markedProvider, err := NewProviderFromTemplateSpec(marked)
			if err != nil {
				t.Fatal(err)
			}
			unmarkedProvider, err := NewProviderFromTemplateSpec(unmarked)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := markedProvider.CompatibilityFingerprint(), unmarkedProvider.CompatibilityFingerprint(); got != want {
				t.Fatalf("comment moved the fingerprint: %s, want %s", got, want)
			}
		})
	}
}
