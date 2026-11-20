// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storemut

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"regexp"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keys/keystest"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/lsigsalt/lsigsalttest"
)

var createdAtField = regexp.MustCompile(`"created_at": "[^"]*"`)

// SaveGenericLSig writes the same key file bytes, apart from created_at, for an
// unsalted and an auto-salted program. The digests were taken before the
// payload constructors lost their salt counter parameter; the unsalted one was
// retaken when salt_counter was retired, and differs only by that line.
func TestSaveGenericLSigKeyFilesAreUnchanged(t *testing.T) {
	for _, test := range []struct {
		name       string
		program    []byte
		offset     int
		autoSalted bool
		want       string
	}{
		{name: "unsalted", program: []byte{0x06, 0x81, 0x01, 0x00}, offset: 3, want: "05b25fa85fa1bfc959e3db3cac549560814a3d67fff20612ec73bf00d31af64b"},
		{name: "auto-salted", program: []byte{13, 0x81, 0}, offset: 2, autoSalted: true, want: "88d9fe93c13e6fa7e36330a79465c317a6ce19dacc911a303b17745747db1614"},
	} {
		t.Run(test.name, func(t *testing.T) {
			paths, masterKey, cleanup := setupKeystore(t)
			defer cleanup()
			salted := lsigsalttest.OffCurve(t, test.program, test.offset)
			keyType := registerRekeyTargetTemplate(t, "key-file-golden", true)
			if err := New(paths).SaveGenericLSig(keyType, map[string]string{"unlock_round": "123"}, salted.Bytecode, test.autoSalted,
				"#pragma version 10\nint 1\nreturn", nil, lsigresource.DefaultOpcodeProfile(lsigresource.SingleTransactionOpcodeCeiling), masterKey); err != nil {
				t.Fatalf("SaveGenericLSig() error = %v", err)
			}
			keyPath := keystest.AccountKeyFilePath(genstoretest.Active(t, paths), salted.Address.String())
			encrypted, err := os.ReadFile(keyPath)
			if err != nil {
				t.Fatal(err)
			}
			credentialContext, err := keys.CredentialContextForFile(keyPath)
			if err != nil {
				t.Fatal(err)
			}
			decrypted, err := masterKey.Open(encrypted, credentialContext)
			if err != nil {
				t.Fatal(err)
			}
			defer crypto.ZeroBytes(decrypted)
			sum := sha256.Sum256(createdAtField.ReplaceAll(decrypted, []byte(`"created_at": ""`)))
			if got := hex.EncodeToString(sum[:]); got != test.want {
				t.Fatalf("key file digest = %s, want %s", got, test.want)
			}
		})
	}
}
