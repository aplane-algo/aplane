// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	apbackup "github.com/aplane-algo/aplane/internal/backup"
	apcrypto "github.com/aplane-algo/aplane/internal/crypto"
	apkeys "github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keys/keystest"
	"github.com/aplane-algo/aplane/internal/keytypecatalog"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/noderole"

	sdkcrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

func testEd25519KeyJSON(t *testing.T) (string, []byte) {
	t.Helper()
	return keystest.Ed25519KeyJSON(t)
}

func bytes32(fill byte) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = fill
	}
	return b
}

func writeStandaloneBackup(dir, address string, keyJSON, exportPassphrase []byte) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	encrypted, err := apcrypto.EncryptStandalone(keyJSON, exportPassphrase)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, address+".apb"), encrypted, 0o600)
}

func withTestStdin(input string, fn func() error) error {
	origStdin := os.Stdin
	origReader := stdinReader

	r, w, err := os.Pipe()
	if err != nil {
		return err
	}
	if _, err := io.WriteString(w, input); err != nil {
		_ = r.Close()
		_ = w.Close()
		return err
	}
	_ = w.Close()

	os.Stdin = r
	stdinReader = nil
	defer func() {
		os.Stdin = origStdin
		stdinReader = origReader
		_ = r.Close()
	}()

	return fn()
}

func withCapturedStdout(fn func() error) (string, error) {
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		return "", err
	}
	defer func() { _ = r.Close() }()
	defer func() { _ = w.Close() }()

	os.Stdout = w
	defer func() { os.Stdout = origStdout }()
	runErr := fn()
	_ = w.Close()

	data, readErr := io.ReadAll(r)
	if runErr != nil {
		return string(data), runErr
	}
	if readErr != nil {
		return string(data), readErr
	}
	return string(data), nil
}

func canonicalGenericKeyJSONForApstore(t *testing.T, keyType string, bytecode []byte) []byte {
	t.Helper()
	return keystest.GenericLSigKeyJSON(t, keyType, bytecode, saltCounterForTest, nil, "")
}

func canonicalDSALSigKeyJSONForApstore(t *testing.T, keyType, baseKeyType string, bytecode []byte) []byte {
	t.Helper()
	return keystest.DSALSigKeyJSON(t, keyType, baseKeyType, []byte{0x01}, []byte{0x02}, bytecode, saltCounterForTest)
}

func canonicalGenericKeyWithoutSigningMetadataForApstore(t *testing.T, keyType string, bytecode []byte) []byte {
	t.Helper()
	return mustMarshalJSON(t, map[string]any{
		"format_version": apkeys.CurrentKeyFormatVersion,
		"category":       apkeys.CategoryGenericLsig,
		"key_type":       keyType,
		"lsig_bytecode":  hex.EncodeToString(bytecode),
		"salt_counter":   saltCounterForTest,
		"created_at":     time.Now().UTC().Truncate(time.Second).Format(time.RFC3339),
	})
}

func mustMarshalJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return data
}

func logicSigAddressForTestForBytes(t *testing.T, bytecode []byte) string {
	t.Helper()
	lsig := sdkcrypto.LogicSigAccount{Lsig: types.LogicSig{Logic: bytecode}}
	addr, err := lsig.Address()
	if err != nil {
		t.Fatalf("LogicSigAccount.Address() error = %v", err)
	}
	return addr.String()
}

func registerRestoreLibraryProvider(keyType string) {
	keytypecatalog.Register(keytypecatalog.Entry{
		KeyType:      keyType,
		Family:       strings.TrimSuffix(keyType, "-v1"),
		Availability: keytypecatalog.AvailabilityLibrary,
	})
	lsigprovider.RegisterIfAbsent(restoreLibraryProvider{keyType: keyType})
}

type restoreLibraryProvider struct {
	keyType string
}

func (p restoreLibraryProvider) KeyType() string                             { return p.keyType }
func (p restoreLibraryProvider) RoutingFamily() string                       { return strings.TrimSuffix(p.keyType, "-v1") }
func (p restoreLibraryProvider) Version() int                                { return 1 }
func (p restoreLibraryProvider) Category() string                            { return lsigprovider.CategoryDSALsig }
func (p restoreLibraryProvider) DisplayName() string                         { return p.keyType }
func (p restoreLibraryProvider) Description() string                         { return "restore test provider" }
func (p restoreLibraryProvider) DisplayColor() string                        { return "" }
func (p restoreLibraryProvider) CreationParams() []lsigprovider.ParameterDef { return nil }
func (p restoreLibraryProvider) ValidateCreationParams(map[string]string) error {
	return nil
}
func (p restoreLibraryProvider) RuntimeArgs() []lsigprovider.RuntimeArgDef { return nil }
func (p restoreLibraryProvider) BuildArgs(signature []byte, runtimeArgs map[string][]byte) ([][]byte, error) {
	_ = runtimeArgs
	return [][]byte{signature}, nil
}

// sealTestArchive seals a manifest over a hand-built archive tree so it has
// the authenticated shape every real archive carries.
func sealTestArchive(t *testing.T, root string, role noderole.Role) {
	t.Helper()
	if err := apbackup.WriteSealedManifest(
		root,
		role,
		time.Unix(1_700_000_000, 0),
		[]byte("export-passphrase"),
	); err != nil {
		t.Fatalf("WriteSealedManifest() error = %v", err)
	}
}
