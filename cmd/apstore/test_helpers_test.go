// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
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
	"github.com/aplane-algo/aplane/internal/protocol"

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

type fakeApstoreAdminRequester struct {
	requests                 []string
	previewResult            protocol.RestorePreviewMessage
	recoverResult            protocol.RecoverBackupResultMessage
	recoveredListResult      protocol.RecoveredListMessage
	recoveredReviewResult    protocol.ReviewRecoveredResultMessage
	recoveredActivateResult  protocol.ActivateRecoveredResultMessage
	recoveredRollbackResult  protocol.RollbackRecoveredResultMessage
	recoveredPurgeResult     protocol.PurgeRecoveredResultMessage
	backupResult             protocol.BackupResultMessage
	listBackupsResult        protocol.BackupsListMessage
	deleteBackupResult       protocol.DeleteBackupResultMessage
	installedTemplatesResult protocol.InstalledTemplatesMessage
	showTemplateResult       protocol.ShowInstalledTemplateResultMessage
	importTemplateResult     protocol.ImportInstalledTemplateResultMessage
	removeTemplateResult     protocol.RemoveInstalledTemplateResultMessage
	activateResult           protocol.ActivateKeyTypeResultMessage
	deactivateResult         protocol.DeactivateKeyTypeResultMessage
	changePassphraseResult   protocol.ChangeStorePassphraseResultMessage
	recoverRequest           protocol.RecoverBackupMessage
	recoveredActivateRequest protocol.ActivateRecoveredMessage
	backupRequest            protocol.BackupMessage
	deleteBackupRequest      protocol.DeleteBackupMessage
	showTemplateRequest      protocol.ShowInstalledTemplateMessage
	importTemplateRequest    protocol.ImportInstalledTemplateMessage
	removeTemplateRequest    protocol.RemoveInstalledTemplateMessage
	activateRequest          protocol.ActivateKeyTypeMessage
	deactivateRequest        protocol.DeactivateKeyTypeMessage
	changePassphraseRequest  protocol.ChangeStorePassphraseMessage
	adminPassphrase          string
	closed                   bool
}

func (f *fakeApstoreAdminRequester) request(msg any, out any) error {
	switch typed := msg.(type) {
	case protocol.BackupMessage:
		f.requests = append(f.requests, typed.Type)
		f.backupRequest = typed
		result, ok := out.(*protocol.BackupResultMessage)
		if !ok {
			return errors.New("backup output has unexpected type")
		}
		*result = f.backupResult
		return nil
	case protocol.ListBackupsMessage:
		f.requests = append(f.requests, typed.Type)
		result, ok := out.(*protocol.BackupsListMessage)
		if !ok {
			return errors.New("list backups output has unexpected type")
		}
		*result = f.listBackupsResult
		return nil
	case protocol.DeleteBackupMessage:
		f.requests = append(f.requests, typed.Type)
		f.deleteBackupRequest = typed
		result, ok := out.(*protocol.DeleteBackupResultMessage)
		if !ok {
			return errors.New("delete backup output has unexpected type")
		}
		*result = f.deleteBackupResult
		return nil
	case protocol.PreviewRestoreMessage:
		f.requests = append(f.requests, typed.Type)
		result, ok := out.(*protocol.RestorePreviewMessage)
		if !ok {
			return errors.New("preview restore output has unexpected type")
		}
		*result = f.previewResult
		return nil
	case protocol.RecoverBackupMessage:
		f.requests = append(f.requests, typed.Type)
		f.recoverRequest = typed
		result, ok := out.(*protocol.RecoverBackupResultMessage)
		if !ok {
			return errors.New("recover backup output has unexpected type")
		}
		*result = f.recoverResult
		return nil
	case protocol.ListRecoveredMessage:
		f.requests = append(f.requests, typed.Type)
		result, ok := out.(*protocol.RecoveredListMessage)
		if !ok {
			return errors.New("list recovered output has unexpected type")
		}
		*result = f.recoveredListResult
		return nil
	case protocol.ReviewRecoveredMessage:
		f.requests = append(f.requests, typed.Type)
		result, ok := out.(*protocol.ReviewRecoveredResultMessage)
		if !ok {
			return errors.New("review recovered output has unexpected type")
		}
		*result = f.recoveredReviewResult
		return nil
	case protocol.ActivateRecoveredMessage:
		f.requests = append(f.requests, typed.Type)
		f.recoveredActivateRequest = typed
		result, ok := out.(*protocol.ActivateRecoveredResultMessage)
		if !ok {
			return errors.New("activate recovered output has unexpected type")
		}
		*result = f.recoveredActivateResult
		return nil
	case protocol.RollbackRecoveredMessage:
		f.requests = append(f.requests, typed.Type)
		result, ok := out.(*protocol.RollbackRecoveredResultMessage)
		if !ok {
			return errors.New("rollback recovered output has unexpected type")
		}
		*result = f.recoveredRollbackResult
		return nil
	case protocol.PurgeRecoveredMessage:
		f.requests = append(f.requests, typed.Type)
		result, ok := out.(*protocol.PurgeRecoveredResultMessage)
		if !ok {
			return errors.New("purge recovered output has unexpected type")
		}
		*result = f.recoveredPurgeResult
		return nil
	case protocol.ListInstalledTemplatesMessage:
		f.requests = append(f.requests, typed.Type)
		result, ok := out.(*protocol.InstalledTemplatesMessage)
		if !ok {
			return errors.New("installed templates output has unexpected type")
		}
		*result = f.installedTemplatesResult
		return nil
	case protocol.ShowInstalledTemplateMessage:
		f.requests = append(f.requests, typed.Type)
		f.showTemplateRequest = typed
		result, ok := out.(*protocol.ShowInstalledTemplateResultMessage)
		if !ok {
			return errors.New("show installed template output has unexpected type")
		}
		*result = f.showTemplateResult
		return nil
	case protocol.ImportInstalledTemplateMessage:
		f.requests = append(f.requests, typed.Type)
		f.importTemplateRequest = typed
		result, ok := out.(*protocol.ImportInstalledTemplateResultMessage)
		if !ok {
			return errors.New("import installed template output has unexpected type")
		}
		*result = f.importTemplateResult
		return nil
	case protocol.RemoveInstalledTemplateMessage:
		f.requests = append(f.requests, typed.Type)
		f.removeTemplateRequest = typed
		result, ok := out.(*protocol.RemoveInstalledTemplateResultMessage)
		if !ok {
			return errors.New("remove installed template output has unexpected type")
		}
		*result = f.removeTemplateResult
		return nil
	case protocol.ActivateKeyTypeMessage:
		f.requests = append(f.requests, typed.Type)
		f.activateRequest = typed
		result, ok := out.(*protocol.ActivateKeyTypeResultMessage)
		if !ok {
			return errors.New("activate keytype output has unexpected type")
		}
		*result = f.activateResult
		return nil
	case protocol.DeactivateKeyTypeMessage:
		f.requests = append(f.requests, typed.Type)
		f.deactivateRequest = typed
		result, ok := out.(*protocol.DeactivateKeyTypeResultMessage)
		if !ok {
			return errors.New("deactivate keytype output has unexpected type")
		}
		*result = f.deactivateResult
		return nil
	case protocol.ChangeStorePassphraseMessage:
		f.requests = append(f.requests, typed.Type)
		typed.CurrentPassphrase = protocol.SensitiveBytes(append([]byte(nil), typed.CurrentPassphrase...))
		typed.NewPassphrase = protocol.SensitiveBytes(append([]byte(nil), typed.NewPassphrase...))
		f.changePassphraseRequest = typed
		result, ok := out.(*protocol.ChangeStorePassphraseResultMessage)
		if !ok {
			return errors.New("change passphrase output has unexpected type")
		}
		*result = f.changePassphraseResult
		return nil
	default:
		return fmt.Errorf("unexpected request type %T", msg)
	}
}

func (f *fakeApstoreAdminRequester) close() {
	f.closed = true
}

func withFakeApstoreAdminClient(t *testing.T, fake apstoreAdminRequester) {
	t.Helper()
	oldNewApstoreAdminClientForCommand := newApstoreAdminClientForCommand
	oldNewApstoreAdminClientWithPassphraseForCommand := newApstoreAdminClientWithPassphraseForCommand
	newApstoreAdminClientForCommand = func() (apstoreAdminRequester, error) {
		return fake, nil
	}
	newApstoreAdminClientWithPassphraseForCommand = func(passphrase []byte) (apstoreAdminRequester, error) {
		if typed, ok := fake.(*fakeApstoreAdminRequester); ok {
			typed.adminPassphrase = string(passphrase)
		}
		return fake, nil
	}
	t.Cleanup(func() {
		newApstoreAdminClientForCommand = oldNewApstoreAdminClientForCommand
		newApstoreAdminClientWithPassphraseForCommand = oldNewApstoreAdminClientWithPassphraseForCommand
	})
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

func startApstoreIPCTestServer(t *testing.T, handler func(*bufio.Reader, net.Conn) error) (string, <-chan error) {
	t.Helper()
	socketPath := filepath.Join(t.TempDir(), "apstore-ipc.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Listen(unix) error = %v", err)
	}
	done := make(chan error, 1)
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		done <- handler(bufio.NewReader(conn), conn)
	}()
	t.Cleanup(func() { _ = listener.Close() })
	return socketPath, done
}

func waitApstoreIPCTestServer(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("IPC test server error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("IPC test server did not finish")
	}
}

func writeAdminTestMessage(w io.Writer, msg any) error {
	data, err := protocol.MarshalAdminMessage(msg)
	if err != nil {
		return err
	}
	return protocol.WriteJSONLine(w, data)
}

func testAllowlistBackupBundle(t *testing.T, keyType string, templateYAML []byte) (string, []byte) {
	t.Helper()

	bytecode := saltedLogicSigBytecodeForTest()
	address := logicSigAddressForTestForBytes(t, bytecode)
	keyJSON, err := json.Marshal(apbackup.BackupBundle{
		BackupBundle:   apbackup.BackupBundleSentinel,
		PayloadVersion: apbackup.CurrentBackupBundlePayloadVersion,
		Key:            json.RawMessage(canonicalGenericKeyJSONForApstore(t, keyType, bytecode)),
		TemplateYAML:   string(templateYAML),
		TemplateType:   "generic",
	})
	if err != nil {
		t.Fatalf("json.Marshal(backup bundle) error = %v", err)
	}
	return address, keyJSON
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
