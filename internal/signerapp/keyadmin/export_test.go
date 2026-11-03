// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keyadmin

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/protocol"
	nativereg "github.com/aplane-algo/aplane/internal/signing/falcon1024/signerreg"
	"github.com/aplane-algo/aplane/internal/witness"
)

// exportCapture records what ExportKey delivered, cloning the phrase because
// the service clears its buffer once delivery returns.
type exportCapture struct {
	calls    int
	mnemonic []byte
	shared   []byte
	err      error
}

func (c *exportCapture) deliver(result adminproto.ExportKeyResult) error {
	c.calls++
	c.mnemonic = bytes.Clone(result.Mnemonic)
	c.shared = result.Mnemonic
	return c.err
}

func exportWith(svc Service, ctx context.Context, address string, pass []byte) (adminproto.ExportKeyResult, *exportCapture) {
	capture := &exportCapture{}
	result := svc.ExportKey(ctx, adminproto.ExportKeyRequest{Address: address, Passphrase: pass}, capture.deliver)
	return result, capture
}

func TestNativeMnemonicExportRoundTrip(t *testing.T) {
	nativereg.RegisterSigner()
	for _, keyType := range []string{"ed25519", "falcon1024"} {
		t.Run(keyType, func(t *testing.T) {
			ir := setupProductRuntime(t)
			audit := &auditRecorder{}
			svc := Service{Runtime: ir, AuditLog: audit}
			generated, err := svc.GenerateKey(context.Background(), keyType, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			pass := protocol.SensitiveBytes(bytes.Clone(testPassphrase))
			result, exported := exportWith(svc, context.Background(), generated.Address, pass)
			defer crypto.ZeroBytes(exported.mnemonic)
			if !result.Success || exported.calls != 1 {
				t.Fatalf("export failed: %s", result.Error)
			}
			if len(result.Mnemonic) != 0 || !bytes.Equal(exported.shared, make([]byte, len(exported.shared))) {
				t.Fatal("service retained the delivered phrase")
			}
			if details, detailsErr := svc.GetKeyDetails(generated.Address); detailsErr != nil || !details.MnemonicExportable {
				t.Fatal("key details do not mark the key exportable")
			}
			if len(audit.exported) != 1 || audit.exported[0].address != generated.Address || audit.exported[0].outcome != "released" {
				t.Fatal("export audit missing")
			}
			if !bytes.Equal(pass, make([]byte, len(pass))) {
				t.Fatal("passphrase was not cleared")
			}
			if string(exported.mnemonic) != generated.Mnemonic || result.WordCount != 25 {
				t.Fatal("export did not recover generated phrase")
			}
			other := Service{Runtime: setupProductRuntime(t)}
			imported, err := other.ImportKey(context.Background(), keyType, string(exported.mnemonic), nil)
			if err != nil {
				t.Fatal(err)
			}
			if imported.Address != generated.Address {
				t.Fatal("import changed the account address")
			}
			reresult, reexported := exportWith(other, context.Background(), imported.Address, bytes.Clone(testPassphrase))
			defer crypto.ZeroBytes(reexported.mnemonic)
			if !reresult.Success || !bytes.Equal(exported.mnemonic, reexported.mnemonic) {
				t.Fatal("import did not preserve exportability")
			}
		})
	}
}

func TestNativeMnemonicExportDenials(t *testing.T) {
	ir := setupProductRuntime(t)
	svc := Service{Runtime: ir}
	generated, err := svc.GenerateKey(context.Background(), "ed25519", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, address, pass, code string }{
		{"bad passphrase", generated.Address, "incorrect", "invalid_passphrase"},
		{"empty passphrase", generated.Address, "", "invalid_passphrase"},
		{"missing key", "missing", string(testPassphrase), "not_found"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, delivered := exportWith(svc, context.Background(), tc.address, protocol.NewSensitiveBytes(tc.pass))
			if result.Success || delivered.calls != 0 || result.Code != tc.code {
				t.Fatalf("unexpected result code %s", result.Code)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, delivered := exportWith(svc, ctx, generated.Address, bytes.Clone(testPassphrase))
	if result.Success || delivered.calls != 0 {
		t.Fatal("canceled export released material")
	}
}

func TestNativeMnemonicExportAuditsDeliveryFailure(t *testing.T) {
	ir := setupProductRuntime(t)
	audit := &auditRecorder{}
	svc := Service{Runtime: ir, AuditLog: audit}
	generated, err := svc.GenerateKey(context.Background(), "ed25519", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	capture := &exportCapture{err: errors.New("connection closed")}
	result := svc.ExportKey(context.Background(), adminproto.ExportKeyRequest{Address: generated.Address, Passphrase: bytes.Clone(testPassphrase)}, capture.deliver)
	defer crypto.ZeroBytes(capture.mnemonic)
	if result.Success || capture.calls != 1 || result.Code != "internal" {
		t.Fatalf("delivery failure reported as %+v", result)
	}
	if !bytes.Equal(capture.shared, make([]byte, len(capture.shared))) {
		t.Fatal("undelivered phrase not cleared")
	}
	if len(audit.exported) != 1 || audit.exported[0].outcome == ExportOutcomeReleased {
		t.Fatalf("failed delivery audited as %+v", audit.exported)
	}
}

func TestLegacyNativeFalconMnemonicUnavailable(t *testing.T) {
	nativereg.RegisterSigner()
	ir := setupProductRuntime(t)
	svc := Service{Runtime: ir}
	generated, genErr := svc.GenerateKey(context.Background(), "falcon1024", nil, nil)
	if genErr != nil {
		t.Fatal(genErr)
	}
	file, err := ir.FindKeyFile(generated.Address)
	if err != nil {
		t.Fatal(err)
	}
	err = ir.WithKeyring(func(kr *crypto.Keyring) error {
		raw, err := keys.ReadDecryptedKeyJSONWithKeyring(file, kr)
		if err != nil {
			return err
		}
		defer crypto.ZeroBytes(raw)
		payload, err := keys.ParsePayload(raw)
		if err != nil {
			return err
		}
		defer payload.ZeroSecrets()
		crypto.ZeroBytes(payload.RecoveryEntropy)
		payload.RecoveryEntropy = nil
		payload.FormatVersion = keys.CurrentKeyFormatVersion
		_, err = keys.SavePayload(ir.KeyPaths(), payload, kr)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	result, delivered := exportWith(svc, context.Background(), generated.Address, bytes.Clone(testPassphrase))
	if result.Success || delivered.calls != 0 || result.Code != "unavailable" {
		t.Fatalf("unexpected result code %s", result.Code)
	}
	if details, detailsErr := svc.GetKeyDetails(generated.Address); detailsErr != nil || details.MnemonicExportable {
		t.Fatal("key details mark a Falcon key without entropy exportable")
	}
}

func TestNativeMnemonicExportRejectsWitness(t *testing.T) {
	ir := setupProductRuntimeWithRole(t, noderole.RoleCosigner)
	svc := Service{Runtime: ir}
	key, err := svc.GenerateKey(context.Background(), witness.Falcon1024V1, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	result, delivered := exportWith(svc, context.Background(), key.Address, bytes.Clone(testPassphrase))
	if result.Success || delivered.calls != 0 || result.Code != "forbidden" {
		t.Fatalf("unexpected result code %s", result.Code)
	}
	if details, detailsErr := svc.GetKeyDetails(key.Address); detailsErr != nil || details.MnemonicExportable {
		t.Fatal("key details mark a witness key exportable")
	}
}

type exportTestGate struct{ entered, resume chan struct{} }

func (g *exportTestGate) Lock()   { close(g.entered); <-g.resume }
func (g *exportTestGate) Unlock() {}

func TestNativeMnemonicExportRechecksLockAfterWaiting(t *testing.T) {
	ir := setupProductRuntime(t)
	svc := Service{Runtime: ir}
	key, err := svc.GenerateKey(context.Background(), "ed25519", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	gate := &exportTestGate{make(chan struct{}), make(chan struct{})}
	svc.MutationLock = func() Locker { return gate }
	done := make(chan adminproto.ExportKeyResult, 1)
	pass := protocol.SensitiveBytes(bytes.Clone(testPassphrase))
	capture := &exportCapture{}
	go func() {
		done <- svc.ExportKey(context.Background(), adminproto.ExportKeyRequest{Address: key.Address, Passphrase: pass}, capture.deliver)
	}()
	<-gate.entered
	ir.Lock()
	close(gate.resume)
	select {
	case result := <-done:
		if result.Success || capture.calls != 0 || result.Code != "locked" {
			t.Fatal("queued export survived lock")
		}
		if !bytes.Equal(pass, make([]byte, len(pass))) {
			t.Fatal("locked request retained passphrase")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("export did not resume")
	}
}
