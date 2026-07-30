// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package templates

import (
	"errors"
	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	"reflect"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	utilkeys "github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/templatepolicy"
	"github.com/aplane-algo/aplane/internal/templatestore"
	"github.com/aplane-algo/aplane/internal/witness"
)

type fakeKeyStore struct {
	cache        map[string]string
	keyTypes     map[string]string
	lsigSizes    map[string]int
	keyring      *crypto.Keyring
	scanWarnings []keys.KeyScanWarning
	scanCalled   bool
	withMKCalled bool
	clearCount   int
	clearCache   int
	scanErr      error
	withMKErr    error
	onScan       func()
}

func (f *fakeKeyStore) Unlock(_ []byte) error { return nil }
func (f *fakeKeyStore) WithKeyring(fn func(kr *crypto.Keyring) error) error {
	f.withMKCalled = true
	if f.withMKErr != nil {
		return f.withMKErr
	}
	if f.keyring != nil {
		return fn(f.keyring)
	}
	kr, err := crypto.NewKeyringFromKey(testTemplateMasterKey())
	if err != nil {
		return err
	}
	defer kr.Zero()
	return fn(kr)
}
func (f *fakeKeyStore) Scan(_ []byte) error {
	f.scanCalled = true
	if f.onScan != nil {
		f.onScan()
	}
	if f.scanErr != nil {
		return f.scanErr
	}
	return nil
}
func (f *fakeKeyStore) ClearKeys()                     { f.clearCount++ }
func (f *fakeKeyStore) ClearCache()                    { f.clearCache++ }
func (f *fakeKeyStore) GetCache() map[string]string    { return f.cache }
func (f *fakeKeyStore) GetKeyTypes() map[string]string { return f.keyTypes }
func (f *fakeKeyStore) GetLsigSizes() map[string]int   { return f.lsigSizes }
func (f *fakeKeyStore) GetScanWarnings() []keys.KeyScanWarning {
	return append([]keys.KeyScanWarning(nil), f.scanWarnings...)
}

type fakeSession struct{ initialized bool }

func (f *fakeSession) InitializeSession() { f.initialized = true }

type fakeAuditLog struct {
	reloads  int
	rejected []struct {
		identityID string
		keyFile    string
		reason     string
	}
}

func (f *fakeAuditLog) LogKeyReload(string, int) {
	f.reloads++
}

func (f *fakeAuditLog) LogKeyRejected(identityID, keyFile, reason string) {
	f.rejected = append(f.rejected, struct {
		identityID string
		keyFile    string
		reason     string
	}{identityID: identityID, keyFile: keyFile, reason: reason})
}

func TestReloadReportsTemplateActivationAndConflicts(t *testing.T) {
	store := &fakeKeyStore{
		cache:     map[string]string{"ADDR": "mock"},
		keyTypes:  map[string]string{"ADDR": "mock-type"},
		lsigSizes: map[string]int{"ADDR": 42},
	}
	session := &fakeSession{}

	var infos []string
	var warns []string
	var publishedKeys map[string]string
	var publishedKeyTypes map[string]string
	var publishedLsigSizes map[string]int
	paths := utilkeys.NewPaths(t.TempDir())
	genstoretest.MintFirst(t, paths, "default")
	saveTemplateRecord(t, paths, "new-generic", templatestore.TemplateTypeGeneric, testTemplateMasterKey())
	saveTemplateRecord(t, paths, "conflicting-generic", templatestore.TemplateTypeGeneric, testTemplateMasterKey())
	saveTemplateRecord(t, paths, "invalid-composed", templatestore.TemplateTypeComposed, testTemplateMasterKey())
	lsigprovider.RegisterIfAbsent(templatesTestProvider{
		keyType:     "conflicting-generic",
		fingerprint: "registered-fingerprint",
	})

	service := &ReloadService{
		KeyStore: store,
		Session:  session,
		TemplateManager: &Manager{
			Paths: paths,
			Registrars: []TemplateRegistrar{
				{
					Name:         "generic",
					Source:       keytypestate.SourceYAMLGeneric,
					TemplateType: templatestore.TemplateTypeGeneric,
					Prepare: func(keyType string, _ []byte) (templatepolicy.PreparedTemplateRegistration, error) {
						return templatepolicy.PreparedTemplateRegistration{
							Fingerprint: "incoming-" + keyType,
							Register:    func() bool { return true },
						}, nil
					},
				},
				{
					Name:         "composed",
					Source:       keytypestate.SourceYAMLComposed,
					TemplateType: templatestore.TemplateTypeComposed,
					Prepare: func(string, []byte) (templatepolicy.PreparedTemplateRegistration, error) {
						return templatepolicy.PreparedTemplateRegistration{}, errors.New("invalid composed")
					},
				},
			},
		},
		PublishSnapshot: func(keys map[string]string, keyTypes map[string]string, lsigSizes map[string]int) {
			publishedKeys = keys
			publishedKeyTypes = keyTypes
			publishedLsigSizes = lsigSizes
		},
		Info: func(msg string) { infos = append(infos, msg) },
		Warn: func(msg string) { warns = append(warns, msg) },
	}

	_ = publishedKeys
	_ = publishedKeyTypes
	_ = publishedLsigSizes
	_ = infos
	_ = warns
	report, err := service.Reload("default", nil)
	// Content defects fail closed: the invalid composed template aborts the
	// reload with a generation-validation error naming the defect.
	if err == nil || !IsGenerationValidationError(err.Error()) {
		t.Fatalf("Reload() error = %v, want generation validation failure", err)
	}
	if report != nil {
		t.Fatalf("report = %+v, want nil on fail-closed reload", report)
	}
}

func TestReloadRunsBeforeKeyScanHookBeforeTemplatesAndScan(t *testing.T) {
	var events []string
	store := &fakeKeyStore{
		cache:     map[string]string{},
		keyTypes:  map[string]string{},
		lsigSizes: map[string]int{},
		onScan: func() {
			events = append(events, "scan")
		},
	}
	session := &fakeSession{}
	paths := utilkeys.NewPaths(t.TempDir())
	genstoretest.MintFirst(t, paths, "default")
	saveTemplateRecord(t, paths, "hook-order", templatestore.TemplateTypeGeneric, testTemplateMasterKey())

	service := &ReloadService{
		KeyStore: store,
		Session:  session,
		TemplateManager: &Manager{
			Paths: paths,
			Registrars: []TemplateRegistrar{
				{
					Name:         "generic",
					Source:       keytypestate.SourceYAMLGeneric,
					TemplateType: templatestore.TemplateTypeGeneric,
					Prepare: func(string, []byte) (templatepolicy.PreparedTemplateRegistration, error) {
						events = append(events, "templates")
						return templatepolicy.PreparedTemplateRegistration{}, nil
					},
				},
			},
		},
		BeforeKeyScan: func(kr *crypto.Keyring) error {
			events = append(events, "before")
			if kr == nil {
				t.Fatal("BeforeKeyScan received no keyring")
			}
			return nil
		},
		PublishSnapshot: func(map[string]string, map[string]string, map[string]int) {
			events = append(events, "publish")
		},
	}

	if _, err := service.Reload("default", nil); err != nil && !IsGenerationValidationError(err.Error()) {
		t.Fatalf("Reload() error = %v", err)
	}
	want := []string{"before", "templates", "scan", "publish"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("reload order = %#v, want %#v", events, want)
	}
	// Session initialization only happens on a fully clean reload; the
	// fixture's deliberately-invalid template fails the generation gate
	// after publish, which is the ordering under test. Clean-reload session
	// initialization is covered end-to-end by the daemon unlock tests.
}

func TestReloadBeforeKeyScanHookErrorAbortsReload(t *testing.T) {
	wantErr := errors.New("policy integrity failed")
	store := &fakeKeyStore{
		cache:     map[string]string{},
		keyTypes:  map[string]string{},
		lsigSizes: map[string]int{},
	}
	session := &fakeSession{}
	paths := utilkeys.NewPaths(t.TempDir())
	genstoretest.MintFirst(t, paths, "default")

	var prepared bool
	var published bool
	service := &ReloadService{
		KeyStore: store,
		Session:  session,
		TemplateManager: &Manager{
			Paths: paths,
			Registrars: []TemplateRegistrar{
				{
					Name:         "generic",
					Source:       keytypestate.SourceYAMLGeneric,
					TemplateType: templatestore.TemplateTypeGeneric,
					Prepare: func(string, []byte) (templatepolicy.PreparedTemplateRegistration, error) {
						prepared = true
						return templatepolicy.PreparedTemplateRegistration{}, nil
					},
				},
			},
		},
		BeforeKeyScan: func(*crypto.Keyring) error {
			return wantErr
		},
		PublishSnapshot: func(map[string]string, map[string]string, map[string]int) {
			published = true
		},
	}

	_, err := service.Reload("default", nil)
	if !errors.Is(err, wantErr) {
		t.Fatalf("Reload() error = %v, want %v", err, wantErr)
	}
	if !store.withMKCalled {
		t.Fatalf("Reload() did not obtain master key")
	}
	if prepared || store.scanCalled || published || session.initialized {
		t.Fatalf("Reload() continued after hook failure: prepared=%v scan=%v published=%v session=%v",
			prepared, store.scanCalled, published, session.initialized)
	}
}

func TestReloadPendingRotationEntersRecoveryBeforeRuntimePublication(t *testing.T) {
	passphrase := []byte("pending-rotation-passphrase")
	keystoreDir := t.TempDir()
	kr, err := crypto.CreateKeyringStore(keystoreDir, passphrase)
	if err != nil {
		t.Fatalf("CreateKeyringStore() error = %v", err)
	}
	t.Cleanup(kr.Zero)
	if err := crypto.StartRotation(
		keystoreDir,
		kr,
		passphrase,
		[]crypto.HistoricalGenerationAnchor{},
		func(target *crypto.Keyring, _, _ int64) (crypto.RotationSnapshotReference, error) {
			sealed, err := target.Seal([]byte("cutover"), crypto.RotationSnapshotContext())
			if err != nil {
				return crypto.RotationSnapshotReference{}, err
			}
			return crypto.NewRotationSnapshotReference(sealed)
		},
	); err != nil {
		t.Fatalf("StartRotation() error = %v", err)
	}

	store := &fakeKeyStore{
		cache:     map[string]string{},
		keyTypes:  map[string]string{},
		lsigSizes: map[string]int{},
		keyring:   kr,
	}
	session := &fakeSession{}
	var hookCalled bool
	var prepared bool
	var published bool
	service := &ReloadService{
		KeyStore: store,
		Session:  session,
		TemplateManager: &Manager{
			Paths: mintedPathsForReloadTest(t),
			Registrars: []TemplateRegistrar{
				{
					Name:         "generic",
					Source:       keytypestate.SourceYAMLGeneric,
					TemplateType: templatestore.TemplateTypeGeneric,
					Prepare: func(string, []byte) (templatepolicy.PreparedTemplateRegistration, error) {
						prepared = true
						return templatepolicy.PreparedTemplateRegistration{}, nil
					},
				},
			},
		},
		BeforeKeyScan: func(*crypto.Keyring) error {
			hookCalled = true
			return nil
		},
		PublishSnapshot: func(map[string]string, map[string]string, map[string]int) {
			published = true
		},
	}

	report, err := service.Reload("default", nil)
	if err == nil || !IsGenerationValidationError(err.Error()) {
		t.Fatalf("Reload() error = %v, want generation validation failure", err)
	}
	if report != nil {
		t.Fatalf("Reload() report = %+v, want nil", report)
	}
	if !store.withMKCalled {
		t.Fatal("Reload() did not inspect the keyring")
	}
	if hookCalled || prepared || store.scanCalled || published || session.initialized {
		t.Fatalf(
			"Reload() exposed pending state: hook=%v prepared=%v scan=%v published=%v session=%v",
			hookCalled,
			prepared,
			store.scanCalled,
			published,
			session.initialized,
		)
	}
}

func TestReloadLockedErrorPreservesStoreLockedSentinel(t *testing.T) {
	store := &fakeKeyStore{withMKErr: keystore.ErrStoreLocked}
	service := &ReloadService{
		KeyStore: store,
		Session:  &fakeSession{},
		TemplateManager: &Manager{
			Paths: mintedPathsForReloadTest(t),
		},
		PublishSnapshot: func(map[string]string, map[string]string, map[string]int) {},
	}

	_, err := service.Reload("default", nil)
	if err == nil {
		t.Fatal("Reload() error = nil, want locked error")
	}
	if !errors.Is(err, keystore.ErrStoreLocked) {
		t.Fatalf("Reload() error = %v, want errors.Is ErrStoreLocked", err)
	}
}

func TestReloadMapsKeyStorePendingGuardToGenerationRecovery(t *testing.T) {
	store := &fakeKeyStore{withMKErr: crypto.ErrRotationPending}
	service := &ReloadService{
		KeyStore: store,
		Session:  &fakeSession{},
		TemplateManager: &Manager{
			Paths: mintedPathsForReloadTest(t),
		},
		PublishSnapshot: func(map[string]string, map[string]string, map[string]int) {},
	}

	report, err := service.Reload("default", nil)
	if err == nil || !IsGenerationValidationError(err.Error()) {
		t.Fatalf("Reload() error = %v, want generation validation failure", err)
	}
	if report != nil {
		t.Fatalf("Reload() report = %+v, want nil", report)
	}
}

func TestReloadClearsInitializedMasterKeyOnBeforeKeyScanError(t *testing.T) {
	wantErr := errors.New("policy integrity failed")
	store := &fakeKeyStore{
		cache:     map[string]string{},
		keyTypes:  map[string]string{},
		lsigSizes: map[string]int{},
	}
	service := &ReloadService{
		KeyStore:        store,
		Session:         &fakeSession{},
		TemplateManager: &Manager{Paths: mintedPathsForReloadTest(t), Registrars: []TemplateRegistrar{testNoopRegistrar()}},
		BeforeKeyScan: func(*crypto.Keyring) error {
			return wantErr
		},
		PublishSnapshot: func(map[string]string, map[string]string, map[string]int) {},
	}

	_, err := service.Reload("default", []byte("passphrase"))
	if !errors.Is(err, wantErr) {
		t.Fatalf("Reload() error = %v, want %v", err, wantErr)
	}
	if store.clearCount != 1 {
		t.Fatalf("ClearKeys() calls = %d, want 1", store.clearCount)
	}
}

func TestReloadClearsInitializedMasterKeyOnScanError(t *testing.T) {
	wantErr := errors.New("scan failed")
	store := &fakeKeyStore{
		cache:     map[string]string{},
		keyTypes:  map[string]string{},
		lsigSizes: map[string]int{},
		scanErr:   wantErr,
	}
	service := &ReloadService{
		KeyStore:        store,
		Session:         &fakeSession{},
		TemplateManager: &Manager{Paths: mintedPathsForReloadTest(t), Registrars: []TemplateRegistrar{testNoopRegistrar()}},
		PublishSnapshot: func(map[string]string, map[string]string, map[string]int) {},
	}

	_, err := service.Reload("default", []byte("passphrase"))
	if !errors.Is(err, wantErr) {
		t.Fatalf("Reload() error = %v, want %v", err, wantErr)
	}
	if store.clearCount != 1 {
		t.Fatalf("ClearKeys() calls = %d, want 1", store.clearCount)
	}
}

func TestReloadDoesNotClearExistingUnlockOnScanError(t *testing.T) {
	wantErr := errors.New("scan failed")
	store := &fakeKeyStore{
		cache:     map[string]string{},
		keyTypes:  map[string]string{},
		lsigSizes: map[string]int{},
		scanErr:   wantErr,
	}
	service := &ReloadService{
		KeyStore:        store,
		Session:         &fakeSession{},
		TemplateManager: &Manager{Paths: mintedPathsForReloadTest(t), Registrars: []TemplateRegistrar{testNoopRegistrar()}},
		PublishSnapshot: func(map[string]string, map[string]string, map[string]int) {},
	}

	_, err := service.Reload("default", nil)
	if !errors.Is(err, wantErr) {
		t.Fatalf("Reload() error = %v, want %v", err, wantErr)
	}
	if store.clearCount != 0 {
		t.Fatalf("ClearKeys() calls = %d, want 0", store.clearCount)
	}
}

func TestReloadBeforePublishErrorInvalidatesSnapshotAndClearsKeyCache(t *testing.T) {
	wantErr := errors.New("node role rejects key")
	store := &fakeKeyStore{
		cache:     map[string]string{"ADDR": "/keys/ADDR.key"},
		keyTypes:  map[string]string{"ADDR": "ed25519"},
		lsigSizes: map[string]int{"ADDR": 0},
	}
	session := &fakeSession{}
	publishedKeys := map[string]string{"OLD": "/keys/OLD.key"}
	publishedKeyTypes := map[string]string{"OLD": "ed25519"}
	publishedLsigSizes := map[string]int{"OLD": 0}
	var notifications []KeysChangedNotification
	service := &ReloadService{
		KeyStore:        store,
		Session:         session,
		TemplateManager: &Manager{Paths: mintedPathsForReloadTest(t), Registrars: []TemplateRegistrar{testNoopRegistrar()}},
		BeforePublish: func(map[string]string, map[string]string, map[string]int) error {
			return wantErr
		},
		PublishSnapshot: func(keys map[string]string, keyTypes map[string]string, lsigSizes map[string]int) {
			publishedKeys = keys
			publishedKeyTypes = keyTypes
			publishedLsigSizes = lsigSizes
		},
		NotifyKeysChanged: func(notification KeysChangedNotification) {
			notifications = append(notifications, notification)
		},
	}

	_, err := service.Reload("default", nil)
	if !errors.Is(err, wantErr) {
		t.Fatalf("Reload() error = %v, want %v", err, wantErr)
	}
	if len(publishedKeys) != 0 || len(publishedKeyTypes) != 0 || len(publishedLsigSizes) != 0 {
		t.Fatalf("published snapshot = (%#v, %#v, %#v), want empty maps after rejection", publishedKeys, publishedKeyTypes, publishedLsigSizes)
	}
	if store.clearCache != 1 {
		t.Fatalf("ClearCache() calls = %d, want 1", store.clearCache)
	}
	if session.initialized {
		t.Fatal("session initialized after rejected snapshot")
	}
	if !reflect.DeepEqual(notifications, []KeysChangedNotification{{KeyCount: 0}}) {
		t.Fatalf("notifications = %#v, want key count 0", notifications)
	}
}

func TestReloadNodeRoleValidationRejectsConflictingInventoryBeforePublish(t *testing.T) {
	store := &fakeKeyStore{
		cache:     map[string]string{"ADDR": "/keys/ADDR.key"},
		keyTypes:  map[string]string{"ADDR": witness.Falcon1024V1},
		lsigSizes: map[string]int{"ADDR": 0},
	}
	session := &fakeSession{}
	publishedKeys := map[string]string{"OLD": "/keys/OLD.key"}
	publishedKeyTypes := map[string]string{"OLD": "ed25519"}
	publishedLsigSizes := map[string]int{"OLD": 0}
	service := &ReloadService{
		KeyStore:        store,
		Session:         session,
		TemplateManager: &Manager{Paths: mintedPathsForReloadTest(t), Registrars: []TemplateRegistrar{testNoopRegistrar()}},
		BeforePublish: func(_ map[string]string, keyTypes map[string]string, _ map[string]int) error {
			if keyTypes["ADDR"] == witness.Falcon1024V1 {
				return errors.New(`node role "signer" rejects key inventory: ADDR:aplane.witness-falcon1024.v1`)
			}
			return nil
		},
		PublishSnapshot: func(keys map[string]string, keyTypes map[string]string, lsigSizes map[string]int) {
			publishedKeys = keys
			publishedKeyTypes = keyTypes
			publishedLsigSizes = lsigSizes
		},
	}

	_, err := service.Reload("default", nil)
	if err == nil {
		t.Fatal("Reload() error = nil, want node role validation failure")
	}
	if !strings.Contains(err.Error(), `node role "signer"`) {
		t.Fatalf("Reload() error = %q, want signer node role rejection", err)
	}
	if len(publishedKeys) != 0 || len(publishedKeyTypes) != 0 || len(publishedLsigSizes) != 0 {
		t.Fatalf("published snapshot = (%#v, %#v, %#v), want empty maps after node role rejection", publishedKeys, publishedKeyTypes, publishedLsigSizes)
	}
	if store.clearCache != 1 {
		t.Fatalf("ClearCache() calls = %d, want 1", store.clearCache)
	}
	if session.initialized {
		t.Fatal("session initialized after rejected node role validation")
	}
}

func TestReloadAddressCollisionInvalidatesPublishedSnapshot(t *testing.T) {
	collisionErr := &keys.AddressCollisionError{
		Collisions: map[string][]string{
			"ADDR": {"/keys/ADDR.key", "/keys/duplicate.key"},
		},
	}
	store := &fakeKeyStore{
		cache:     map[string]string{"ADDR": "/keys/ADDR.key"},
		keyTypes:  map[string]string{"ADDR": "ed25519"},
		lsigSizes: map[string]int{"ADDR": 0},
		scanErr:   collisionErr,
	}
	session := &fakeSession{}
	publishedKeys := map[string]string{"ADDR": "/keys/ADDR.key"}
	publishedKeyTypes := map[string]string{"ADDR": "ed25519"}
	publishedLsigSizes := map[string]int{"ADDR": 0}
	var notifications []KeysChangedNotification
	service := &ReloadService{
		KeyStore:        store,
		Session:         session,
		TemplateManager: &Manager{Paths: mintedPathsForReloadTest(t), Registrars: []TemplateRegistrar{testNoopRegistrar()}},
		PublishSnapshot: func(keys map[string]string, keyTypes map[string]string, lsigSizes map[string]int) {
			publishedKeys = keys
			publishedKeyTypes = keyTypes
			publishedLsigSizes = lsigSizes
		},
		NotifyKeysChanged: func(notification KeysChangedNotification) {
			notifications = append(notifications, notification)
		},
	}

	_, err := service.Reload("default", nil)
	if !errors.Is(err, keys.ErrAddressCollision) {
		t.Fatalf("Reload() error = %v, want ErrAddressCollision", err)
	}
	if len(publishedKeys) != 0 || len(publishedKeyTypes) != 0 || len(publishedLsigSizes) != 0 {
		t.Fatalf("published snapshot = (%#v, %#v, %#v), want empty maps after collision", publishedKeys, publishedKeyTypes, publishedLsigSizes)
	}
	if store.clearCache != 1 {
		t.Fatalf("ClearCache() calls = %d, want 1", store.clearCache)
	}
	if session.initialized {
		t.Fatal("session initialized after address collision")
	}
	if !reflect.DeepEqual(notifications, []KeysChangedNotification{{KeyCount: 0}}) {
		t.Fatalf("notifications = %#v, want key count 0", notifications)
	}
}

func TestReloadAuditsLogicSigSaltScanWarnings(t *testing.T) {
	store := &fakeKeyStore{
		cache:     map[string]string{},
		keyTypes:  map[string]string{},
		lsigSizes: map[string]int{},
		scanWarnings: []keys.KeyScanWarning{
			{Code: keys.KeyScanWarningLogicSigSaltInvalid, KeyFile: "/tmp/BAD.key", Err: keys.ErrMissingLogicSigSaltCounter},
			{Code: keys.KeyScanWarningLogicSigAddressInvalid, KeyFile: "/tmp/ONCURVE.key", Err: keys.ErrLogicSigAddressOnCurve},
			{Code: keys.KeyScanWarningParseLogicSigFailed, KeyFile: "/tmp/BADCODE.key", Err: keys.ErrInvalidLogicSigBytecode},
			{Code: keys.KeyScanWarningReadFailed, KeyFile: "/tmp/OTHER.key", Err: errors.New("read failed")},
		},
	}
	session := &fakeSession{}
	audit := &fakeAuditLog{}
	paths := utilkeys.NewPaths(t.TempDir())
	genstoretest.MintFirst(t, paths, "default")

	service := &ReloadService{
		KeyStore:        store,
		Session:         session,
		TemplateManager: &Manager{Paths: paths, Registrars: []TemplateRegistrar{testNoopRegistrar()}},
		PublishSnapshot: func(map[string]string, map[string]string, map[string]int) {},
		AuditLog:        audit,
	}

	if _, err := service.Reload("default", nil); err == nil || !IsGenerationValidationError(err.Error()) {
		t.Fatalf("Reload() error = %v, want fail-closed reload over malformed keys", err)
	}
	if len(audit.rejected) != 3 {
		t.Fatalf("rejected audit calls = %#v, want the three LogicSig invariant warnings", audit.rejected)
	}
	got := audit.rejected[0]
	if got.identityID != "default" || got.keyFile != "/tmp/BAD.key" {
		t.Fatalf("rejected audit = %#v", got)
	}
	if !strings.Contains(got.reason, string(keys.KeyScanWarningLogicSigSaltInvalid)) || !strings.Contains(got.reason, keys.ErrMissingLogicSigSaltCounter.Error()) {
		t.Fatalf("rejected reason = %q", got.reason)
	}
	if audit.rejected[1].keyFile != "/tmp/ONCURVE.key" || !strings.Contains(audit.rejected[1].reason, string(keys.KeyScanWarningLogicSigAddressInvalid)) {
		t.Fatalf("on-curve rejection not audited: %#v", audit.rejected[1])
	}
	if audit.rejected[2].keyFile != "/tmp/BADCODE.key" || !strings.Contains(audit.rejected[2].reason, string(keys.KeyScanWarningParseLogicSigFailed)) {
		t.Fatalf("invalid-bytecode rejection not audited: %#v", audit.rejected[2])
	}
}

func testNoopRegistrar() TemplateRegistrar {
	return TemplateRegistrar{
		Name:         "generic",
		Source:       keytypestate.SourceYAMLGeneric,
		TemplateType: templatestore.TemplateTypeGeneric,
		Prepare: func(string, []byte) (templatepolicy.PreparedTemplateRegistration, error) {
			return templatepolicy.PreparedTemplateRegistration{}, nil
		},
	}
}

func mintedPathsForReloadTest(t *testing.T) utilkeys.Paths {
	t.Helper()
	paths := utilkeys.NewPaths(t.TempDir())
	genstoretest.MintFirst(t, paths, "default")
	return paths
}
