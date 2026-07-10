// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package templates

import (
	"errors"
	"fmt"

	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keystore"
)

type KeyStore interface {
	InitializeMasterKey(passphrase []byte) ([]byte, error)
	WithMasterKey(fn func(masterKey []byte) error) error
	ClearMasterKey()
	Scan(passphrase []byte) error
	GetCache() map[string]string
	GetKeyTypes() map[string]string
	GetLsigSizes() map[string]int
}

type Session interface {
	InitializeSession()
}

type AuditLogger interface {
	LogKeyReload(identityID string, keyCount int)
	LogKeyRejected(identityID, keyFile, reason string)
}

type KeysChangedNotification struct {
	KeyCount int
}

type NotifyKeysChangedFunc func(notification KeysChangedNotification)
type BeforeKeyScanFunc func(masterKey []byte) error
type BeforePublishSnapshotFunc func(keys map[string]string, keyTypes map[string]string, lsigSizes map[string]int) error
type PublishSnapshotFunc func(keys map[string]string, keyTypes map[string]string, lsigSizes map[string]int)
type WarnFunc func(msg string)
type InfoFunc func(msg string)

// ReloadReport is a request-scoped projection of one identity reload. It
// describes what the reload accepted or rejected for callers such as template
// administration; it is not persisted and is not template/key-type state.
// Durable authority remains in encrypted template files and keytypestate
// records.
type ReloadReport struct {
	KeyCount         int
	TemplateNotices  []string
	TemplateWarnings []string
	RegistrationReport
}

type ReloadService struct {
	KeyStore          KeyStore
	Session           Session
	TemplateManager   *Manager
	BeforeKeyScan     BeforeKeyScanFunc
	BeforePublish     BeforePublishSnapshotFunc
	PublishSnapshot   PublishSnapshotFunc
	AuditLog          AuditLogger
	NotifyKeysChanged NotifyKeysChangedFunc
	Info              InfoFunc
	Warn              WarnFunc
}

func (s *ReloadService) Reload(identityID string, passphrase []byte) (*ReloadReport, error) {
	if s.KeyStore == nil || s.Session == nil || s.TemplateManager == nil || s.PublishSnapshot == nil {
		return nil, fmt.Errorf("reload service not fully configured")
	}

	report := &ReloadReport{}

	initializedMasterKey := false
	clearInitializedMasterKey := func() {
		if initializedMasterKey {
			s.KeyStore.ClearMasterKey()
			initializedMasterKey = false
		}
	}

	if len(passphrase) > 0 {
		if _, err := s.KeyStore.InitializeMasterKey(passphrase); err != nil {
			return nil, fmt.Errorf("failed to initialize master key: %w", err)
		}
		initializedMasterKey = true
	}

	var beforeKeyScanErr error
	if err := s.KeyStore.WithMasterKey(func(mk []byte) error {
		if s.BeforeKeyScan != nil {
			if err := s.BeforeKeyScan(mk); err != nil {
				beforeKeyScanErr = err
				return err
			}
		}
		registrationReport, err := s.TemplateManager.RegisterKeystoreTemplates(identityID, mk)
		if err != nil {
			return err
		}
		report.TemplateNotices = registrationReport.Notices()
		report.TemplateWarnings = registrationReport.Warnings()
		report.RegistrationReport = registrationReport
		for _, notice := range report.TemplateNotices {
			if s.Info != nil {
				s.Info(notice)
			} else {
				fmt.Printf("Info: %s\n", notice)
			}
		}
		for _, warning := range report.TemplateWarnings {
			if s.Warn != nil {
				s.Warn(warning)
			} else {
				fmt.Printf("Warning: %s\n", warning)
			}
		}
		return nil
	}); err != nil {
		clearInitializedMasterKey()
		if beforeKeyScanErr != nil {
			return nil, fmt.Errorf("reload pre-scan hook failed: %w", beforeKeyScanErr)
		}
		if errors.Is(err, keystore.ErrStoreLocked) {
			return nil, fmt.Errorf("signer is locked: %w", err)
		}
		return nil, fmt.Errorf("failed to register keystore templates: %w", err)
	}

	if err := s.KeyStore.Scan(nil); err != nil {
		clearInitializedMasterKey()
		if errors.Is(err, keys.ErrAddressCollision) {
			s.clearKeyCache()
			s.PublishSnapshot(map[string]string{}, map[string]string{}, map[string]int{})
			if s.NotifyKeysChanged != nil {
				s.NotifyKeysChanged(KeysChangedNotification{KeyCount: 0})
			}
		}
		return nil, fmt.Errorf("failed to rescan keys directory: %w", err)
	}
	s.auditRejectedLogicSigKeys(identityID)

	newKeysMap := s.KeyStore.GetCache()
	newKeyTypes := s.KeyStore.GetKeyTypes()
	newLsigSizes := s.KeyStore.GetLsigSizes()
	if s.BeforePublish != nil {
		if err := s.BeforePublish(newKeysMap, newKeyTypes, newLsigSizes); err != nil {
			clearInitializedMasterKey()
			s.clearKeyCache()
			s.PublishSnapshot(map[string]string{}, map[string]string{}, map[string]int{})
			if s.NotifyKeysChanged != nil {
				s.NotifyKeysChanged(KeysChangedNotification{KeyCount: 0})
			}
			return nil, fmt.Errorf("key snapshot rejected: %w", err)
		}
	}
	s.PublishSnapshot(newKeysMap, newKeyTypes, newLsigSizes)

	s.Session.InitializeSession()

	keyCount := len(newKeysMap)
	report.KeyCount = keyCount
	if s.AuditLog != nil {
		s.AuditLog.LogKeyReload(identityID, keyCount)
	}

	fmt.Printf("🔄 Keys reloaded: %d key(s) available\n", keyCount)

	if s.NotifyKeysChanged != nil {
		s.NotifyKeysChanged(KeysChangedNotification{KeyCount: keyCount})
	}

	return report, nil
}

func (s *ReloadService) clearKeyCache() {
	type keyCacheClearer interface {
		ClearCache()
	}
	if clearer, ok := s.KeyStore.(keyCacheClearer); ok {
		clearer.ClearCache()
	}
}

func (s *ReloadService) auditRejectedLogicSigKeys(identityID string) {
	if s.AuditLog == nil {
		return
	}
	provider, ok := s.KeyStore.(keys.KeyScanWarningProvider)
	if !ok {
		return
	}
	for _, warning := range provider.GetScanWarnings() {
		if !warning.IsLogicSigInvariantViolation() {
			continue
		}
		s.AuditLog.LogKeyRejected(identityID, warning.KeyFile, string(warning.Code)+": "+warning.Reason())
	}
}
