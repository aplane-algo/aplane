// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"errors"
	"fmt"
	"sync"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/keyclass"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	"github.com/aplane-algo/aplane/internal/signerapp/policyruntime"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
)

// newReloadServiceForIdentity creates a template reload service wired to the
// given identity runtime and process-root services.
// The session parameter is passed directly because the caller already holds
// passphraseLock; this function must not call ir.SnapshotKeySession().
func (fs *Signer) newReloadServiceForIdentity(ir *identity.Runtime, session *keystore.KeySession) *signertemplates.ReloadService {
	var auditLog signertemplates.AuditLogger
	if fs.auditLog != nil {
		auditLog = fs.auditLog
	}

	var notifyKeysChanged signertemplates.NotifyKeysChangedFunc
	if hub := fs.adminHub(); hub != nil {
		notifyKeysChanged = func(notification signertemplates.KeysChangedNotification) {
			hub.NotifyKeysChanged(ir.ID(), adminproto.KeysChangedNotification{KeyCount: notification.KeyCount})
		}
	}

	return &signertemplates.ReloadService{
		KeyStore:        ir.KeyStore(),
		Session:         session,
		TemplateManager: signertemplates.NewManager(ir.KeyPaths()),
		BeforeKeyScan: func(masterKey []byte) error {
			if verifiedRole, err := noderole.LoadAndVerifyWithMasterKey(ir.KeyPaths(), ir.ID(), masterKey); err != nil {
				return fmt.Errorf("node role verification failed for identity %q: %w", ir.ID(), err)
			} else if verifiedRole.Role != ir.NodeRole() {
				return fmt.Errorf("node role verification failed for identity %q: runtime role %q does not match verified role %q", ir.ID(), ir.NodeRole(), verifiedRole.Role)
			}
			storedPolicy, effectivePolicy, err := policyruntime.LoadVerifiedForNodeRoleWithStored(ir.NodeRole(), fs.dataDir, ir.ID(), fs.config, masterKey)
			if err != nil {
				return fmt.Errorf("policy verification failed for identity %q: %w", ir.ID(), err)
			}
			switch ir.NodeRole() {
			case noderole.RoleAttestor:
				ir.SetPolicyState(nil, nil)
				ir.SetAttestationPolicyState(storedPolicy, effectivePolicy)
			default:
				ir.SetPolicyState(storedPolicy, effectivePolicy)
				ir.SetAttestationPolicyState(nil, nil)
			}
			return nil
		},
		BeforePublish: func(_ map[string]string, keyTypes map[string]string, _ map[string]int) error {
			if err := keyclass.ValidateKeyTypesAllowedForNodeRole(ir.NodeRole(), keyTypes); err != nil {
				if errors.Is(err, keyclass.ErrNodeRoleConflict) && fs.registry != nil {
					fs.registry.CloseFailClosed(fmt.Errorf("node role inventory conflict for identity %q: %w", ir.ID(), err))
				}
				return err
			}
			return nil
		},
		PublishSnapshot:   ir.PublishSnapshot,
		AuditLog:          auditLog,
		NotifyKeysChanged: notifyKeysChanged,
		Info: func(msg string) {
			logInfof("%s", msg)
		},
		Warn: func(msg string) {
			logWarnf("%s", msg)
		},
	}
}

// wireReloadFunc configures the reload function on an identity runtime.
// This must be called after the Signer's ipcServer and auditLog are initialized.
func (fs *Signer) wireReloadFunc(ir *identity.Runtime) {
	ir.SetReloadFunc(func(identityID string, passphrase []byte, session *keystore.KeySession) (*signertemplates.ReloadReport, error) {
		svc := fs.newReloadServiceForIdentity(ir, session)
		return svc.Reload(identityID, passphrase)
	})
	ir.SetReloadMutationLock(func() sync.Locker {
		return fs.storeMutationLock(ir.ID())
	})
}
