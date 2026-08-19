// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package startup

import (
	"errors"
	"fmt"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"sync"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keyclass"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/signerapp/approval"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	"github.com/aplane-algo/aplane/internal/signerapp/policyruntime"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/tokenfile"

	"github.com/aplane-algo/aplane/internal/auth"
)

// IdentityBuildOptions describes the config and paths needed to construct all
// signer identity runtimes for process startup.
type IdentityBuildOptions struct {
	DataDir               string
	KeyPaths              storepaths.Paths
	Config                *serverconfig.ServerConfig
	DefaultSessionTimeout time.Duration
	ProductIdentityID     string
}

// IdentityBuildHooks provides the non-owning process callbacks needed by
// identity runtime assembly.
type IdentityBuildHooks struct {
	HasAdminClient               func() bool
	SendSignRequest              func(req *approval.SignRequest) bool
	SendSignRequestCanceled      func(msg *approval.SignRequestCanceled) bool
	SendTokenProvisioningRequest func(req *approval.TokenProvisioningRequest) bool
	NotifyLocked                 func()
	NotifyKeysChanged            func(keyCount int)
	ReloadAuditLog               signertemplates.AuditLogger
	NodeFailClosed               func(error)
	// ReloadMutationLock returns the process-wide store mutation lock that
	// watcher-triggered reloads must hold while scanning disk.
	ReloadMutationLock func() sync.Locker
	Info               func(string)
	Warn               func(string)
}

// BuildProductRuntime validates the product layout and constructs the one
// process-owned identity runtime.
func BuildProductRuntime(opts IdentityBuildOptions, hooks IdentityBuildHooks) (*identity.Runtime, error) {
	if err := identity.ValidateProductIdentityLayout(opts.DataDir, opts.ProductIdentityID); err != nil {
		return nil, err
	}
	return BuildIdentityRuntime(opts, hooks, opts.ProductIdentityID)
}

// BuildIdentityRuntime constructs one identity runtime. Product startup should
// use BuildProductRuntime so layout validation cannot be skipped.
func BuildIdentityRuntime(opts IdentityBuildOptions, hooks IdentityBuildHooks, identityID string) (*identity.Runtime, error) {
	nodeDoc, _, err := noderole.Load(opts.KeyPaths)
	if err != nil {
		return nil, fmt.Errorf("failed to load node role for identity %q: %w", identityID, err)
	}

	storedCfg, err := identity.LoadStoredConfig(opts.DataDir)
	if err != nil {
		return nil, fmt.Errorf("failed to load config for identity %q: %w", identityID, err)
	}
	tokenPath := tokenfile.GetAPlaneTokenPathForRoot(opts.KeyPaths.Root())
	token, err := tokenfile.ReadToken(tokenPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read token for identity %q: %w", identityID, err)
	}
	if token == "" {
		if identityID != opts.ProductIdentityID {
			return nil, fmt.Errorf("identity %q is missing token file: %s", identityID, tokenPath)
		}
		token, err = tokenfile.LoadAPlaneToken(opts.KeyPaths.Root())
		if err != nil {
			return nil, fmt.Errorf("failed to load token for identity %q: %w", identityID, err)
		}
	}

	defaultApprovalWait, err := serverconfig.ParseApprovalWait(opts.Config.ApprovalWait)
	if err != nil {
		return nil, fmt.Errorf("invalid approval_wait for identity %q: %w", identityID, err)
	}

	effectiveCfg, err := storedCfg.Apply(identity.ConfigDefaults{
		UserAutoApprove:  opts.Config.UserAutoApprove,
		LockOnDisconnect: opts.Config.ShouldLockOnDisconnect(),
		SessionTimeout:   opts.DefaultSessionTimeout,
		ApprovalWait:     defaultApprovalWait,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to resolve config for identity %q: %w", identityID, err)
	}
	userAutoApprove := effectiveCfg.UserAutoApprove
	lockOnDisconnect := effectiveCfg.LockOnDisconnect
	sessionTimeout := effectiveCfg.SessionTimeout
	approvalWait := effectiveCfg.ApprovalWait

	unlockCfg, unlockErr := ResolveUnlockConfig(opts.DataDir, opts.Config)
	if unlockErr != nil {
		return nil, fmt.Errorf("failed to load unlock config for identity %q: %w", identityID, unlockErr)
	}
	if unlockCfg != nil {
		lockOnDisconnect = false
		sessionTimeout = 0
	}

	ir := identity.New(identity.Config{
		ID:               identityID,
		KeyStore:         keystore.NewFileKeyStoreForPaths(opts.KeyPaths),
		KeyPaths:         opts.KeyPaths,
		Authenticator:    auth.NewTokenAuthenticator(token),
		SessionTimeout:   sessionTimeout,
		ApprovalWait:     approvalWait,
		UserAutoApprove:  &userAutoApprove,
		LockOnDisconnect: lockOnDisconnect,
		NodeRole:         nodeDoc.Role,
		OnLocked: func() {
			if hooks.NotifyLocked != nil {
				hooks.NotifyLocked()
			}
		},
	})

	WireReloadFunc(ir, opts, hooks)
	WireApprovalCoordinator(ir, hooks)
	return ir, nil
}

// WireApprovalCoordinator creates and installs an approval coordinator on the
// identity runtime using the process hooks.
func WireApprovalCoordinator(ir *identity.Runtime, hooks IdentityBuildHooks) {
	coordinator := approval.New(
		func() bool {
			if hooks.HasAdminClient == nil {
				return false
			}
			return hooks.HasAdminClient()
		},
		func(msg *approval.SignRequest) bool {
			if hooks.SendSignRequest == nil {
				return false
			}
			return hooks.SendSignRequest(msg)
		},
		func(msg *approval.SignRequestCanceled) bool {
			if hooks.SendSignRequestCanceled == nil {
				return false
			}
			return hooks.SendSignRequestCanceled(msg)
		},
		func(msg *approval.TokenProvisioningRequest) bool {
			if hooks.SendTokenProvisioningRequest == nil {
				return false
			}
			return hooks.SendTokenProvisioningRequest(msg)
		},
	)
	ir.SetApprovalCoordinator(coordinator)
}

// NewReloadService builds the template reload service for an identity runtime
// using the process options and hooks. The session parameter is passed
// directly because reload callers already hold passphraseLock; this function
// must not call ir.SnapshotKeySession().
func NewReloadService(ir *identity.Runtime, opts IdentityBuildOptions, hooks IdentityBuildHooks, session *keystore.KeySession) *signertemplates.ReloadService {
	identityID := ir.ID()
	svc := &signertemplates.ReloadService{
		KeyStore:        ir.KeyStore(),
		Session:         session,
		TemplateManager: newTemplateManager(ir.KeyPaths()),
		BeforeKeyScan: func(kr *crypto.Keyring) error {
			if verifiedRole, err := noderole.LoadAndVerifyWithKeyring(opts.KeyPaths, kr); err != nil {
				return fmt.Errorf("node role verification failed for identity %q: %w", identityID, err)
			} else if verifiedRole.Role != ir.NodeRole() {
				return fmt.Errorf("node role verification failed for identity %q: runtime role %q does not match verified role %q", identityID, ir.NodeRole(), verifiedRole.Role)
			}
			storedPolicy, effectivePolicy, err := policyruntime.LoadVerifiedForNodeRoleWithStored(ir.NodeRole(), opts.DataDir, opts.Config, kr)
			if err != nil {
				return fmt.Errorf("policy verification failed for identity %q: %w", identityID, err)
			}
			switch ir.NodeRole() {
			case noderole.RoleSentry:
				ir.SetPolicyState(nil, nil)
				ir.SetSentryPolicyState(storedPolicy, effectivePolicy)
			default:
				ir.SetPolicyState(storedPolicy, effectivePolicy)
				ir.SetSentryPolicyState(nil, nil)
			}
			return nil
		},
		BeforePublish: func(_ map[string]string, keyTypes map[string]string) error {
			if err := keyclass.ValidateKeyTypesAllowedForNodeRole(ir.NodeRole(), keyTypes); err != nil {
				if errors.Is(err, keyclass.ErrNodeRoleConflict) && hooks.NodeFailClosed != nil {
					hooks.NodeFailClosed(fmt.Errorf("node role inventory conflict for identity %q: %w", identityID, err))
				}
				return err
			}
			return nil
		},
		PublishSnapshot: ir.PublishSnapshot,
		AuditLog:        hooks.ReloadAuditLog,
		Info:            hooks.Info,
		Warn:            hooks.Warn,
	}
	if hooks.NotifyKeysChanged != nil {
		svc.NotifyKeysChanged = func(notification signertemplates.KeysChangedNotification) {
			hooks.NotifyKeysChanged(notification.KeyCount)
		}
	}
	return svc
}

// WireReloadFunc configures the reload function and the watcher reload
// mutation lock on an identity runtime.
func WireReloadFunc(ir *identity.Runtime, opts IdentityBuildOptions, hooks IdentityBuildHooks) {
	ir.SetReloadFunc(func(passphrase []byte, session *keystore.KeySession) (*signertemplates.ReloadReport, error) {
		svc := NewReloadService(ir, opts, hooks, session)
		return svc.Reload(passphrase)
	})
	if hooks.ReloadMutationLock != nil {
		ir.SetReloadMutationLock(func() sync.Locker {
			return hooks.ReloadMutationLock()
		})
	}
}

func newTemplateManager(keyPaths storepaths.Paths) *signertemplates.Manager {
	return signertemplates.NewManager(keyPaths)
}
