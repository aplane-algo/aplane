// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package startup

import (
	"fmt"
	"sort"
	"time"

	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/signerapp/approval"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	"github.com/aplane-algo/aplane/internal/signerapp/policyruntime"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/tokenfile"

	"github.com/aplane-algo/aplane/internal/auth"
	apconfig "github.com/aplane-algo/aplane/internal/config"
)

// IdentityBuildOptions describes the config and paths needed to construct all
// signer identity runtimes for process startup.
type IdentityBuildOptions struct {
	DataDir               string
	KeyPaths              storepaths.Paths
	Config                *apconfig.ServerConfig
	DefaultSessionTimeout time.Duration
	ProductIdentityID     string
}

// IdentityBuildHooks provides the non-owning process callbacks needed by
// identity runtime assembly.
type IdentityBuildHooks struct {
	HasAdminClient               func(identityID string) bool
	SendSignRequest              func(identityID string, req *approval.SignRequest) bool
	SendSignRequestCanceled      func(identityID string, msg *approval.SignRequestCanceled) bool
	SendTokenProvisioningRequest func(identityID string, req *approval.TokenProvisioningRequest) bool
	NotifyLocked                 func(identityID string)
	NotifyKeysChanged            func(identityID string, keyCount int)
	ReloadAuditLog               signertemplates.AuditLogger
	Info                         func(string)
	Warn                         func(string)
}

// BuildRegistry discovers and constructs all startup identity runtimes,
// registering them into the provided registry and returning the product
// identity runtime.
func BuildRegistry(reg *identity.Registry, opts IdentityBuildOptions, hooks IdentityBuildHooks) (*identity.Runtime, error) {
	ids, err := StartupIdentityIDs(opts.DataDir, opts.ProductIdentityID)
	if err != nil {
		return nil, err
	}

	var product *identity.Runtime
	for _, identityID := range ids {
		ir, err := BuildIdentityRuntime(reg, opts, hooks, identityID)
		if err != nil {
			return nil, err
		}
		if identityID == opts.ProductIdentityID {
			product = ir
		}
	}
	if product == nil {
		return nil, fmt.Errorf("product identity runtime missing: %s", opts.ProductIdentityID)
	}
	return product, nil
}

// StartupIdentityIDs returns the discovered, non-decommissioned identities
// present at startup, always including the product identity.
func StartupIdentityIDs(dataDir string, productID string) ([]string, error) {
	discovered, err := identity.DiscoverIdentities(dataDir)
	if err != nil {
		return nil, err
	}

	seen := make(map[string]bool, len(discovered)+1)
	ids := make([]string, 0, len(discovered)+1)
	for _, id := range discovered {
		storedCfg, cfgErr := identity.LoadStoredConfig(dataDir, id)
		if cfgErr != nil {
			return nil, fmt.Errorf("load config for identity %q: %w", id, cfgErr)
		}
		if storedCfg.IsDecommissioned() {
			if id == productID {
				return nil, fmt.Errorf("product identity %q is decommissioned", id)
			}
			continue
		}
		if !seen[id] {
			ids = append(ids, id)
			seen[id] = true
		}
	}

	if !seen[productID] {
		ids = append(ids, productID)
	}

	sort.Strings(ids)
	return ids, nil
}

// BuildIdentityRuntime constructs and registers one identity runtime.
func BuildIdentityRuntime(reg *identity.Registry, opts IdentityBuildOptions, hooks IdentityBuildHooks, identityID string) (*identity.Runtime, error) {
	nodeDoc, _, err := noderole.Load(opts.KeyPaths)
	if err != nil {
		return nil, fmt.Errorf("failed to load node role for identity %q: %w", identityID, err)
	}

	storedCfg, err := identity.LoadStoredConfig(opts.DataDir, identityID)
	if err != nil {
		return nil, fmt.Errorf("failed to load config for identity %q: %w", identityID, err)
	}
	if storedCfg.IsDecommissioned() {
		return nil, fmt.Errorf("identity %q is decommissioned", identityID)
	}

	tokenPath := tokenfile.GetAPlaneTokenPathForRoot(opts.KeyPaths.Root(), identityID)
	token, err := tokenfile.ReadToken(tokenPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read token for identity %q: %w", identityID, err)
	}
	if token == "" {
		if identityID != opts.ProductIdentityID {
			return nil, fmt.Errorf("identity %q is missing token file: %s", identityID, tokenPath)
		}
		token, err = tokenfile.LoadAPlaneToken(opts.KeyPaths.Root(), identityID)
		if err != nil {
			return nil, fmt.Errorf("failed to load token for identity %q: %w", identityID, err)
		}
	}

	defaultApprovalWait, err := apconfig.ParseApprovalWait(opts.Config.ApprovalWait)
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

	unlockCfg, unlockErr := ResolveUnlockConfig(opts.DataDir, identityID, opts.Config)
	if unlockErr != nil {
		return nil, fmt.Errorf("failed to load unlock config for identity %q: %w", identityID, unlockErr)
	}
	if unlockCfg != nil {
		lockOnDisconnect = false
		sessionTimeout = 0
	}

	ir := identity.New(identity.Config{
		ID:               identityID,
		KeyStore:         keystore.NewFileKeyStoreForPaths(opts.KeyPaths, identityID),
		KeyPaths:         opts.KeyPaths,
		Authenticator:    auth.NewTokenAuthenticator(token),
		SessionTimeout:   sessionTimeout,
		ApprovalWait:     approvalWait,
		UserAutoApprove:  &userAutoApprove,
		LockOnDisconnect: lockOnDisconnect,
		NodeRole:         nodeDoc.Role,
		PersistDecommission: func(id string) error {
			return identity.SaveStoredSetting(opts.DataDir, id, "decommissioned", true)
		},
		OnLocked: func() {
			if hooks.NotifyLocked != nil {
				hooks.NotifyLocked(identityID)
			}
		},
	})

	if err := reg.Register(ir); err != nil {
		return nil, err
	}

	wireReloadFunc(ir, opts, hooks)
	wireApprovalCoordinator(ir, hooks)
	return ir, nil
}

func wireApprovalCoordinator(ir *identity.Runtime, hooks IdentityBuildHooks) {
	identityID := ir.ID()
	coordinator := approval.New(
		func() bool {
			if hooks.HasAdminClient == nil {
				return false
			}
			return hooks.HasAdminClient(identityID)
		},
		func(msg *approval.SignRequest) bool {
			if hooks.SendSignRequest == nil {
				return false
			}
			return hooks.SendSignRequest(identityID, msg)
		},
		func(msg *approval.SignRequestCanceled) bool {
			if hooks.SendSignRequestCanceled == nil {
				return false
			}
			return hooks.SendSignRequestCanceled(identityID, msg)
		},
		func(msg *approval.TokenProvisioningRequest) bool {
			if hooks.SendTokenProvisioningRequest == nil {
				return false
			}
			return hooks.SendTokenProvisioningRequest(identityID, msg)
		},
	)
	ir.SetApprovalCoordinator(coordinator)
}

func wireReloadFunc(ir *identity.Runtime, opts IdentityBuildOptions, hooks IdentityBuildHooks) {
	ir.SetReloadFunc(func(identityID string, passphrase []byte, session *keystore.KeySession) (*signertemplates.ReloadReport, error) {
		svc := &signertemplates.ReloadService{
			KeyStore:        ir.KeyStore(),
			Session:         session,
			TemplateManager: newTemplateManager(ir.KeyPaths()),
			BeforeKeyScan: func(masterKey []byte) error {
				if verifiedRole, err := noderole.LoadAndVerifyWithMasterKey(opts.KeyPaths, identityID, masterKey); err != nil {
					return fmt.Errorf("node role verification failed for identity %q: %w", identityID, err)
				} else if verifiedRole.Role != ir.NodeRole() {
					return fmt.Errorf("node role verification failed for identity %q: runtime role %q does not match verified role %q", identityID, ir.NodeRole(), verifiedRole.Role)
				}
				storedPolicy, effectivePolicy, err := policyruntime.LoadVerifiedWithStored(opts.DataDir, identityID, opts.Config, masterKey)
				if err != nil {
					return fmt.Errorf("policy verification failed for identity %q: %w", identityID, err)
				}
				storedAttestation, effectiveAttestation, err := policyruntime.LoadVerifiedAttestationWithStored(opts.DataDir, identityID, opts.Config, masterKey)
				if err != nil {
					return fmt.Errorf("attestation policy verification failed for identity %q: %w", identityID, err)
				}
				ir.SetPolicyState(storedPolicy, effectivePolicy)
				ir.SetAttestationPolicyState(storedAttestation, effectiveAttestation)
				return nil
			},
			BeforePublish: func(_ map[string]string, keyTypes map[string]string, _ map[string]int) error {
				return identity.ValidateKeyTypesAllowedForNodeRole(ir.NodeRole(), keyTypes)
			},
			PublishSnapshot: ir.PublishSnapshot,
			AuditLog:        hooks.ReloadAuditLog,
			Info:            hooks.Info,
			Warn:            hooks.Warn,
		}
		if hooks.NotifyKeysChanged != nil {
			svc.NotifyKeysChanged = func(notification signertemplates.KeysChangedNotification) {
				hooks.NotifyKeysChanged(identityID, notification.KeyCount)
			}
		}
		return svc.Reload(identityID, passphrase)
	})
}

func newTemplateManager(keyPaths storepaths.Paths) *signertemplates.Manager {
	return signertemplates.NewManager(keyPaths)
}
