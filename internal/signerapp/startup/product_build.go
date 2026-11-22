// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package startup

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/aplane-algo/aplane/internal/asaset"
	"github.com/aplane-algo/aplane/internal/asasetstore"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keyclass"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policyadmission"
	"github.com/aplane-algo/aplane/internal/policycontext"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/signerapp/approval"
	"github.com/aplane-algo/aplane/internal/signerapp/policyruntime"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
	"github.com/aplane-algo/aplane/internal/signerapp/unlockconfig"
	"github.com/aplane-algo/aplane/internal/sourcetokens"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// ProductBuildOptions describes the config and paths needed to construct the
// process-owned product runtime.
type ProductBuildOptions struct {
	DataDir               string
	KeyPaths              storepaths.Paths
	Config                *serverconfig.ServerConfig
	DefaultSessionTimeout time.Duration
	// UnlockMethod is the unlock plan's method. Anything but
	// unlockconfig.MethodNone makes the runtime headless: no idle timeout and no
	// lock on disconnect.
	UnlockMethod string
}

// ProductBuildHooks provides the non-owning process callbacks needed by
// product runtime assembly.
type ProductBuildHooks struct {
	HasAdminClient          func() bool
	SendSignRequest         func(req *approval.SignRequest) bool
	SendSignRequestCanceled func(msg *approval.SignRequestCanceled) bool
	NotifyLocked            func()
	NotifyKeysChanged       func(keyCount int)
	ReloadAuditLog          signertemplates.AuditLogger
	NodeFailClosed          func(error)
	// ReloadMutationLock returns the process-wide store mutation lock that
	// watcher-triggered reloads must hold while scanning disk.
	ReloadMutationLock func() sync.Locker
	Info               func(string)
	Warn               func(string)
	// NotifyReloadRecovery is called with the defect after a reload without
	// the passphrase entered recovery for one.
	NotifyReloadRecovery func(cause error)
}

// BuildProductRuntime validates the product layout and constructs the one
// process-owned product runtime.
func BuildProductRuntime(opts ProductBuildOptions, hooks ProductBuildHooks) (*productruntime.Runtime, error) {
	if err := productruntime.ValidateProductStoreLayout(opts.DataDir); err != nil {
		return nil, err
	}
	nodeDoc, _, err := noderole.Load(opts.KeyPaths)
	if err != nil {
		return nil, fmt.Errorf("failed to load product node role: %w", err)
	}

	storedCfg, err := productruntime.LoadStoredConfig(opts.DataDir)
	if err != nil {
		return nil, fmt.Errorf("failed to load product config: %w", err)
	}
	defaultApprovalWait, err := serverconfig.ParseApprovalWait(opts.Config.ApprovalWait)
	if err != nil {
		return nil, fmt.Errorf("invalid product approval_wait: %w", err)
	}

	effectiveCfg, err := storedCfg.Apply(productruntime.EffectiveConfig{
		UserAutoApprove:  opts.Config.UserAutoApprove,
		LockOnDisconnect: opts.Config.ShouldLockOnDisconnect(),
		SessionTimeout:   opts.DefaultSessionTimeout,
		ApprovalWait:     defaultApprovalWait,
		Theme:            productruntime.DefaultTheme,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to resolve product config: %w", err)
	}
	userAutoApprove := effectiveCfg.UserAutoApprove
	lockOnDisconnect := effectiveCfg.LockOnDisconnect
	sessionTimeout := effectiveCfg.SessionTimeout
	approvalWait := effectiveCfg.ApprovalWait

	unlockMethod := opts.UnlockMethod
	if unlockMethod == "" {
		unlockMethod = unlockconfig.MethodNone
	}
	if unlockMethod != unlockconfig.MethodNone {
		lockOnDisconnect = false
		sessionTimeout = 0
	}

	ir := productruntime.New(productruntime.Config{
		KeyStore:         keystore.NewAtomicFileKeyStoreForPaths(opts.KeyPaths),
		KeyPaths:         opts.KeyPaths,
		SessionTimeout:   sessionTimeout,
		ApprovalWait:     approvalWait,
		UserAutoApprove:  &userAutoApprove,
		LockOnDisconnect: lockOnDisconnect,
		NodeRole:         nodeDoc.Role,
		UnlockMethod:     unlockMethod,
		OnLocked: func() {
			if hooks.NotifyLocked != nil {
				hooks.NotifyLocked()
			}
		},
	})

	ir.Config().SetGenerationRequirements(effectiveCfg.RequireContained, effectiveCfg.RequireCosigner)
	ir.Config().SetTheme(effectiveCfg.Theme)
	WireReloadFunc(ir, opts, hooks)
	WireApprovalCoordinator(ir, hooks)
	return ir, nil
}

// WireApprovalCoordinator creates and installs an approval coordinator on the
// product runtime using the process hooks.
func WireApprovalCoordinator(ir *productruntime.Runtime, hooks ProductBuildHooks) {
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
	)
	ir.SetApprovalCoordinator(coordinator)
}

// NewReloadService builds the template reload service for a product runtime
// using the process options and hooks. The session parameter is passed
// directly because reload callers already hold passphraseLock; this function
// must not call ir.SnapshotKeySession().
func NewReloadService(ir *productruntime.Runtime, opts ProductBuildOptions, hooks ProductBuildHooks, session *keystore.KeySession) *signertemplates.ReloadService {
	templateManager := signertemplates.NewManager(ir.KeyPaths(), ir.ProviderRegistry())
	svc := &signertemplates.ReloadService{
		KeyStore:        ir.KeyStore(),
		Session:         session,
		TemplateManager: templateManager,
		BeforeKeyScan: func(kr *crypto.Keyring) error {
			active, err := genstore.ResolveStoreRootWithKeyring(opts.KeyPaths, kr)
			if err != nil {
				return fmt.Errorf("authenticate active product generation: %w", err)
			}
			templateManager.ActivePaths = active
			if verifiedRole, err := noderole.LoadAndVerifyGenerationWithKeyring(opts.KeyPaths, active, kr); err != nil {
				return fmt.Errorf("node role verification failed for product store: %w", err)
			} else if verifiedRole.Role != ir.NodeRole() {
				return fmt.Errorf("node role verification failed: runtime role %q does not match verified role %q", ir.NodeRole(), verifiedRole.Role)
			}
			nodePolicy, err := policyruntime.Load(ir.NodeRole(), opts.Config, active, kr)
			if err != nil {
				return fmt.Errorf("policy verification failed for product store: %w", err)
			}
			// A present ASA set must authenticate: a damaged one is an
			// integrity failure, never the built-ins only.
			set, err := asasetstore.Load(active, kr)
			if err != nil {
				return fmt.Errorf("asa set verification failed for product store: %w", err)
			}
			// The verified policy is published before the tokens it serves
			// are read, so a reload that a damaged token file fails leaves
			// it published, as one a malformed key file fails does: the
			// recovery it enters shows and exports it. A damaged token
			// file is damage in the selected generation: the reload fails
			// as a generation validation failure, which the unlock paths
			// turn into recovery, where a restore can replace the file.
			// One on a signer node is a role conflict, which fails the
			// node closed as a forbidden key does.
			ir.SetVerifiedPolicyState(nodePolicy, set, storedAdmissionAlerts(ir.NodeRole(), opts.Config, set, nodePolicy))
			tokens, err := sourcetokens.LoadIndex(active, ir.NodeRole(), kr)
			if err != nil {
				switch {
				case errors.Is(err, keyclass.ErrNodeRoleConflict):
					if hooks.NodeFailClosed != nil {
						hooks.NodeFailClosed(fmt.Errorf("node role inventory conflict in product store: %w", err))
					}
				case errors.Is(err, sourcetokens.ErrDamaged):
					return fmt.Errorf("%w: source token verification failed for product store: %w",
						signertemplates.ErrGenerationValidation, err)
				}
				return fmt.Errorf("source token verification failed for product store: %w", err)
			}
			ir.PublishSourceTokens(tokens)
			return nil
		},
		BeforePublish: func(_ map[string]string, keyTypes map[string]string) error {
			if err := keyclass.ValidateKeyTypesAllowedForNodeRole(ir.NodeRole(), keyTypes); err != nil {
				if errors.Is(err, keyclass.ErrNodeRoleConflict) && hooks.NodeFailClosed != nil {
					hooks.NodeFailClosed(fmt.Errorf("node role inventory conflict in product store: %w", err))
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

// Build builds the generation the store root selects with kr, for a
// reload's publish (productruntime.BuildFunc), and changes no live state. It
// reads the store root once. The order is the one a failure needs: the
// selection first, so a failure after a root commit still says what the
// root selects; then the policy and the ASA set, so the recovery a later
// failure enters shows them; then the tokens, the templates, the key scan and
// the role check on its key types.
func Build(ir *productruntime.Runtime, opts ProductBuildOptions, kr *crypto.Keyring) (*productruntime.Loaded, error) {
	loaded := &productruntime.Loaded{}
	selected, err := genstore.AuthenticateStoreRootSelection(opts.KeyPaths, kr)
	if err != nil {
		return loaded, fmt.Errorf("failed to resolve active key store layout: authenticate store root selection: %w", err)
	}
	loaded.Selection = &selected
	if err := genstore.ValidateStoreRootSelection(selected); err != nil {
		return loaded, fmt.Errorf("authenticate active product generation: %w", err)
	}
	if verifiedRole, err := noderole.LoadAndVerifyGenerationWithKeyring(opts.KeyPaths, selected, kr); err != nil {
		return loaded, fmt.Errorf("node role verification failed for product store: %w", err)
	} else if verifiedRole.Role != ir.NodeRole() {
		return loaded, fmt.Errorf("node role verification failed: runtime role %q does not match verified role %q", ir.NodeRole(), verifiedRole.Role)
	}
	nodePolicy, err := policyruntime.Load(ir.NodeRole(), opts.Config, selected, kr)
	if err != nil {
		return loaded, fmt.Errorf("policy verification failed for product store: %w", err)
	}
	// A present ASA set must authenticate: a damaged one is an integrity
	// failure, never the built-ins only.
	set, err := asasetstore.Load(selected, kr)
	if err != nil {
		return loaded, fmt.Errorf("asa set verification failed for product store: %w", err)
	}
	loaded.Policy, loaded.ASASet = nodePolicy, set
	loaded.Alerts = storedAdmissionAlerts(ir.NodeRole(), opts.Config, set, nodePolicy)
	loaded.PolicyVerified = true

	// A damaged token file is damage in the selected generation, a
	// generation validation failure, which a restore can replace. One on a
	// signer node is a role conflict.
	tokens, err := sourcetokens.LoadIndex(selected, ir.NodeRole(), kr)
	if err != nil {
		if errors.Is(err, sourcetokens.ErrDamaged) && !errors.Is(err, keyclass.ErrNodeRoleConflict) {
			return loaded, fmt.Errorf("%w: source token verification failed for product store: %w",
				signertemplates.ErrGenerationValidation, err)
		}
		return loaded, fmt.Errorf("source token verification failed for product store: %w", err)
	}
	loaded.Tokens = tokens

	manager := signertemplates.NewManager(opts.KeyPaths, ir.ProviderRegistry())
	manager.ActivePaths = selected
	prepared, err := manager.PrepareKeystoreTemplates(kr)
	if err != nil {
		return loaded, fmt.Errorf("failed to register keystore templates: %w", err)
	}
	loaded.Templates = prepared

	contents, err := keystore.ScanGeneration(selected, kr)
	loaded.Contents = contents
	if err != nil {
		return loaded, fmt.Errorf("failed to rescan keys directory: %w", err)
	}
	// The selected generation is the committed state, and a malformed or
	// undecryptable entry in it means the generation fails validation:
	// recovery, not a warning-tolerant reload (docs/ARCH_STORE.md, "Runtime
	// reload behavior").
	if defects := prepared.Report().ContentDefectKeyTypes(); len(contents.Warnings) > 0 || len(defects) > 0 {
		detail := ""
		if len(contents.Warnings) > 0 {
			detail = contents.Warnings[0].Message()
		} else {
			detail = "key type " + defects[0]
		}
		return loaded, fmt.Errorf("%w: %d malformed key file(s) and %d template/key-type defect(s) in the selected generation: %s",
			signertemplates.ErrGenerationValidation, len(contents.Warnings), len(defects), detail)
	}
	if err := keyclass.ValidateKeyTypesAllowedForNodeRole(ir.NodeRole(), contents.KeyTypes()); err != nil {
		return loaded, fmt.Errorf("key snapshot rejected: %w", err)
	}
	return loaded, nil
}

// WireReloadFunc configures the reload's build and the reload function, the
// watcher reload mutation lock and the hook for a reload's entry into
// recovery on a product runtime.
func WireReloadFunc(ir *productruntime.Runtime, opts ProductBuildOptions, hooks ProductBuildHooks) {
	effects := productruntime.ReloadEffects{
		Audit:             hooks.ReloadAuditLog,
		NotifyKeysChanged: hooks.NotifyKeysChanged,
		Info:              hooks.Info,
		Warn:              hooks.Warn,
		NodeFailClosed:    hooks.NodeFailClosed,
	}
	ir.SetBuildFunc(func(kr *crypto.Keyring) (*productruntime.Loaded, error) {
		return Build(ir, opts, kr)
	}, effects)
	ir.SetReloadFunc(func(passphrase []byte, session *keystore.KeySession) (*signertemplates.ReloadReport, error) {
		svc := NewReloadService(ir, opts, hooks, session)
		return svc.Reload(passphrase)
	})
	if hooks.ReloadMutationLock != nil {
		ir.SetReloadMutationLock(hooks.ReloadMutationLock)
	}
	ir.SetReloadRecoveryHook(hooks.NotifyReloadRecovery)
}

// storedAdmissionAlerts are the admission problems of the stored documents,
// checked against the node's networks and ASA set. They become status
// alerts; they never block loading.
func storedAdmissionAlerts(role noderole.Role, cfg *serverconfig.ServerConfig, set *asaset.Set, np *policyruntime.NodePolicy) []string {
	var custom map[string]string
	if cfg != nil {
		custom = cfg.GenesisHashNetworks
	}
	networks, err := apconfig.NewGenesisHashNetworkResolver(custom)
	if err != nil {
		return []string{"policy admission checks are unavailable: " + err.Error()}
	}
	ctx, err := policycontext.New(role, networks, set)
	if err != nil {
		return []string{"policy admission checks are unavailable: " + err.Error()}
	}
	return policyadmission.StoredAlerts(np.Documents, ctx)
}
