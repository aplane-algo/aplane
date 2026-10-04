// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package admin

import (
	"errors"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/signerapp/policyapply"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
)

// GetPolicy returns the node's active policy documents.
func (s Service) GetPolicy() adminproto.PolicyView {
	return policyapply.View(s.Runtime.NodePolicy(), s.heldCosignerKeys(), "")
}

// GetPolicyDocument returns one active policy document's exact bytes.
func (s Service) GetPolicyDocument(key string) adminproto.PolicyDocumentResult {
	return policyapply.Document(s.Runtime.NodePolicy(), key)
}

// CheckPolicy validates candidate documents against the node's role and
// reports the cosigner key coverage the change would leave, without writing.
func (s Service) CheckPolicy(req adminproto.CheckPolicyRequest) adminproto.CheckPolicyResult {
	current := s.Runtime.NodePolicy()
	if current == nil {
		return adminproto.CheckPolicyResult{Code: "policy_unavailable", Error: "policy is not loaded; unlock the signer"}
	}
	return policyapply.Check(s.policyEnv(nil), current, req)
}

// ApplyPolicy replaces policy documents in one generation commit and reloads
// the runtime from the committed generation.
func (s Service) ApplyPolicy(req adminproto.ApplyPolicyRequest) adminproto.ApplyPolicyResult {
	ir := s.Runtime
	var outcome policyapply.Outcome
	err := s.Deps.WithStoreMutation(func() error {
		err := s.commitAndReload(ir, req, &outcome)
		// Enter recovery before releasing the mutation lock, as restore does.
		// Until reload succeeds the runtime may still serve the superseded
		// generation, so no key write or signing request may run in between.
		if outcome.Uncertain {
			ir.SetRecovery()
		}
		return err
	})
	if err != nil {
		if errors.Is(err, keystore.ErrStoreLocked) {
			return adminproto.ApplyPolicyResult{Code: "identity_locked", Error: "identity is locked; unlock the signer before applying policy"}
		}
		return adminproto.ApplyPolicyResult{
			Code:            policyapply.Code(err, "policy_apply_failed"),
			Error:           err.Error(),
			Errors:          outcome.Problems,
			CommitUncertain: outcome.Uncertain,
		}
	}
	view := policyapply.View(ir.NodePolicy(), s.heldCosignerKeys(), outcome.GenerationID)
	return adminproto.ApplyPolicyResult{Success: true, Policy: &view}
}

// commitAndReload commits the change and reloads the runtime from the
// committed generation. outcome.Uncertain reports a commit that may have
// landed without the runtime following it.
func (s Service) commitAndReload(ir *productruntime.Runtime, req adminproto.ApplyPolicyRequest, outcome *policyapply.Outcome) error {
	if err := ir.WithKeyring(func(kr *crypto.Keyring) error {
		var err error
		*outcome, err = policyapply.Commit(s.policyEnv(kr), req)
		return err
	}); err != nil {
		return err
	}
	if outcome.GenerationID == "" {
		return nil
	}
	if _, err := ir.Reload(); err != nil {
		outcome.Uncertain = true
		return policyapply.Error{Code: "policy_reload_failed", Msg: "policy committed as generation " +
			outcome.GenerationID + " but runtime reload failed; signing is blocked pending recovery: " + err.Error()}
	}
	return nil
}

func (s Service) policyEnv(kr *crypto.Keyring) policyapply.Env {
	return policyapply.Env{
		Role:     s.Runtime.NodeRole(),
		DataDir:  s.Deps.DataDir(),
		Config:   s.Deps.Config(),
		KeyPaths: s.Deps.KeyPaths(),
		HeldKeys: s.heldCosignerKeys(),
		Keyring:  kr,
	}
}

func (s Service) heldCosignerKeys() map[string]bool {
	keyFiles, _ := s.Runtime.KeySnapshot()
	return policyapply.HeldCosignerKeys(keyFiles)
}
