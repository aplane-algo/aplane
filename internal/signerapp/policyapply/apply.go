// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package policyapply owns the rules for checking and committing a change to
// a node's policy documents. The online admin service and the offline rescue
// workflow both apply policy through it, so the two paths cannot drift.
package policyapply

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/signerapp/policyruntime"
	"github.com/aplane-algo/aplane/internal/signerapp/storevalidate"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// Operation is the generation manifest operation for a policy apply.
const Operation = "policy-apply"

// MaxPolicies caps a node's per-key policy documents. Together with the
// credential caps it bounds the get_policy summary, which lists every
// document and every key's coverage, to one admin frame.
const MaxPolicies = 8192

// Env is the node context a policy change is checked and committed in.
type Env struct {
	Role     noderole.Role
	DataDir  string
	Config   *serverconfig.ServerConfig
	KeyPaths storepaths.Paths
	HeldKeys map[string]bool // key selectors the node holds
	Now      func() time.Time
	Keyring  *crypto.Keyring
}

// Error is a policy request failure with a stable result code.
type Error struct {
	Code string
	Msg  string
}

func (e Error) Error() string { return e.Msg }

// Code returns err's result code, or fallback when err carries none.
func Code(err error, fallback string) string {
	var pe Error
	if errors.As(err, &pe) {
		return pe.Code
	}
	return fallback
}

// Candidate builds and compiles the policy that would result from applying
// docs and removals to current. Invalid documents are returned as problems;
// malformed requests are returned as errors. The layout is the same on both
// node roles: the default plus zero or more per-key documents. The default
// can be replaced but never removed.
func Candidate(env Env, current *policyruntime.NodePolicy, docs []adminproto.PolicyDocument, remove []string) (*policyruntime.NodePolicy, []adminproto.PolicyProblem, error) {
	if env.Role != noderole.RoleSigner && env.Role != noderole.RoleCosigner {
		return nil, nil, Error{"policy_unavailable", fmt.Sprintf("unsupported node role %q", env.Role)}
	}
	if len(docs) == 0 && len(remove) == 0 {
		return nil, nil, Error{"invalid_policy_request", "the request changes no documents"}
	}
	byKey := make(map[string]policy.StoredDocument)
	if current != nil {
		for _, doc := range current.Documents {
			byKey[doc.Key] = doc
		}
	}
	seen := map[string]bool{}
	for _, key := range remove {
		if key == policy.DefaultKey {
			return nil, nil, Error{"invalid_policy_request", "the node default cannot be removed; apply a new one instead"}
		}
		if err := storepaths.ValidatePolicySelector(key); err != nil {
			return nil, nil, Error{"invalid_policy_request", err.Error()}
		}
		if _, ok := byKey[key]; !ok || seen[key] {
			return nil, nil, Error{"invalid_policy_request", fmt.Sprintf("cannot remove the policy for %s: it has none of its own", key)}
		}
		seen[key] = true
		delete(byKey, key)
	}
	for _, doc := range docs {
		if doc.Key != policy.DefaultKey {
			if err := storepaths.ValidatePolicySelector(doc.Key); err != nil {
				return nil, nil, Error{"invalid_policy_request", err.Error()}
			}
		}
		if seen[doc.Key] {
			return nil, nil, Error{"invalid_policy_request", fmt.Sprintf("the policy for %s is listed twice or both replaced and removed", doc.Key)}
		}
		seen[doc.Key] = true
		byKey[doc.Key] = policy.StoredDocument{Key: doc.Key, Bytes: []byte(doc.Document)}
	}
	if _, ok := byKey[policy.DefaultKey]; !ok {
		return nil, nil, Error{"invalid_policy_request", "the node has no default policy; apply one with key \"default\""}
	}
	if len(byKey)-1 > MaxPolicies {
		return nil, nil, Error{"policy_set_too_large", fmt.Sprintf(
			"the change leaves %d key policy documents; a node holds at most %d", len(byKey)-1, MaxPolicies)}
	}
	var resulting []policy.StoredDocument
	for _, key := range sortedKeys(byKey) {
		resulting = append(resulting, byKey[key])
	}

	var problems []adminproto.PolicyProblem
	for _, doc := range docs {
		if _, err := policy.DecodePolicyV1([]byte(doc.Document), doc.Key, env.Role); err != nil {
			problems = append(problems, documentProblem(doc.Key, err))
		}
	}
	if len(problems) > 0 {
		return nil, problems, nil
	}
	candidate, err := policyruntime.Compile(env.Role, env.DataDir, env.Config, resulting)
	if err != nil {
		return nil, []adminproto.PolicyProblem{{Message: err.Error()}}, nil
	}
	return candidate, nil, nil
}

// Check validates a candidate change and reports the key coverage it would
// leave: advisories for each submitted document and documents for keys the
// node does not hold.
func Check(env Env, current *policyruntime.NodePolicy, req adminproto.CheckPolicyRequest) adminproto.CheckPolicyResult {
	candidate, problems, err := Candidate(env, current, req.Documents, req.Remove)
	if err != nil {
		return adminproto.CheckPolicyResult{Code: Code(err, "policy_check_failed"), Error: err.Error()}
	}
	result := adminproto.CheckPolicyResult{Success: true, Valid: len(problems) == 0, Errors: problems}
	if candidate != nil {
		for _, doc := range req.Documents {
			result.Warnings = append(result.Warnings, advisoryWarnings(env.Role, doc)...)
		}
		result.Warnings = append(result.Warnings, CoverageWarnings(KeyStatus(env.HeldKeys, candidate))...)
	}
	return result
}

// advisoryWarnings reports a valid document's surprising shapes.
func advisoryWarnings(role noderole.Role, doc adminproto.PolicyDocument) []adminproto.PolicyProblem {
	decoded, err := policy.DecodePolicyV1([]byte(doc.Document), doc.Key, role)
	if err != nil {
		return nil
	}
	advisories := decoded.Advisories()
	out := make([]adminproto.PolicyProblem, 0, len(advisories))
	for _, a := range advisories {
		pointer := ""
		if a.Scope != "policy" {
			pointer = "/" + a.Scope
		}
		out = append(out, adminproto.PolicyProblem{Key: doc.Key, Pointer: pointer, Message: a.Message})
	}
	return out
}

// Outcome is the result of Commit.
type Outcome struct {
	// GenerationID is the committed generation, empty when the change left
	// the policy unchanged.
	GenerationID string
	// Uncertain means the commit may be visible but its durability is
	// unconfirmed; the caller must block signing pending reconciliation.
	Uncertain bool
	Problems  []adminproto.PolicyProblem
}

// Commit verifies the active policy, checks the concurrency base, validates
// the change, and mints one generation carrying it. The caller holds the store
// mutation lock and env.Keyring.
func Commit(env Env, req adminproto.ApplyPolicyRequest) (Outcome, error) {
	if strings.TrimSpace(req.ExpectedPolicySetSHA256) == "" {
		return Outcome{}, Error{"expected_policy_set_sha256_required", "apply requires the policy_set_sha256 of the policy it replaces"}
	}
	active, err := genstore.ResolveStoreRootWithKeyring(env.KeyPaths, env.Keyring)
	if err != nil {
		return Outcome{}, Error{"policy_verify_failed", fmt.Sprintf("resolve active generation: %v", err)}
	}
	current, err := policyruntime.Load(env.Role, env.DataDir, env.Config, active, env.Keyring)
	if err != nil {
		return Outcome{}, Error{"policy_verify_failed", fmt.Sprintf("verify active policy: %v", err)}
	}
	if !strings.EqualFold(req.ExpectedPolicySetSHA256, current.SetSHA256()) {
		return Outcome{}, Error{"policy_snapshot_changed", "active policy changed; reload it and try again"}
	}
	candidate, problems, err := Candidate(env, current, req.Documents, req.Remove)
	if err != nil {
		return Outcome{}, err
	}
	if len(problems) > 0 {
		return Outcome{Problems: problems}, Error{"policy_validation_failed", "policy documents are invalid"}
	}
	if candidate.SetSHA256() == current.SetSHA256() {
		return Outcome{}, nil
	}
	now := time.Now
	if env.Now != nil {
		now = env.Now
	}
	generationID, err := genstore.NewGenerationID(now())
	if err != nil {
		return Outcome{}, err
	}
	_, mintErr := genstore.Mint(env.KeyPaths, genstore.MintRequest{
		GenerationID: generationID,
		Parent:       active.GenerationID(),
		Operation:    Operation,
		OperationID:  "policy-" + generationID,
		CreatedAt:    now(),
		Integrity:    env.Keyring,
		Apply: func(staged storepaths.GenPaths) error {
			return writeChange(staged, env.Role, req, env.Keyring, now())
		},
		ValidateCandidate: func(staged storepaths.GenPaths) error {
			return storevalidate.Candidate(storevalidate.Options{
				Paths: env.KeyPaths, Candidate: staged, Keyring: env.Keyring,
				ExpectedRole: env.Role, DataDir: env.DataDir, Config: env.Config,
			})
		},
	})
	if mintErr != nil {
		visible, visibleErr := genstore.ResolveStoreRootWithKeyring(env.KeyPaths, env.Keyring)
		if errors.Is(mintErr, genstore.ErrStoreRootCommitDurabilityUnknown) ||
			(visibleErr == nil && visible.GenerationID() == generationID) {
			return Outcome{GenerationID: generationID, Uncertain: true}, Error{"policy_commit_uncertain", fmt.Sprintf(
				"policy committed as generation %s but durability is unconfirmed; signing is blocked pending reconciliation: %v",
				generationID, mintErr)}
		}
		return Outcome{}, Error{"policy_save_failed", fmt.Sprintf("policy apply failed before commit: %v", mintErr)}
	}
	return Outcome{GenerationID: generationID}, nil
}

// writeChange applies an already-validated change to a staged generation.
func writeChange(staged storepaths.GenPaths, role noderole.Role, req adminproto.ApplyPolicyRequest, kr *crypto.Keyring, now time.Time) error {
	for _, key := range req.Remove {
		if err := policy.RemoveKeyPolicy(staged, key); err != nil {
			return err
		}
	}
	for _, doc := range req.Documents {
		if doc.Key == policy.DefaultKey {
			if err := policy.WriteDefault(staged, role, []byte(doc.Document), kr, now); err != nil {
				return err
			}
			continue
		}
		if err := policy.WriteKeyPolicy(staged, role, doc.Key, []byte(doc.Document), kr, now); err != nil {
			return err
		}
	}
	return nil
}

// View projects a node's policy for the admin surface.
func View(np *policyruntime.NodePolicy, held map[string]bool, generationID string) adminproto.PolicyView {
	if np == nil {
		return adminproto.PolicyView{Code: "policy_unavailable", Error: "policy is not loaded; unlock the signer"}
	}
	view := adminproto.PolicyView{
		Success:         true,
		NodeRole:        string(np.Role),
		PolicySetSHA256: np.SetSHA256(),
		GenerationID:    generationID,
	}
	for _, doc := range np.Documents {
		view.Documents = append(view.Documents, adminproto.PolicyDocumentInfo{
			Key: doc.Key, SHA256: doc.SHA256(), Size: len(doc.Bytes), SignedAtUnix: doc.SignedAtUnix,
		})
	}
	view.Keys = KeyStatus(held, np)
	return view
}

// Document returns one active policy document's exact bytes. key is
// policy.DefaultKey for the node default.
func Document(np *policyruntime.NodePolicy, key string) adminproto.PolicyDocumentResult {
	if np == nil {
		return adminproto.PolicyDocumentResult{Code: "policy_unavailable", Error: "policy is not loaded; unlock the signer"}
	}
	if key == "" {
		return adminproto.PolicyDocumentResult{Code: "policy_document_not_found", Error: "name the document: \"default\" or a key"}
	}
	for _, doc := range np.Documents {
		if doc.Key == key {
			return adminproto.PolicyDocumentResult{
				Success: true, Key: doc.Key, Document: string(doc.Bytes), SHA256: doc.SHA256(), SignedAtUnix: doc.SignedAtUnix,
			}
		}
	}
	return adminproto.PolicyDocumentResult{Key: key, Code: "policy_document_not_found", Error: fmt.Sprintf("no policy of its own for key %s; it follows the node default", key)}
}

// HeldPolicyKeys returns the selectors among a key index's selector-to-file
// map that may carry a policy on role: account credentials on a signer node,
// cosigner credentials on a cosigner node.
func HeldPolicyKeys(role noderole.Role, keyFiles map[string]string) map[string]bool {
	want := keys.ManagedCredentialAccount
	if role == noderole.RoleCosigner {
		want = keys.ManagedCredentialCosigner
	}
	held := make(map[string]bool, len(keyFiles))
	for selector, file := range keyFiles {
		if _, class, ok := keys.ParseManagedCredentialFilename(filepath.Base(file)); ok && class == want {
			held[selector] = true
		}
	}
	return held
}

// HeldPolicyKeysInGeneration lists the role's credentials in a generation's
// key namespace by file name, without opening them.
func HeldPolicyKeysInGeneration(role noderole.Role, active storepaths.ActivePaths) (map[string]bool, error) {
	entries, err := os.ReadDir(active.KeysDir())
	if err != nil {
		return nil, err
	}
	files := make(map[string]string, len(entries))
	for _, entry := range entries {
		if selector, _, ok := keys.ParseManagedCredentialFilename(entry.Name()); ok {
			files[selector] = entry.Name()
		}
	}
	return HeldPolicyKeys(role, files), nil
}

// KeyStatus reports coverage for every held key and every per-key document,
// sorted by key. The default is not a key and is not listed.
func KeyStatus(held map[string]bool, np *policyruntime.NodePolicy) []adminproto.PolicyKeyStatus {
	status := map[string]string{}
	for key := range held {
		status[key] = adminproto.PolicyKeyDefault
	}
	if np != nil {
		for _, doc := range np.Documents {
			if doc.Key == policy.DefaultKey {
				continue
			}
			if held[doc.Key] {
				status[doc.Key] = adminproto.PolicyKeyOwn
			} else {
				status[doc.Key] = adminproto.PolicyKeyNotHeld
			}
		}
	}
	out := make([]adminproto.PolicyKeyStatus, 0, len(status))
	for _, key := range sortedKeys(status) {
		out = append(out, adminproto.PolicyKeyStatus{Key: key, Status: status[key]})
	}
	return out
}

// CoverageWarnings turns coverage anomalies into check warnings. A key on
// the node default is covered, not a gap.
func CoverageWarnings(statuses []adminproto.PolicyKeyStatus) []adminproto.PolicyProblem {
	var out []adminproto.PolicyProblem
	for _, st := range statuses {
		if st.Status == adminproto.PolicyKeyNotHeld {
			out = append(out, adminproto.PolicyProblem{Key: st.Key, Message: "policy is for a key this node does not hold"})
		}
	}
	return out
}

func documentProblem(key string, err error) adminproto.PolicyProblem {
	var docErr *policy.DocumentError
	if errors.As(err, &docErr) {
		return adminproto.PolicyProblem{Key: key, Pointer: docErr.Pointer, Message: docErr.Msg}
	}
	return adminproto.PolicyProblem{Key: key, Message: err.Error()}
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for key := range m {
		out = append(out, key)
	}
	slices.Sort(out)
	return out
}
