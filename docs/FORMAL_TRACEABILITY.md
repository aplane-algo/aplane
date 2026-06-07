# Formalization Traceability

> Status: working table. Each row in this file maps one model invariant
> to its lifecycle: where it is stated, what code embodies it, what test
> exercises it, and where the gaps are.

This file is the durable home for invariant *status*. The
`FORMAL_*_MODEL.md` documents state the contract; this table records
whether the contract is observed, intended, derived, assumed, or
deferred.

## Status Taxonomy

| Status | Meaning |
|---|---|
| `implemented` | Code observes the rule and at least one named test verifies it. |
| `implemented*` | Code observes the rule but no test exercises it directly (covered transitively or not at all). |
| `intended` | Code is meant to observe the rule; needs verification or no specific test exists. |
| `derived` | Follows by construction from a decision procedure or definition; no separate enforcement needed. |
| `assumption` | The model imports this from an external source without verifying. |
| `deferred` | Model describes a target the implementation does not yet enforce. |

## Maintenance Rules

1. Every invariant added to a `FORMAL_*_MODEL.md` must get a row here in the same change.
2. A status downgrade (e.g. `implemented` -> `intended`) must update both the row and the invariant prose.
3. `implemented` requires a named test function. If no test exists, the status is `implemented*` or `intended`.
4. `deferred` rows must reference an open question in the source model.

---

## Transaction Planning Model

Source: [FORMAL_TXN_PLANNING_MODEL.md](FORMAL_TXN_PLANNING_MODEL.md)

| ID | Status | Source § | Code anchor | Test anchor | Notes |
|---|---|---|---|---|---|
| I1 | implemented | Mode Validation | `internal/signerapp/signing/planner.go` (CategorizeRequests) | `internal/signerapp/signing/planner_test.go::TestCategorizeRequests_AllowsForeign`; `cmd/apsigner/plan_sign_shape_test.go::TestPlanRejectsMalformedRequestShapeWithStableErrorShape` | Mode trichotomy. |
| I2 | implemented | Mode Validation | `internal/signerapp/signing/planner.go` (mixed-mode reject) | `cmd/apsigner/plan_sign_shape_test.go::TestPlanRejectsMixedPassthroughAndForeignWithStableErrorShape` | |
| I3 | implemented | Mode Validation | `internal/signerapp/signing/planner.go` (all-foreign reject); validation in `internal/signerapi/types.go::GroupSignRequest.Validate` | `internal/signerapi/types_test.go::TestGroupSignRequestValidate` (table case "all foreign") | |
| I4 | implemented | Plan/Sign Planning Parity | `internal/signerapp/signing/planner.go` reused by `/plan` and `/sign` | `cmd/apsigner/plan_sign_parity_test.go::TestPlanAndSignProduceMatchingCanonicalTransactionForEd25519`; `::TestPlanAndSignPreserveCanonicalTransactionsForMixedSignAndPassthroughGroup`; `::TestPlanAllowsMixedSignAndForeignGroupAndPreservesCanonicalTransactions`; `::TestPlanAndSignAgreeOnDummyAndFeeMutationsForSingleFalconGroup`; `::TestSignReplansAgainstCurrentSnapshotAfterKeyRemoval` | Equivalent-snapshot parity and cross-endpoint snapshot divergence are both covered. |
| I5 | implemented | Pre-Grouped Immutability | `internal/signerapp/signing/planner_runtime.go::calculateDummies` (isPreGrouped branch) | `internal/signerapp/signing/planner_runtime_test.go::TestCalculateDummies_PreGroupedImmutability` | |
| I6 | implemented | Policy and Approval Boundary | `internal/signerapp/signing/service.go::signGroupWithPlanContext` passes plan-derived txns to evaluators | `internal/signerapp/signing/service_test.go::TestSignGroupWithPlanEvaluatesFinalizedTxnsNotCallerDrafts` covers divergent draft/finalized fee verdicts in both directions. | |
| I7 | implemented | Signing Output Rules; I7 | `internal/signerapp/signing/execution.go` (foreign slot -> "") | `cmd/apsigner/plan_sign_parity_test.go::TestPlanAllowsMixedSignAndForeignGroupAndPreservesCanonicalTransactions` asserts the signer-owned output is populated and the foreign output is `""` after `/sign`. | |
| I8 | implemented | Signing Output Rules; I8 | `internal/signerapp/signing/execution.go` passes through `signed_txn_hex` | `test/integration/passthrough_test.go:212` asserts `groupResp.Signed[1] == stxnBHex` after `/sign`; `:447` confirms preservation through resign | Direct byte-equality assertion exists. |
| I9 | implemented | Hard Deny Dominance | `internal/signerapp/signing/service.go::signGroupWithPlanContext` (auto-rejection before approval) | `internal/signerapp/signing/service_test.go::TestSignGroupWithPlanUserAutoApproveStillRejectsPolicyViolation` | Machine-checked via `policy_precedence.tla::I9_HardDenyDominance` and end-to-end via `composition.tla::HardDenyProducesNoOutput`. |
| I10 | implemented | Network Hash Authority | `internal/policy/lint.go:179`, `internal/signerapp/signing/planner.go:318`, `internal/signerapp/signing/simulation.go:61` all use `NetworkForGenesisHashBytes`; `GenesisID` references in `approval.go:354` and `planner_runtime.go:201` are consistency/propagation, not network selection | `internal/signerapp/signing/planner_test.go::TestValidateKnownNetwork_*`; `cmd/apsigner/genesis_hash_test.go` | Verified: no policy code path reads `GenesisID` for selection. |
| IS1 | implemented | Simulate Plans Like Sign | `internal/signerapp/signing/service.go::SignGroupForSimulationWithContext` reuses `PlanGroup` | `cmd/apsigner/plan_sign_parity_test.go::TestPlanAndSimulateProduceMatchingCanonicalTransactionsForEd25519` | |
| IS2 | implemented | Simulate Enforces Hard Policy | `internal/signerapp/signing/service.go::signGroupWithPlanContext` runs `EvaluateAutoRejectionRules` even in simulation mode | `internal/signerapp/signing/service_test.go::TestSignGroupForSimulationRejectsHardPolicyBeforeExecution` targets the simulation entry point and asserts hard policy rejects before execution. | |
| IS3 | implemented | Simulate Does Not Wait For Operator Approval | `internal/signerapp/signing/service.go::signGroupWithPlanContext` skips approval requests when `simulation=true` | `internal/signerapp/signing/service_test.go::TestSignGroupWithPlanSimulationSkipsApproval` | |
| IS4 | implemented | Simulate Never Exposes Signed Bytes | `internal/signerapp/rest/simulate.go` returns `Transactions` only | `internal/signerapp/rest/service_test.go::TestServiceSimulateSignsInternallyAndOmitsSignedBytes` | |
| IS5 | implemented | Simulate Rejects Unresolved Foreign Slots | `internal/signerapp/rest/simulate.go` (ForeignCount > 0 reject) | `internal/signerapp/rest/service_test.go::TestServiceSimulateRejectsForeignPlaceholders` | |
| IS6 | implemented | Simulate Honors Lifecycle And Unlock State | `internal/signerapp/rest/simulate.go:26-31` (IsDecommissioned, IsUnlocked rejection) | `internal/signerapp/rest/service_test.go::TestServiceSimulateRejectsDecommissionedRuntime`; `*RejectsLockedRuntime` | |

## Policy Model

Source: [FORMAL_POLICY_MODEL.md](FORMAL_POLICY_MODEL.md)

| ID | Status | Source § | Code anchor | Test anchor | Notes |
|---|---|---|---|---|---|
| P1 | implemented | Policy Snapshot; P1 | `internal/policy/integrity.go`; `internal/signerapp/policyruntime/policy.go` | `internal/policy/integrity_test.go`; `internal/policy/store_test.go` | HMAC sidecar verification. |
| P2 | implemented | Runtime Snapshot Semantics; P2 | `internal/signerapp/policyruntime/policy.go` (snapshot capture per-request); `cmd/apsigner/signing_service.go::newSigningServiceForIdentityWithAudit`; `cmd/apsigner/approval_service.go::newApprovalServiceForIdentityWithAudit`; `internal/signerapp/signing/service.go::signGroupWithPlanContext` | `internal/signerapp/identity/identity_test.go::TestRuntimePolicySnapshotStoresDefensiveCopies`; `cmd/apsigner/signing_service_test.go::TestNewSigningServiceForIdentityCapturesPolicyAndUserAutoApproveSnapshot`; `internal/signerapp/signing/service_test.go::TestSignGroupWithPlanDoesNotReevaluatePolicyAfterApproval` | Defensive policy copies, sign-service policy/default capture, and no post-approval policy re-evaluation are covered. |
| P3 | implemented | Planned Request | `internal/signerapp/signing/service.go::signGroupWithPlanContext` passes `allTxns` (plan output) to evaluators | `internal/signerapp/signing/service_test.go::TestSignGroupWithPlanEvaluatesFinalizedTxnsNotCallerDrafts` pins that policy follows finalized data when caller draft bytes diverge. | |
| P4 | implemented | Deny Dominance | `internal/signerapp/signing/approval.go::EvaluateAutoRejectionRules` is called first | `internal/signerapp/signing/service_test.go::TestSignGroupWithPlanUserAutoApproveStillRejectsPolicyViolation` | Machine-checked via `policy_precedence.tla::P4_DenyDominance`. |
| P5 | derived | Decision Procedure | Order-of-evaluation in `signGroupWithPlanContext` and `EvaluateAlwaysReviewRules` | `internal/signerapp/signing/service_test.go::TestSignGroupWithPlanAlwaysReviewWarningsOverridesUserAutoApprove`; `*TransferRoutingReviewOverrides*` | Holds by construction of the short-circuit decision procedure. Machine-checked via `policy_precedence.tla::P5_ReviewDominance`. |
| P6 | derived | Decision Procedure | Order-of-evaluation in `signGroupWithPlanContext`; `EvaluateAutoApprovalRules` is third in the chain | `internal/signerapp/signing/service_test.go::TestSignGroupWithPlanAutoApproveSelfNoOpTransferSkipsManualReview` | Machine-checked via `policy_precedence.tla::P6_ApproveAfterDenyReview`. |
| P7 | derived | Decision Procedure | `user_auto_approve` consulted only after policy verdict miss | `internal/signerapp/signing/service_test.go::TestSignGroupWithPlanAlwaysReviewWarningsOverridesUserAutoApprove`; `::TestSignGroupWithPlanTransferRoutingReviewOverridesUserAutoApprove`; `::TestSignGroupWithPlanUsesSingleTxnApprovalForServerAddedDummies`; `cmd/apsigner/audit_test.go::TestHandleSignWritesHTTPAttributedAuditEntries` | Machine-checked via `policy_precedence.tla::P7_OperatorDefaultLast`. |
| P8 | implemented | Slot Classes | `EvaluateAutoRejectionRules` skips passthrough/foreign positions by index map | `internal/signerapp/signing/service_test.go::TestEvaluateAutoRejectionRulesSkipsForeignAndDummyTransactions`; `*SkipsTransferRoutingForPassthroughForeignAndDummySlots*` | |
| P9 | implemented | P9 | `internal/policy/transfer_routing_eval.go` returns `Reject`/`Review`/no-verdict only | `internal/policy/transfer_routing_eval_test.go`; `internal/policy/ruleids_test.go` | |
| P10 | implemented | Effective Policy Selection; P10 | `internal/policy/config.go::ForKey`; `internal/signerapp/signing/service.go::authPolicyKeysFromRequest` passes auth addresses to policy evaluators | `internal/signerapp/signing/always_review_test.go::TestEvaluateAlwaysReviewRulesUsesKeyOverride`; `service_test.go::TestEvaluateAutoRejectionRulesAppliesKeyOverrides` | |

## Lifecycle Model

Source: [FORMAL_LIFECYCLE_MODEL.md](FORMAL_LIFECYCLE_MODEL.md)

| ID | Status | Source § | Code anchor | Test anchor | Notes |
|---|---|---|---|---|---|
| L1 | implemented | Decommission Transition; L1 | `internal/signerapp/identity/runtime.go::Decommission` writes config only | `internal/signerapp/identity/identity_test.go::TestDecommission` | |
| L2 | implemented | L2 | `Decommission` in `internal/signerapp/identity/runtime.go` persists before marking | `internal/signerapp/identity/identity_test.go::TestDecommission`; `::TestDecommissionPersistErrorLeavesRuntimeActive` injects a failing `PersistDecommission` and asserts the runtime remains active and pending approvals are untouched. | |
| L3 | implemented | Runtime Rejection Rules | `internal/signerapp/identity/runtime.go` decommission checks across unlock/reload/route/etc | `internal/signerapp/identity/identity_test.go::TestRegistryAuthenticatorSkipsDecommissionedIdentity`; `cmd/apsigner/http_auth_test.go` (decommissioned-identity paths) | |
| L4 | implemented | Lifecycle Lease; L4 | `internal/signerapp/identity/runtime.go::BeginOperation` | `internal/signerapp/signing/service_test.go::TestSignGroupWithPlanStopsBeforeExecute`; `::TestSignGroupWithPlanReleasesBeforeExecuteLeaseAfterExecution` | Machine-checked via `lifecycle.tla::L4_LeaseGatesSigning`. |
| L5 | implemented | L5 | RWMutex write side; documented in `runtime.go` lock-ordering comment | `internal/signerapp/identity/identity_test.go::TestDecommissionWaitsForActiveOperation`; `::TestDecommissionWaitingBlocksNewOperation` | Machine-checked via `lifecycle.tla::L5_DecommissionWaitsForHeldLease` (validated by mutation test). The second test pins the writer-pending behavior the TLA model assumes from Go's `sync.RWMutex`. |
| L6 | implemented | L6 | `BeginOperation` returns ErrDecommissioned when lifecycle flag set | `internal/signerapp/signing/service_test.go::TestSignGroupWithPlanUserAutoApproveDecommissionBeforeExecute` | Machine-checked via `lifecycle.tla::L6_NoAcquireAfterDecommission`. |
| L7 | implemented | Registry Separation; L7 | Registry vs runtime lifecycle separation in `identity/runtime.go` | `internal/signerapp/identity/identity_test.go::TestRegistryRemoveDoesNotDecommissionHeldRuntime` | Machine-checked via `lifecycle.tla::L7_RegistryRemoveDoesNotPreventCompletion`. |
| L8 | implemented | L8 | `Decommission` step 6: fail pending approvals | `internal/signerapp/identity/identity_test.go::TestDecommissionFailsPendingApprovals` | |
| L9 | implemented | L9 | `Decommission` calls `StopKeyWatcher` (step 8); `runtime.go:811-813` clears `watcherCancel` | `internal/signerapp/identity/identity_test.go::TestDecommissionStopsKeyWatcher` observes the watcher context cancellation and asserts it cannot restart after decommission. | |
| L10 | implemented | Startup Rules; L10 | `internal/signerapp/startup` consults stored config | `cmd/apsigner/identity_startup_test.go::TestStartupIdentityIDsSkipsDecommissionedIdentities` | |
| L11 | implemented | Watcher and Reload Rules; L11 | `Reload` step ordering in `internal/signerapp/identity/runtime.go` and `internal/signerapp/templates/reload.go` | `internal/signerapp/templates/reload_test.go::TestReloadRunsBeforeKeyScanHookBeforeTemplatesAndScan` (direct sequence assertion); mutation-lock leg via `identity_test.go::TestWatcherReloadUsesMutationLock` | |

## Signing Authority Model

Source: [FORMAL_SIGNING_AUTHORITY_MODEL.md](FORMAL_SIGNING_AUTHORITY_MODEL.md)

| ID | Status | Source § | Code anchor | Test anchor | Notes |
|---|---|---|---|---|---|
| S1 | implemented | S1 | `internal/keys/keys.go` scan reads stored payload; `internal/signerapp/signing/execution.go` signs from stored authority | Integration: `test/integration/basic_falcon_test.go` and related Falcon tests exercise stored-authority signing. | |
| S2 | implemented | LogicSig v1 Metadata; S2 | Sign-time: `internal/signerapp/signing/execution.go:153,276` (`SigningMetadataVersion == 0` -> `missingLogicSigSigningMetadata`); Restore-time: `internal/backup/restore.go` | Restore path: `internal/backup/restore_test.go::TestRestoreKeyRejectsLogicSigWithoutSigningMetadata`; sign path: `internal/signerapp/signing/execution_test.go::TestExecutorSignGenericLSigRejectsMissingSigningMetadata`; `*AssembleDSALogicSigRejectsMissingSigningMetadata` | |
| S3 | implemented | S3 | `internal/keys/keys.go` derives address from bytecode | `internal/keys/lsig_file_test.go`; `internal/keys/template_fingerprint_test.go` | |
| S4 | implemented | S4 | `internal/signingargs` orders runtime args by stored signing_args | `internal/signerapp/signing/runtime_args_test.go` | |
| S5 | implemented | S5 | `internal/keys/keys.go` reads stored payload only; reload paths preserve already-registered templates | `cmd/apsigner/template_reload_test.go::TestReloadKeysKeepsOriginalGenericTemplateDefinition`; `*PreservesAlreadyRegisteredGenericDefinition` | |
| S6 | implemented | Off-Curve Requirement; S6 | `internal/lsigsalt` enforces off-curve at create/scan; `internal/keys/keys.go::ValidateLogicSigSaltedBytecode` rejects on-curve | `internal/keys/keys_test.go::TestValidateLogicSigSaltedBytecodeRejectsOnCurveAddress`; `*TestScanKeysDirectoryWithMasterKeyRejectsDSALSigInvalidBytecode` | |
| S7 | implemented | S7 | `internal/keys/keys.go::RequireLogicSigSaltCounter` | `internal/keys/keys_test.go::TestLSigFileUnmarshalRequiresSaltCounter`; uses `ErrMissingLogicSigSaltCounter` at `keys_test.go:270` | |
| S8 | implemented | S8 | Template fingerprint check is inventory-only; not consulted at sign time | `internal/keys/template_fingerprint_test.go::TestTemplateFingerprintComparison`; `*Unavailable`. Sign-time isolation follows from S5 anchors. | |
| S9 | implemented | S9 | `internal/keys/keys.go` and `lsig_file.go` alias parsing rejects conflicting values | `internal/keys/keys_test.go::TestParseKeyPayloadMetadataRejectsConflictingAliases`; `internal/keys/lsig_file_test.go::TestLSigFileUnmarshalRejectsConflictingAliases` | |
| S10 | implemented | Runtime Key Index; S10 | `internal/signerapp/identity/runtime.go::KeyIndexSnapshot`; `internal/signerapp/signing/planner.go::PlanGroup`; `internal/signerapp/signing/planner_runtime.go::verifySignableKeys` | `internal/signerapp/identity/identity_test.go::TestKeyIndexSnapshotMaterializesConsistentCopy`; `internal/signerapp/signing/planner_runtime_test.go::TestPlannerUsesSingleIdentitySnapshot` | Planning materializes key files, key types, LogicSig sizes, and signer-local known addresses from one copied snapshot. |
| S11 | implemented | Auth Address Binding; S11 | `internal/signerapp/signing/planner_runtime.go` resolves auth addresses through `PlannerIdentitySnapshot.KeyFiles` | `internal/signerapp/signing/planner_runtime_test.go::TestVerifySignableKeysRequiresKeyFileInSnapshot`; `::TestVerifySignableKeysRequiresKeyTypeMetadata` | |
| S12 | implemented | S12 | `service.go::authPolicyKeysFromRequest` uses `txReq.AuthAddress` for policy override selection; `policyCfg.ForKey` consumes it | `internal/signerapp/signing/always_review_test.go::TestEvaluateAlwaysReviewRulesUsesKeyOverride`; `service_test.go::TestEvaluateAutoRejectionRulesAppliesKeyOverrides` | |
| S13 | implemented | Canonical Filename Binding; S13 | Scan derives payload address and skips filename mismatches in `internal/keys/keys.go`; canonical writers use `paths.KeyFilePath(identityID, address)` without write-time directory preflight | `internal/keys/keys_test.go::TestScanKeysDirectoryWithMasterKey/filename_address_mismatch_is_skipped`; `internal/keys/save_test.go::TestSaveKeyFileAllowsCanonicalWriteWithNonCanonicalKeyPresent`; `internal/keymgmt/operations_test.go::TestImportKeyRestoresCanonicalPathWhenExistingKeyIsNonCanonical`; `internal/backup/restore_test.go::TestRestoreKeyWritesCanonicalPathWhenExistingKeyIsNonCanonical` | Open Question 3 resolved as filename binding; address-collision invalidation remains a defensive fallback. |

## Guarded Signing Model

Source: [FORMAL_GUARDED_SIGNING_MODEL.md](FORMAL_GUARDED_SIGNING_MODEL.md)

| ID | Status | Source § | Code anchor | Test anchor | Notes |
|---|---|---|---|---|---|
| A1 | implemented | A1 | `internal/sentry/message/message.go`; `internal/signerapp/signing/component.go::PrepareComponentSigning` | `internal/signerapp/signing/component_test.go::TestPrepareComponentSigningUsesSentryRoleDomain`; `internal/engine/attested_submit_test.go::TestVerifySentryComponentSignaturesUsesSharedMessage` | Role byte separates user and sentry signatures for the same target txid. |
| A2 | implemented | A2 | `internal/signerapp/signing/attestor_gate.go`; `internal/signerapp/signing/execution.go` | `internal/signerapp/signing/execution_test.go::TestExecutorRejectsSentryKeyTypesBeforeSessionLoad`; `::TestExecutorSignCryptoKeyRejectsSentryKeyTypesBeforeProviderLookup` | Covers both sentry component key types and both guarded account key types. |
| A3 | implemented | A3 | `internal/signerapp/signing/component_sign.go::signPreparedUserComponents` | `internal/signerapp/signing/component_test.go::TestSignPreparedUserComponentsRejectsSenderMismatchBeforeKeyLoad`; `::TestSignPreparedUserComponentsSignsGuardedAccountMessages` | Sender mismatch rejects before local attested key load. |
| A4 | implemented | A4 | `internal/signerapp/signing/service.go::SignComponentWithContext`; `internal/signerapp/signing/attestor_policy.go`; `internal/policy` | `internal/signerapp/signing/component_test.go::TestSignComponentSentryRequiresPolicyBeforeKeyLoad`; `::TestSignComponentSentryRejectsNonTransferBeforeKeyLoad`; `::TestSignComponentSentryRejectsRouteMissBeforeKeyLoad`; `::TestSignComponentSentryRejectsInheritedReviewRouteMissBeforeKeyLoad`; `::TestSignComponentSentryRejectsRekeyBeforeKeyLoad` | Sentry policy is deterministic: no review and no operator default. |
| A5 | implemented | A5 | `internal/signerapp/signing/component_sign.go::loadSentryComponentKey`; `internal/sentry/keytypes/keytypes.go` | `internal/signerapp/signing/component_test.go::TestSignPreparedSentryComponentsRejectsWrongKeyType`; `::TestLoadSentryComponentKeyRejectsMismatchedPublicPrivateKey`; `::TestSignPreparedSentryComponentsSignsEd25519Messages`; `::TestSignPreparedSentryComponentsSignsFalcon1024Messages` | Selector, category, key type, and public/private pair must agree. |
| A6 | implemented | A6 | `internal/signerapp/signing/component_assemble.go::assembleGuardedTarget` | `internal/signerapp/signing/component_test.go::TestAssembleDecodedAttestedRejectsWrongUserSignature`; `::TestAssembleDecodedAttestedVerifiesAndBuildsSignedGroup` | User signature is checked against the user public key stored in the local guarded account key. |
| A7 | implemented | A7 | `internal/signerapp/signing/component_assemble.go::assembleGuardedTarget` | `internal/signerapp/signing/component_test.go::TestAssembleDecodedAttestedRejectsWrongSentrySignature`; `::TestAssembleDecodedAttestedVerifiesFalconSentryAndBuildsSignedGroup` | Sentry signature is checked against the sentry public key embedded in local key metadata/bytecode, not endpoint metadata. |
| A8 | implemented | A8 | `internal/signerapp/signing/component_assemble.go::validateGuardedPassthrough` | `internal/signerapp/signing/component_test.go::TestAssembleDecodedAttestedRejectsMismatchedPassthrough`; `::TestAssembleDecodedAttestedVerifiesAndBuildsSignedGroup` | Passthrough bytes are preserved only when their decoded txid matches the canonical group entry. |
| A9 | implemented | A9 | `internal/engine/attested_submit.go::resolveSentryEndpoint`; `::verifySentryEndpointAdvertises` | `internal/engine/attested_submit_test.go::TestRequestSentryComponentSignaturesExplicitMismatchDoesNotFallback`; `::TestRequestSentryComponentSignaturesFallsBackToCurrentSigner` | `/keys` is an ergonomic precheck only; explicit mismatch prevents silent self fallback. |
| A10 | implemented | A10 | `internal/engine/attested_submit.go::verifySentryComponentSignatures`; `internal/sentry/verify` | `internal/engine/attested_submit_test.go::TestVerifySentryComponentSignaturesUsesSharedMessage`; `::TestVerifySentryComponentSignaturesUsesFalcon1024Scheme` | Client precheck reuses shared message/verification primitives. |
| A11 | implemented | A11 | `internal/engine/attested_submit.go::collectComponentSignatures`; `pkg/signerapi/sentry.go` | `internal/engine/attested_submit_test.go::TestCollectComponentSignaturesRejectsMalformedResponses`; `pkg/signerapi/sentry_test.go::TestComponentSignResponseValidate` | Client requires exact response coverage and expected scheme before local sentry signature verification. |
| A12 | implemented | A12 | `internal/engine/attestor_endpoint.go`; `internal/config/client_endpoint_writes.go`; `internal/apshellapp/endpoints.go` | `internal/apshellapp/endpoints_test.go::TestEndpointDiscoverSentriesPreservesUnreachableEndpointInventory`; `::TestEndpointDiscoverSentriesPreservesLockedEndpointInventory`; `::TestEndpointDiscoverSentriesRejectsAuthFailure`; `::TestEndpointDiscoverSentriesRejectsInvalidEndpointMetadata`; `internal/config/client_endpoint_writes_test.go::TestRebuildStoredClientEndpointPublishedSentriesRejectsDuplicatePublicKey` | Unavailable/locked endpoints preserve previous inventory; hard failures write nothing. |
| A13 | implemented | A13 | `internal/keyclass/keyclass.go`; `internal/signerapp/keyadmin/service.go`; `internal/signerapp/templates/reload.go`; `internal/signerapp/rest/role.go` | `internal/keyclass/keyclass_test.go::TestNodeRoleAllowsKeyType`; `::TestValidateKeyTypesAllowedForNodeRoleReportsConflicts`; `internal/signerapp/keyadmin/service_test.go::TestServiceGenerateKeyRejectsKeyTypeDisallowedByNodeRole`; `::TestServiceImportKeyRejectsKeyTypeDisallowedByNodeRole`; `internal/signerapp/templates/reload_test.go::TestReloadNodeRoleValidationRejectsConflictingInventoryBeforePublish`; `internal/signerapp/rest/service_test.go::TestServiceNodeRoleGatesEndpointRoles` | Node role gates generation/import, REST role dispatch, and reload-time publication. |

## Open Cross-Cutting Gaps

No open cross-cutting gaps. The concrete sketches that previously lived
in [FORMAL_TEST_GAPS.md](FORMAL_TEST_GAPS.md) have all been closed or
are deferred behind explicit design decisions; see that file for the
status of deferred items.

## Machine-Checkable Coverage

### Sign-boundary module

[formal/sign_boundary.tla](formal/sign_boundary.tla) (see
[FORMAL_TLA_SIGN_BOUNDARY_MODEL.md](FORMAL_TLA_SIGN_BOUNDARY_MODEL.md))
has been checked with TLC under `MaxRequestEntries = 3` and
`MaxDummies = 2`. The recorded bounded run generated 2,628 distinct
initial states, reached depth 1, and found no counterexamples for
`Safety`.

| Invariant | TLA+ predicate |
|---|---|
| I1 (Mode Totality) | structural via `RequestMode` |
| I2 (Passthrough-Foreign Exclusion) | `ValidRequest` |
| I3 (All-Foreign Rejection) | `ValidRequest` |
| I7 (Foreign Slots Are Never Signed) | `ForeignSlotsEmpty` |
| I8 (Passthrough Byte Preservation) | `PassthroughPreserved` |
| Output alignment | `OutputAligned` |
| M4 target | `SignerOutputBelongsToOwnedClass` |

`DenyOutputSuppression` exists in the spec but is true by construction
(verdict is a free oracle). Real I9 is checked in the policy-precedence
module below.

### Policy-precedence module

[formal/policy_precedence.tla](formal/policy_precedence.tla) (see
[FORMAL_TLA_POLICY_PRECEDENCE_MODEL.md](FORMAL_TLA_POLICY_PRECEDENCE_MODEL.md))
has been checked with TLC. No bounds are needed; every domain is finite
by construction. The recorded run generated 64 distinct initial states,
reached depth 1, and found no counterexamples for `Safety`.

| Invariant | TLA+ predicate |
|---|---|
| P4 (Deny Dominance) | `P4_DenyDominance` |
| P5 (Review Dominance Over Approval) | `P5_ReviewDominance` |
| P6 (Explicit Approval Only After Deny/Review Pass) | `P6_ApproveAfterDenyReview` |
| P7 (Operator Default Is Last) | `P7_OperatorDefaultLast` |
| I9 (Hard Deny Dominance) | `I9_HardDenyDominance` |
| Approval resolution table | `ApprovalResolution` |

P4-P7 follow by construction from the short-circuit decision procedure,
which TLC now confirms over every input combination. I9 is the
centerpiece: it could not be machine-checked in the sign-boundary
module because verdict was a free oracle; here verdict is derived from
rule application, so I9 becomes a real property TLC verifies.

### Composition module

[formal/composition.tla](formal/composition.tla) (see
[FORMAL_TLA_COMPOSITION_MODEL.md](FORMAL_TLA_COMPOSITION_MODEL.md))
joins the two component modules. The verdict that sign_boundary
previously treated as a free oracle is here derived by running
policy_precedence on rule matches and operator default. The joint
Init feeds that derived outcome into sign_boundary's output
computation. TLC checked under `MaxRequestEntries = 3` and
`MaxDummies = 2`; the recorded bounded run generated 84,096 distinct
initial states, reached depth 1, and found no counterexamples for
`Safety`.

| Claim | TLA+ predicate | Kind |
|---|---|---|
| Policy outcome binds signing output | `PolicyOutcomeBindsOutput` | Seam |
| Hard deny produces no output (real I9 over full pipeline) | `HardDenyProducesNoOutput` | Seam |
| Signed output requires policy approval | `SignedOutputRequiresPolicyApproval` | Seam |
| Foreign slots remain empty under derived verdict | `ForeignSlotsEmpty` | Recheck |
| Passthrough bytes remain preserved under derived verdict | `PassthroughPreserved` | Recheck |

The composition does not duplicate every component-internal invariant.
Each component module checks its own properties under its own Init.
The three **seam** rows are new claims that only exist at the
join. The two **recheck** rows are sign-boundary properties
re-verified against the derived (rather than oracle) verdict — cheap
regression guards rather than new behavioral claims. The component
operator copies in `composition.tla` are kept in sync with the
component modules by code review, not by TLC; see the prose
companion for the deliberate trade.

### Lifecycle module

[formal/lifecycle.tla](formal/lifecycle.tla) (see
[FORMAL_TLA_LIFECYCLE_MODEL.md](FORMAL_TLA_LIFECYCLE_MODEL.md))
models the lock-ordering race between `BeginOperation` and
`Decommission`. Unlike the previous three modules (one-shot Init-only),
this module has real transitions in `Next`: two signer processes and
one admin process race over a writer-priority RWMutex. TLC checked
under `SignerProcs = {s1, s2}`, `admin = a`, `NONE = none`, with
symmetry over signers; the recorded run generated 48 distinct
reachable states, reached depth 10, and found no counterexamples for
`Safety`.

| Invariant | TLA+ predicate |
|---|---|
| L4 (Final signing uses runtime lease) | `L4_LeaseGatesSigning` |
| L5 (Decommission waits for held lease) | `L5_DecommissionWaitsForHeldLease` |
| L6 (Decommission wins race before lease) | `L6_NoAcquireAfterDecommission` |
| L7 (Registry removal doesn't prevent completion) | `L7_RegistryRemoveDoesNotPreventCompletion` |
| RWMutex exclusion + state consistency | `TypeOK` |

L4 and L6 are pinned by history variables (`heldEver`,
`badAcquireAfterDecommission`). L5 is a direct state predicate
validated by mutation test (removing the `readers = {}` guard from
`AdminAcquireWrite` produces a counterexample). L7 uses `ENABLED`
reasoning over `SignerCompleteAndRelease`.

L1, L2, L3, L9-L11 are not modeled here. They are sequential
properties already covered by Go tests; not concurrency claims. L8
(Pending Approvals Fail On Successful Decommission) is deferred to a
future approval-coordinator model — it crosses the lifecycle/approval
boundary and needs the pending-approval state machine to model
meaningfully.

### Unmodeled invariants

The following invariants have no TLA+ representation yet:
- Most of I4-I6, IS1-IS6 (planning details, simulate boundary).
- P1, P2, P3, P8, P9, P10 (snapshot semantics, slot scope, routing,
  key overrides).
- L1, L2, L3, L9-L11 (lifecycle non-concurrency claims), plus L8
  (pending-approval cascade, deferred to a future approval-coordinator
  model).
- All of S1-S13 (signing authority).
- All of A1-A13 (guarded signing, assembly, endpoint routing, and identity
  mode).

Lifecycle-aware composition (joining the temporal lifecycle model
with the existing one-shot sign-boundary/policy-precedence/composition
modules) is the next likely module per the extension plans in the
formal prose companion docs.

## Update Workflow

When adding or changing an invariant:

1. Update or add the row in the appropriate model section above.
2. If status is `implemented`, name the specific test function.
3. If status is `intended` or `implemented*`, add an entry to "Open
   Cross-Cutting Gaps" so the gap is visible.
4. If status is `deferred`, link to an open question in the source model.

When closing a test gap:

1. Add or rename the test to make the invariant's claim explicit.
2. Update the row's test anchor.
3. Remove the corresponding entry from "Open Cross-Cutting Gaps."
