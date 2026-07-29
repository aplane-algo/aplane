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
4. `deferred` rows must reference an open question or an explicit
   implementation gate in the source model.

---

## Transaction Planning Model

Source: [FORMAL_TXN_PLANNING_MODEL.md](FORMAL_TXN_PLANNING_MODEL.md)

| ID | Status | Source § | Code anchor | Test anchor | Notes |
|---|---|---|---|---|---|
| I1 | implemented | Mode Validation | `internal/signerapp/signing/planner.go` (categorizeRequests) | `internal/signerapp/signing/planner_test.go::TestCategorizeRequests_AllowsForeign`; `internal/signerapp/daemon/plan_sign_shape_test.go::TestPlanRejectsMalformedRequestShapeWithStableErrorShape` | Mode trichotomy. |
| I2 | implemented | Mode Validation | `internal/signerapp/signing/planner.go` (mixed-mode reject) | `internal/signerapp/daemon/plan_sign_shape_test.go::TestPlanRejectsMixedPassthroughAndForeignWithStableErrorShape` | |
| I3 | implemented | Mode Validation | `internal/signerapp/signing/planner.go` (all-foreign reject); validation in `pkg/signerapi/types.go::GroupSignRequest.Validate` | `pkg/signerapi/types_test.go::TestGroupSignRequestValidate` and alias coverage in `internal/signerapi/types_test.go` (table case "all foreign") | |
| I4 | implemented | Plan/Sign Planning Parity | `internal/signerapp/signing/planner.go` reused by `/plan` and `/sign` | `internal/signerapp/daemon/plan_sign_parity_test.go::TestPlanAndSignProduceMatchingCanonicalTransactionForEd25519`; `::TestPlanAndSignPreserveCanonicalTransactionsForMixedSignAndPassthroughGroup`; `::TestPlanAllowsMixedSignAndForeignGroupAndPreservesCanonicalTransactions`; `::TestPlanAndSignAgreeOnDummyAndFeeMutationsForSingleFalconGroup`; `::TestSignReplansAgainstCurrentSnapshotAfterKeyRemoval` | Equivalent-snapshot parity and cross-endpoint snapshot divergence are both covered. |
| I5 | implemented | Pre-Grouped Immutability | `internal/signerapp/signing/planner_runtime.go::calculateDummies` (isPreGrouped branch) | `internal/signerapp/signing/planner_runtime_test.go::TestCalculateDummies_PreGroupedImmutability` | |
| I6 | implemented | Policy and Approval Boundary | `internal/signerapp/signing/service.go::signGroupWithPlanContext` passes plan-derived txns to evaluators | `internal/signerapp/signing/service_test.go::TestSignGroupWithPlanEvaluatesFinalizedTxnsNotCallerDrafts` covers divergent draft/finalized fee verdicts in both directions. | |
| I7 | implemented | Signing Output Rules; I7 | `internal/signerapp/signing/execution.go` (foreign slot -> "") | `internal/signerapp/daemon/plan_sign_parity_test.go::TestPlanAllowsMixedSignAndForeignGroupAndPreservesCanonicalTransactions` asserts the signer-owned output is populated and the foreign output is `""` after `/sign`. | |
| I8 | implemented | Signing Output Rules; I8 | `internal/signerapp/signing/execution.go` passes through `signed_txn_hex` | `test/integration/passthrough_test.go:212` asserts `groupResp.Signed[1] == stxnBHex` after `/sign`; `:447` confirms preservation through resign | Direct byte-equality assertion exists. |
| I9 | implemented | Hard Deny Dominance | `internal/signerapp/signing/service.go::signGroupWithPlanContext` (auto-rejection before approval) | `internal/signerapp/signing/service_test.go::TestSignGroupWithPlanUserAutoApproveStillRejectsPolicyViolation` | Machine-checked via `policy_precedence.tla::I9_HardDenyDominance` and end-to-end via `composition.tla::HardDenyProducesNoOutput`. |
| I10 | implemented | Network Hash Authority | `internal/policy/lint.go`, `internal/signerapp/signing/planner.go`, and client network selection use `NetworkForGenesisHashBytes`; `GenesisID` references in approval and planner runtime are consistency/propagation, not network selection | `internal/signerapp/signing/planner_test.go::TestValidateKnownNetwork_*` | Verified: no policy code path reads `GenesisID` for selection. |
| CS1 | implemented | Authorization Equivalence | `internal/clientsign/submit.go` always calls ordinary `/sign`; `internal/engine/guarded/submit.go` always uses ordinary component signing and assembly | `internal/clientsign/submit_test.go::TestSignAndSubmitViaGroupSimulateSignsThenUsesClientAlgod`; `internal/engine/guarded/simulate_submit_test.go::TestSignAndSubmitGroupSimulateUsesExecutableGuardedFlow`; ordinary gate tests in `internal/signerapp/signing/service_test.go` | The signer receives no simulation mode. |
| CS2 | implemented | Exact Signed Group Routing | `internal/clientsign/submit.go`, `internal/engine/guarded/submit.go`, `internal/engine/plugin_presign.go` | The three client-flow tests above compare algod input to the returned or assembled signed group. | No regroup or mutation occurs after signing. |
| CS3 | implemented | Signer Routing Ignorance | signer HTTP routes and DTOs expose no simulation request; audit remains in ordinary signing | `internal/signerapp/daemon/http_runtime_test.go::TestHTTPServerDoesNotExposeSignerSimulationRoutes`; ordinary signing audit tests | Audit records authorization and release, not the client route. |
| CS4 | implemented | Algod Availability Precedes Signing | standard, guarded, and plugin client workflows check algod before signer calls | `internal/clientsign/submit_test.go::TestSignAndSubmitViaGroupRejectsNilAlgodBeforeSigning`; `internal/engine/guarded/simulate_submit_test.go::TestSignAndSubmitGroupRejectsNilAlgodBeforeComponentSigning`; `internal/engine/plugin_presign_test.go::TestSignAndSubmitWithPluginSignersRejectsNilAlgodBeforeSigning` | |

## Policy Model

Source: [FORMAL_POLICY_MODEL.md](FORMAL_POLICY_MODEL.md)

| ID | Status | Source § | Code anchor | Test anchor | Notes |
|---|---|---|---|---|---|
| P1 | implemented | Policy Snapshot; P1 | `internal/policy/integrity.go`; `internal/signerapp/policyruntime/policy.go` | `internal/policy/integrity_test.go`; `internal/policy/store_test.go` | HMAC sidecar verification. |
| P2 | implemented | Runtime Snapshot Semantics; P2 | `internal/signerapp/policyruntime/policy.go` (snapshot capture per-request); `internal/signerapp/daemon/signing_service.go::newSigningServiceForIdentityWithAudit`; `internal/signerapp/daemon/approval_service.go::newApprovalServiceForIdentityWithAudit`; `internal/signerapp/signing/service.go::signGroupWithPlanContext` | `internal/signerapp/identity/identity_test.go::TestRuntimePolicySnapshotStoresDefensiveCopies`; `internal/signerapp/daemon/signing_service_test.go::TestNewSigningServiceForIdentityCapturesPolicyAndUserAutoApproveSnapshot`; `internal/signerapp/signing/service_test.go::TestSignGroupWithPlanDoesNotReevaluatePolicyAfterApproval` | Defensive policy copies, sign-service policy/default capture, and no post-approval policy re-evaluation are covered. |
| P3 | implemented | Planned Request | `internal/signerapp/signing/service.go::signGroupWithPlanContext` passes `allTxns` (plan output) to evaluators | `internal/signerapp/signing/service_test.go::TestSignGroupWithPlanEvaluatesFinalizedTxnsNotCallerDrafts` pins that policy follows finalized data when caller draft bytes diverge. | |
| P4 | implemented | Deny Dominance | `internal/signerapp/signing/approval.go::EvaluateAutoRejectionRules` is called first | `internal/signerapp/signing/service_test.go::TestSignGroupWithPlanUserAutoApproveStillRejectsPolicyViolation` | Machine-checked via `policy_precedence.tla::P4_DenyDominance`. |
| P5 | derived | Decision Procedure | Order-of-evaluation in `signGroupWithPlanContext` and `EvaluateAlwaysReviewRules` | `internal/signerapp/signing/service_test.go::TestSignGroupWithPlanAlwaysReviewWarningsOverridesUserAutoApprove`; `*TransferRoutingReviewOverrides*` | Holds by construction of the short-circuit decision procedure. Machine-checked via `policy_precedence.tla::P5_ReviewDominance`. |
| P6 | derived | Decision Procedure | Order-of-evaluation in `signGroupWithPlanContext`; `EvaluateAutoApprovalRules` is third in the chain | `internal/signerapp/signing/service_test.go::TestSignGroupWithPlanAutoApproveSelfNoOpTransferSkipsManualReview` | Machine-checked via `policy_precedence.tla::P6_ApproveAfterDenyReview`. |
| P7 | derived | Decision Procedure | `user_auto_approve` consulted only after policy verdict miss | `internal/signerapp/signing/service_test.go::TestSignGroupWithPlanAlwaysReviewWarningsOverridesUserAutoApprove`; `::TestSignGroupWithPlanTransferRoutingReviewOverridesUserAutoApprove`; `::TestSignGroupWithPlanUsesSingleTxnApprovalForServerAddedDummies`; `internal/signerapp/daemon/audit_test.go::TestHandleSignWritesHTTPAttributedAuditEntries` | Machine-checked via `policy_precedence.tla::P7_OperatorDefaultLast`. |
| P8 | implemented | Slot Classes | `EvaluateAutoRejectionRules` skips passthrough/foreign positions by index map | `internal/signerapp/signing/service_test.go::TestEvaluateAutoRejectionRulesSkipsForeignAndDummyTransactions`; `*SkipsTransferRoutingForPassthroughForeignAndDummySlots*` | |
| P9 | implemented | P9 | `internal/policy/transfer_routing_eval.go` returns `Reject`/`Review`/no-verdict only | `internal/policy/transfer_routing_eval_test.go`; `internal/policy/ruleids_test.go` | |
| P10 | implemented | Effective Policy Selection; P10 | `internal/policy/config.go::ForKey`; `internal/signerapp/signing/service.go::authPolicyKeysFromRequest` passes auth addresses to policy evaluators | `internal/signerapp/signing/always_review_test.go::TestEvaluateAlwaysReviewRulesUsesKeyOverride`; `service_test.go::TestEvaluateAutoRejectionRulesAppliesKeyOverrides` | |

## Lifecycle Model

Source: [FORMAL_LIFECYCLE_MODEL.md](FORMAL_LIFECYCLE_MODEL.md)

| ID | Status | Source § | Code anchor | Test anchor | Notes |
|---|---|---|---|---|---|
| L1 | implemented | Decommission Transition; L1 | `internal/signerapp/identity/runtime.go::Decommission` writes config only | `internal/signerapp/identity/identity_test.go::TestDecommission` | |
| L2 | implemented | L2 | `Decommission` in `internal/signerapp/identity/runtime.go` persists before marking | `internal/signerapp/identity/identity_test.go::TestDecommission`; `::TestDecommissionPersistErrorLeavesRuntimeActive` injects a failing `PersistDecommission` and asserts the runtime remains active and pending approvals are untouched. | |
| L3 | implemented | Runtime Rejection Rules | `internal/signerapp/identity/runtime.go` decommission checks across unlock/reload/route/etc | `internal/signerapp/identity/identity_test.go::TestRegistryAuthenticatorSkipsDecommissionedIdentity`; `internal/signerapp/daemon/http_auth_test.go` (decommissioned-identity paths) | |
| L4 | implemented | Lifecycle Lease; L4 | `internal/signerapp/identity/runtime.go::BeginOperation` | `internal/signerapp/signing/service_test.go::TestSignGroupWithPlanStopsBeforeExecute`; `::TestSignGroupWithPlanReleasesBeforeExecuteLeaseAfterExecution` | Machine-checked via `lifecycle.tla::L4_LeaseGatesSigning`. |
| L5 | implemented | L5 | RWMutex write side; documented in `runtime.go` lock-ordering comment | `internal/signerapp/identity/identity_test.go::TestDecommissionWaitsForActiveOperation`; `::TestDecommissionWaitingBlocksNewOperation` | Machine-checked via `lifecycle.tla::L5_DecommissionWaitsForHeldLease` (validated by mutation test). The second test pins the writer-pending behavior the TLA model assumes from Go's `sync.RWMutex`. |
| L6 | implemented | L6 | `BeginOperation` returns ErrDecommissioned when lifecycle flag set | `internal/signerapp/signing/service_test.go::TestSignGroupWithPlanUserAutoApproveDecommissionBeforeExecute` | Machine-checked via `lifecycle.tla::L6_NoAcquireAfterDecommission`. |
| L7 | implemented | Registry Separation; L7 | Registry vs runtime lifecycle separation in `identity/runtime.go` | `internal/signerapp/identity/identity_test.go::TestRegistryRemoveDoesNotDecommissionHeldRuntime` | Machine-checked via `lifecycle.tla::L7_RegistryRemoveDoesNotPreventCompletion`. |
| L8 | implemented | L8 | `Decommission` step 6: fail pending approvals; approval coordinator decommission predicate rechecks before and after the delivery queue | `internal/signerapp/identity/identity_test.go::TestDecommissionFailsPendingApprovals`; `internal/signerapp/approval/coordinator_test.go::TestCoordinatorQueuedSigningApprovalFailsAfterDecommission` | Mechanism and its own invariants are modeled in the Approval Coordinator Model (AP6) and machine-checked in `approval_coordinator.tla` (`L8_NoApproveAfterDecommission`). The lifecycle lease gate remains a downstream defense in depth. |
| L9 | implemented | L9 | `Decommission` calls `StopKeyWatcher` (step 8), which clears `watcherCancel` at `runtime.go:976-983` | `internal/signerapp/identity/identity_test.go::TestDecommissionStopsKeyWatcher` observes the watcher context cancellation and asserts it cannot restart after decommission. | |
| L10 | implemented | Startup Rules; L10 | `internal/signerapp/startup` consults stored config | `internal/signerapp/daemon/identity_startup_test.go::TestStartupIdentityIDsSkipsDecommissionedIdentities` | |
| L11 | implemented | Watcher and Reload Rules; L11 | `Reload` step ordering in `internal/signerapp/identity/runtime.go` and `internal/signerapp/templates/reload.go` | `internal/signerapp/templates/reload_test.go::TestReloadRunsBeforeKeyScanHookBeforeTemplatesAndScan` (direct sequence assertion); mutation-lock leg via `identity_test.go::TestWatcherReloadUsesMutationLock` | |

## Signing Authority Model

Source: [FORMAL_SIGNING_AUTHORITY_MODEL.md](FORMAL_SIGNING_AUTHORITY_MODEL.md)

| ID | Status | Source § | Code anchor | Test anchor | Notes |
|---|---|---|---|---|---|
| S1 | implemented | S1 | `internal/keys/keys.go` scan reads stored payload; `internal/signerapp/signing/execution.go` signs from stored authority | Integration: `test/integration/basic_falcon_test.go` and related Falcon tests exercise stored-authority signing. | |
| S2 | implemented | LogicSig v1 Metadata; S2 | Sign-time: `internal/signerapp/signing/execution.go:208,355` (`SigningMetadataVersion == 0` -> `missingLogicSigSigningMetadata`); Restore-time: `internal/backup/restore.go` | Restore path: `internal/backup/restore_test.go::TestRestoreKeyRejectsLogicSigWithoutSigningMetadata`; sign path: `internal/signerapp/signing/execution_test.go::TestExecutorSignGenericLSigRejectsMissingSigningMetadata`; `*AssembleDSALogicSigRejectsMissingSigningMetadata` | |
| S3 | implemented | S3 | `internal/keys.Payload.Selector` derives address from bytecode | `internal/keys/payload_codec_test.go`; `internal/keys/template_fingerprint_test.go` | |
| S4 | implemented | S4 | `internal/signingargs` orders runtime args by stored signing_args | `internal/signerapp/signing/runtime_args_test.go` | |
| S5 | implemented | S5 | `internal/keys/keys.go` reads stored payload only; reload paths preserve already-registered templates | `internal/signerapp/daemon/template_reload_test.go::TestReloadKeysKeepsOriginalGenericTemplateDefinition`; `*PreservesAlreadyRegisteredGenericDefinition` | |
| S6 | implemented | Off-Curve Requirement; S6 | `internal/lsigsalt` enforces off-curve at create; `internal/keys.Payload.Validate` rejects on-curve stored LogicSig bytecode during parse/scan/restore | `internal/keys/payload_codec_test.go`; `internal/keys/keys_test.go::TestScanKeysDirectoryWithKeyringRejectsDSALSigInvalidBytecode` | |
| S7 | implemented | S7 | `internal/keys.Payload.Validate` requires `salt_counter` for LogicSig payloads | `internal/keys/payload_codec_test.go`; scan/restore use `ErrMissingLogicSigSaltCounter` through canonical payload parsing | |
| S8 | implemented | S8 | Template fingerprint check is inventory-only; not consulted at sign time | `internal/keys/template_fingerprint_test.go::TestTemplateFingerprintComparison`; `*Unavailable`. Sign-time isolation follows from S5 anchors. | |
| S9 | implemented | S9 | `internal/keys.ParsePayload` rejects duplicate JSON object members, unknown fields, and obsolete payload aliases | `internal/keys/payload_codec_test.go` | Fresh-system canonical schema removes cosmetic alias normalization. |
| S10 | implemented | Runtime Key Index; S10 | `internal/signerapp/identity/runtime.go::KeyIndexSnapshot`; `internal/signerapp/signing/planner.go::PlanGroup`; `internal/signerapp/signing/planner_runtime.go::verifySignableKeys` | `internal/signerapp/identity/identity_test.go::TestKeyIndexSnapshotMaterializesConsistentCopy`; `internal/signerapp/signing/planner_runtime_test.go::TestPlannerUsesSingleIdentitySnapshot` | Planning materializes key files, key types, LogicSig sizes, and signer-local known addresses from one copied snapshot. |
| S11 | implemented | Auth Address Binding; S11 | `internal/signerapp/signing/planner_runtime.go` resolves auth addresses through `PlannerIdentitySnapshot.KeyFiles` | `internal/signerapp/signing/planner_runtime_test.go::TestVerifySignableKeysRequiresKeyFileInSnapshot`; `::TestVerifySignableKeysRequiresKeyTypeMetadata` | |
| S12 | implemented | S12 | `service.go::authPolicyKeysFromRequest` uses `txReq.AuthAddress` for policy override selection; `policyCfg.ForKey` consumes it | `internal/signerapp/signing/always_review_test.go::TestEvaluateAlwaysReviewRulesUsesKeyOverride`; `service_test.go::TestEvaluateAutoRejectionRulesAppliesKeyOverrides` | |
| S13 | implemented | Canonical Filename Binding; S13 | `internal/keys/managed_files.go` owns `CanonicalName = Selector || ExtensionForCategory`; scan rejects selector and category/extension mismatches; save, backup/restore, deletion, rotation, and watching consume the central classes | `internal/keys/managed_files_test.go`; `internal/keys/keys_test.go::TestScanKeysDirectoryWithKeyring`; `internal/keys/save_test.go::TestSavePayloadWritesWitnessPublicMetadata`; `internal/backup/restore_test.go::TestRestoreKeyRejectsContradictoryManagedCredentialClass`; `test/arch/managed_credential_files_test.go` | Account authority is `.key`; sentry witness authority is `.sen`; `.wit` is excluded. Accepted-selector collision invalidation remains a defensive fallback. |

## Guarded Signing Model

Source: [FORMAL_GUARDED_SIGNING_MODEL.md](FORMAL_GUARDED_SIGNING_MODEL.md)

| ID | Status | Source § | Code anchor | Test anchor | Notes |
|---|---|---|---|---|---|
| A1 | implemented | A1 | `internal/sentry/message/message.go`; `internal/signerapp/signing/component.go::PrepareComponentSigning` | `internal/signerapp/signing/component_test.go::TestPrepareComponentSigningUsesSentryRoleDomain`; `::TestAssembleDecodedGuardedRejectsWrongUserSignature` | Role byte separates user and sentry signatures for the same target txid. Machine-checked in `guarded_assembly.tla` (`A1_RoleDomainSeparation`). |
| A2 | implemented | A2 | `internal/signerapp/signing/sentry_gate.go`; `internal/signerapp/signing/execution.go` | `internal/signerapp/signing/execution_test.go::TestExecutorRejectsSentryKeyTypesBeforeSessionLoad`; `::TestExecutorSignCryptoKeyRejectsSentryKeyTypesBeforeProviderLookup` | Covers witness keys and the dedicated guarded account key type; bounded-sentry ordinary-sign rejection is tested separately. |
| A3 | implemented | A3 | `internal/signerapp/signing/component_sign.go::signPreparedUserComponents`; `::loadGuardedAccountSigningKey` | `internal/signerapp/signing/component_test.go::TestSignPreparedUserComponentsSignsGuardedAccountMessages`; `::TestSignPreparedUserComponentsSignsGuardedAuthorizerMessages` | User component signing proves `component_key` is a local guarded account key; sender may differ and is bound by assembly. |
| A4 | implemented | A4 | `internal/signerapp/signing/service.go::SignComponentWithContext`; `internal/signerapp/signing/sentry_policy.go`; `internal/policy` | `internal/signerapp/signing/component_test.go::TestSignComponentSentryRequiresPolicyBeforeKeyLoad`; `::TestSignComponentSentryRejectsNonTransferBeforeKeyLoad`; `::TestSignComponentSentryRejectsRouteMissBeforeKeyLoad`; `::TestSignComponentSentryRejectsInheritedReviewRouteMissBeforeKeyLoad`; `::TestSignComponentSentryRejectsRekeyBeforeKeyLoad` | Sentry policy is deterministic: no review and no operator default. |
| A5 | implemented | A5 | `internal/signerapp/signing/component_sign.go::loadSentryComponentKey`; `internal/witness` | `internal/signerapp/signing/component_test.go::TestSignPreparedSentryComponentsRejectsWrongKeyType`; `::TestLoadSentryComponentKeyRejectsMismatchedPublicPrivateKey`; `::TestSignPreparedSentryComponentsSignsFalcon1024Messages` | Witness Key ID, category, key type, and public/private pair must agree. |
| A6 | implemented | A6 | `internal/signerapp/signing/component_assemble.go::assembleGuardedTarget` | `internal/signerapp/signing/component_test.go::TestAssembleDecodedGuardedRejectsWrongUserSignature`; `::TestAssembleDecodedGuardedVerifiesAndBuildsSignedGroup` | User signature is checked against the user public key stored in the local guarded account key. Machine-checked in `guarded_assembly.tla` (`A6_UserSignatureVerified`). |
| A7 | implemented | A7 | `internal/signerapp/signing/component_assemble.go::assembleGuardedTarget` | `internal/signerapp/signing/component_test.go::TestAssembleDecodedGuardedRejectsWrongSentrySignature`; `::TestAssembleDecodedGuardedVerifiesFalconSentryAndBuildsSignedGroup` | Sentry signature is checked against the sentry public key embedded in local key metadata/bytecode, not endpoint metadata. Machine-checked in `guarded_assembly.tla` (`A7_SentrySignatureVerified`). |
| A8 | implemented | A8 | `internal/signerapp/signing/component_assemble.go::validateGuardedPassthrough` | `internal/signerapp/signing/component_test.go::TestAssembleDecodedGuardedRejectsMismatchedPassthrough`; `::TestAssembleDecodedGuardedVerifiesAndBuildsSignedGroup` | Passthrough bytes are preserved only when their decoded txid matches the canonical group entry. Machine-checked in `guarded_assembly.tla` (`A8_PassthroughTxidBound`). |
| A9 | implemented | A9 | `internal/engine/guarded/discovery.go::resolveSentryEndpoint`; `::verifySentryEndpointAdvertises` | `internal/engine/guarded/submit_test.go::TestRequestSentryComponentSignaturesExplicitMismatchDoesNotFallback`; `::TestRequestSentryComponentSignaturesFallsBackToCurrentSigner` | `/keys` is an ergonomic precheck only; explicit mismatch prevents silent self fallback. |
| A10 | implemented | A10 | `internal/engine/guarded/submit.go::requestOneSentryComponentSignatureSet`; `internal/sentry/canonical` | `cmd/apshell/deps_test.go::TestClientDoesNotLinkFalcon` | Client collects and forwards component signatures without cryptographic verification; the deps test pins the client binary to exclude `internal/sentry/verify` and the Falcon libraries. |
| A11 | implemented | A11 | `internal/engine/guarded/submit.go::collectComponentSignatures`; `pkg/signerapi/sentry.go` | `internal/engine/guarded/submit_test.go::TestCollectComponentSignaturesRejectsMalformedResponses` (`collectComponentSignatures` enforces exact coverage + scheme directly) | Client requires exact response coverage and expected scheme before forwarding signatures to assembly. |
| A12 | implemented | A12 | `internal/engine/guarded/discovery.go`; `internal/config/client_endpoint_writes.go`; `internal/apshellapp/endpoints.go` | `internal/apshellapp/endpoints_test.go::TestEndpointDiscoverSentriesPreservesUnreachableEndpointInventory`; `::TestEndpointDiscoverSentriesPreservesLockedEndpointInventory`; `::TestEndpointDiscoverSentriesRejectsAuthFailure`; `::TestEndpointDiscoverSentriesRejectsInvalidEndpointMetadata`; `internal/config/client_endpoint_writes_test.go::TestRebuildStoredClientEndpointPublishedSentriesRejectsDuplicatePublicKey` | Unavailable/locked endpoints preserve previous inventory; hard failures write nothing. |
| A13 | implemented | A13 | `internal/keyclass/keyclass.go`; `internal/signerapp/keyadmin/service.go`; `internal/signerapp/templates/reload.go`; `internal/signerapp/rest/role.go` | `internal/keyclass/keyclass_test.go::TestNodeRoleAllowsKeyType`; `::TestValidateKeyTypesAllowedForNodeRoleReportsConflicts`; `internal/signerapp/keyadmin/service_test.go::TestServiceGenerateKeyRejectsKeyTypeDisallowedByNodeRole`; `::TestServiceImportKeyRejectsKeyTypeDisallowedByNodeRole`; `internal/signerapp/templates/reload_test.go::TestReloadNodeRoleValidationRejectsConflictingInventoryBeforePublish`; `internal/signerapp/rest/service_test.go::TestServiceNodeRoleGatesEndpointRoles` | Node role gates generation/import, REST role dispatch, and reload-time publication. |
| A14 | implemented | A14 | `internal/signerapp/signing/component_assemble.go::assembleGuardedTarget`; `::validateAssembledGuardedTarget` | `internal/signerapp/signing/component_test.go::TestAssembleDecodedGuardedVerifiesAndBuildsSignedGroup` | Assembly verifies the assembled signed txn matches the canonical txid and carries `AuthAddr == guarded_account` when sender differs. Machine-checked in `guarded_assembly.tla` (`A14_AssembledTxnBound`). |
| A15 | implemented | A15 | `internal/signerapp/rest/inventory.go::BuildKeyInfoList`; `::buildKeyTypes`; `internal/engine/guarded/submit.go::HasGuardedEffectiveSigner`; `::guardedTargets` | `internal/signerapp/rest/service_test.go::TestBuildKeyTypesServesSigningFlowMetadata`; `internal/engine/guarded/submit_test.go::TestGuardedTargetsRejectUnsupportedSigningFlow`; `test/arch/signingflow_test.go::TestClientPackagesRouteOnSigningFlow` | Daemon serves `signing_flow`/`sentry_component_key_type` in inventory; clients route on the flow label, fail fast on unknown flows, and the arch test pins client packages off compiled guarded key-type switches. |

## Bounded Sentry Model

Source: [FORMAL_TLA_BOUNDED_SENTRY_MODEL.md](FORMAL_TLA_BOUNDED_SENTRY_MODEL.md)

| ID | Status | Source § | Code anchor | Test anchor | Notes |
|---|---|---|---|---|---|
| BS1 | implemented | BS1 | `internal/engine/guarded/submit.go::signAndSubmitBoundedSentryGroup`; `internal/signerapp/signing/bounded_sentry.go::PrepareBoundedComponentWithContext` | `internal/engine/guarded/simulate_submit_test.go::TestBoundedSentrySimulateUsesUserFirstChoreography`; `internal/signerapp/signing/bounded_sentry_test.go::TestValidateBoundedComponentPlanRequiresSentrySpend` | User policy and operator approval complete before the client requests a sentry. Machine-checked in `bounded_sentry.tla` (`BS1_UserFirst`). |
| BS2 | implemented | BS2 | `internal/signerapp/signing/bounded_admin.go`; `internal/apboundedadminapp/app.go` | `internal/signerapp/signing/bounded_admin_test.go::TestValidateBoundedAdminPlanRequiresNarrowTypedPath`; `internal/apboundedadminapp/app_test.go::TestExecuteRekeyCoordinatesExternalSignature` | External-admin completion has no sentry transition. Machine-checked in `bounded_sentry.tla` (`BS2_AdminBypassesSentry`). |
| BS3 | implemented | BS3 | `internal/signerapp/signing/bounded_sentry.go::assembleBoundedTarget` | `internal/signerapp/signing/bounded_sentry_test.go::TestAssembleBoundedTargetVerifiesBothAuthorities` | Spend assembly verifies both authorities against durable metadata. Machine-checked in `bounded_sentry.tla` (`BS3_SpendAuthoritiesVerified`). |
| BS4 | implemented | BS4 | `internal/signerapp/signing/bounded_sentry.go::AssembleBoundedWithContext`; bounded argument assembly in `internal/signerapp/signing/execution.go` | `internal/engine/guarded/submit_test.go::TestCollectComponentSignaturesRejectsMalformedResponses`; `internal/signerapp/signing/execution_test.go::TestAssembleBoundedArgsPreservesInteriorEmptySlots` | Exact target coverage and source/path masks gate assembly; derived inputs remain signer-owned. Machine-checked in `bounded_sentry.tla` (`BS4_DeclaredArgumentsOnly`). |
| BS5 | implemented | BS5 | `internal/engine/guarded/submit.go::verifyAssembledAgainstFrozen`; `internal/signerapp/signing/bounded_sentry.go::AssembleBoundedWithContext` | `internal/engine/guarded/submit_test.go::TestVerifyAssembledAgainstFrozen`; `internal/signerapp/signing/bounded_sentry_test.go::TestBoundedAssemblyReceiptBindsRuntimeAndMetadata` | Receipt, passthrough, and final bytes bind the frozen plan. Machine-checked in `bounded_sentry.tla` (`BS5_CanonicalGroupBound`). |
| BS6 | implemented | BS6 | `internal/signerapp/signing/bounded_sentry.go::validateBoundedComponentPlan`; ordinary-sign rejection in `internal/signerapp/signing/service.go` | `internal/signerapp/signing/bounded_sentry_test.go::TestValidateBoundedComponentPlanRequiresSentrySpend` | Invalid, admin, and non-spend shapes cannot enter bounded-sentry spend output. Machine-checked in `bounded_sentry.tla` (`BS6_InvalidNeverOutputs`). |
| BS7 | implemented | BS7 | `internal/signerapp/signing/bounded_sentry.go::AssembleBoundedWithContext`; `internal/engine/guarded/submit.go::signAndSubmitBoundedSentryGroup` | `internal/signerapp/signing/bounded_sentry_test.go::TestAssembleBoundedTargetVerifiesBothAuthorities`; `internal/engine/guarded/simulate_submit_test.go::TestBoundedSentrySimulateUsesUserFirstChoreography` | Every failed stage returns no signed group; only final assembly reaches submission/simulation. Machine-checked in `bounded_sentry.tla` (`BS7_AtomicOutput`). |

## Approval Coordinator Model

Source: [FORMAL_APPROVAL_COORDINATOR_MODEL.md](FORMAL_APPROVAL_COORDINATOR_MODEL.md)

| ID | Status | Source § | Code anchor | Test anchor | Notes |
|---|---|---|---|---|---|
| AP1 | implemented | AP1 | `internal/signerapp/approval/coordinator.go::HandleSignResponse` (delete-before-deliver); `::trySendSignResponse` (non-blocking, closes channel) | `internal/signerapp/approval/coordinator_test.go::TestCoordinatorLateResponseAfterTimeoutIsIgnored` | At most one terminal outcome per request; late/duplicate events are dropped. |
| AP2 | implemented | AP2 | `internal/signerapp/approval/coordinator.go::RequestSigningApprovalResponseContext`; `internal/signerapp/signing/approval.go::requestSigningApproval` (returns `response.Approved`) | `internal/signerapp/approval/coordinator_test.go::TestCoordinatorCancelSignRequestDismissesPendingApproval`; `::TestCoordinatorFailAllUnblocksPendingRequest` | Only an operator approve yields `Approved=true`; every other outcome denies the signature (approval half of `SignedOutputRequiresPolicyApproval`). |
| AP3 | implemented | AP3 | `internal/signerapp/approval/coordinator.go::HandleSignResponse` (keyed by `msg.ID`) | `internal/signerapp/approval/coordinator_test.go::TestCoordinatorMismatchedResponseIDDoesNotSatisfyActiveRequest` | A response satisfies a request only on exact ID match. |
| AP4 | implemented | AP4 | `internal/signerapp/approval/coordinator.go::acquireDeliveryTurnContext`; `::releaseDeliveryTurn` (`deliveryInFlight`, `deliveryQueue`) | `internal/signerapp/approval/coordinator_test.go::TestCoordinatorSerializesSigningRequests`; `::TestCoordinatorSerializesAcrossApprovalTypes` | One request delivered at a time; FIFO across signing and token-provisioning requests. |
| AP5 | implemented | AP5 | `internal/signerapp/approval/coordinator.go::CancelSignRequest`; `::BeginSignRequest`; `::consumeCanceledSignRequest` | `internal/signerapp/approval/coordinator_test.go::TestCoordinatorCancelSignRequestBeforeApprovalIsPending`; `::TestCoordinatorQueuedSigningApprovalContextCancelReturnsBeforeDeliveryTurn`; `::TestCoordinatorCancelSignRequestCancelsConcurrentSameIDRequests`; `::TestCoordinatorCancelSignRequestUnknownIsNotFound` | Cancellation reaches queued, delivered, and not-yet-waiting requests; unknown ID is `not_found`. |
| AP6 | implemented | AP6 | `internal/signerapp/approval/coordinator.go::NewWithDecommission`; `::RequestSigningApprovalResponseContext` and `::RequestTokenProvisioningContext` decommission rechecks; `::FailAllPendingRequests`; raised by `internal/signerapp/identity/runtime.go::Decommission` (`FailAllPendingApprovals`, `runtime.go:536`) and `internal/signerapp/daemon/ipc.go:163` (operator-client disconnect) | `internal/signerapp/approval/coordinator_test.go::TestCoordinatorFailAllClearsPendingMaps`; `::TestCoordinatorFailAllUnblocksPendingRequest`; `::TestCoordinatorQueuedSigningApprovalFailsAfterDecommission`; `internal/signerapp/daemon/hub_test.go::TestFailAllPendingRequests`; `internal/signerapp/identity/identity_test.go::TestDecommissionFailsPendingApprovals` | Fail-all terminates every then-pending request not-approved; coordinator decommission rechecks prevent queued requests from being delivered after the mark; mechanism behind lifecycle L8. |
| AP7 | implemented | AP7 | `internal/signerapp/daemon/ipc.go` displacement path (`FailAllPendingApprovals("apadmin displaced")` before `adminserver.DisplaceSession`); `internal/signerapp/adminserver/displacement.go::OfferDisplacement` / `::DisplaceSession` (old session remains owner until the replacement is promoted) | `internal/signerapp/daemon/ipc_displacement_test.go::TestDisplacementFailsDeliveredApprovalPrompt`; `::TestOfferDisplacementKeepsExistingClientUntilReplacementPromoted`; `::TestDisplacementReplacementAuthFailureKeepsOldOwner` | A delivered prompt was shown to the old client only, so it is failed in the same step the client is replaced; otherwise the orphaned prompt holds the delivery turn and head-of-line-blocks every later approval until the `ApprovalWait` timer frees it. Machine-checked in `approval_coordinator.tla` (`AP7_NoOrphanedDelivery` history flag on the `Displace` action); the coordinator liveness check (`Progress` under `LiveSpec`) documents that the timer is the only guaranteed exit from Delivered, which is why the orphan mattered. |

## Plugin Signing Model

Source: [FORMAL_PLUGIN_SIGNING_MODEL.md](FORMAL_PLUGIN_SIGNING_MODEL.md)

| ID | Status | Source § | Code anchor | Test anchor | Notes |
|---|---|---|---|---|---|
| PS1 | implemented | PS1 | `internal/engine/plugin_pregrouped.go` (unexported `stxns`/`raw`, sole constructor `DecodePregroupedSigned`, byte-verbatim submit via `g.raw`) | `internal/engine/plugin_pregrouped_test.go::TestDecodePregroupedSigned`; `::TestValidatePregroupedSigned` | Structural: decode provenance binds the displayed decode to the submitted bytes; deliberately not restated as a TLC predicate. |
| PS2 | implemented | PS2 | `internal/engine/plugin_pregrouped.go` (size, uniform group field, `ComputeGroupID` comparison); `internal/signerapp/signing/planner.go` (pre-grouped claimed-group-ID recompute) | `internal/engine/plugin_pregrouped_test.go::TestValidatePregroupedSigned` | Machine-checked in `plugin_signing.tla` (`PS2_GroupDigestVerified`). A self-consistent malicious group passes by design — PS3/PS6 are the gates for that. |
| PS3 | implemented | PS3 | `internal/apshellcli/external_plugins.go::reviewPregroupedSigned` (mandatory review, `RequiresApproval` ignored, AutoConfirm fail-closed); `internal/apshellcli/plugin_group_review.go` (decoded rendering, opaque marking) | `internal/apshellcli/plugin_pregrouped_review_test.go::TestReviewPregroupedSignedFailsClosedWhenAutoConfirm`; `::TestReviewPregroupedSignedIgnoresRequiresApprovalFalse`; `::TestReviewPregroupedSignedRendersDecodedGroupAndApproves` | Machine-checked in `plugin_signing.tla` (`PS3_MandatoryReviewFailClosed`). The fail-closed path had no Go test until the model was anchored; tests added in the same change. |
| PS4 | implemented | PS4 | `internal/engine/plugin_presign.go::assertSlotArtifactFieldsPreserved` (draft vs canonical, Group+Fee zeroed, msgpack byte equality, both slot classes) | `internal/engine/plugin_presign_test.go::TestAssertSlotArtifactFieldsPreserved` | Machine-checked in `plugin_signing.tla` (`PS4_PlanPreserved`). Fee exemption is by design (/plan exists to set fees). |
| PS5 | implemented | PS5 | `internal/engine/plugin_presign.go::validatePluginSignedSlot` (msgpack of `stxn.Txn` = canonical); count/duplicate/unexpected-index checks; `::assertPluginSignersMatched` | `internal/engine/plugin_presign_test.go::TestValidatePluginSignedSlot`; `::TestAssertPluginSignersMatched` | Machine-checked in `plugin_signing.tla` (`PS5_SignedSlotByteMatch`). Signature bytes are not locally verified (the chain validates). |
| PS6 | implemented | PS6 | `internal/engine/plugin_presign.go` (managed slots sign-mode, plugin/dummy slots passthrough in one `/sign` request); `internal/signerapp/signing/approval.go:275` (auto-approval disabled for passthrough/foreign/pre-grouped groups; mixed-mode display); `always_review.go` (dangerous-field forced review) | `internal/signerapp/signing/always_review_test.go::TestEvaluateAlwaysReviewRulesForcesReviewOnDangerousPassthrough`; `test/integration/passthrough_test.go` (PassthroughMixedGroup end to end) | Machine-checked in `plugin_signing.tla` (`PS6_ManagedApprovalGated`). The approval pipeline's own invariants are the AP rows. |
| PS7 | implemented | PS7 | Mode dispatch `internal/apshellcli/external_plugins.go`; `internal/engine/plugin_transactions.go::ProcessTransactionIntents` (raw-only); `internal/apshellapp/submission.go` (localSigners rejection) | `internal/apshellapp/submission_pregrouped_test.go::TestSubmitPluginTransactionsRejectsLocalSigners`; `internal/engine/plugin_pregrouped_test.go::TestProcessSignedTransactionIntents` | Machine-checked in `plugin_signing.tla` (`PS7_NoUngatedSubmission`). The removed `localSigners` path was the violation of this invariant. |

## Open Cross-Cutting Gaps

No open cross-cutting gaps. The concrete sketches that previously lived
in [FORMAL_TEST_GAPS.md](FORMAL_TEST_GAPS.md) have all been closed or
are deferred behind explicit design decisions; see that file for the
status of deferred items.

## Store Cryptography

Source: [PROPOSAL_KEYTERM_ROTATION.md](PROPOSAL_KEYTERM_ROTATION.md)

| ID | Status | Property | Code anchor | Test anchor | Notes |
|---|---|---|---|---|---|
| K1 | implemented | The keyring is the store's only cryptographic root; opening it is the passphrase check | `internal/crypto/keyring.go::OpenKeyring`; `internal/crypto/keyring_store.go::OpenKeyringStore` | `internal/crypto/keyring_test.go::TestOpenKeyringRejectsEditedHeader`; `::TestKeyringHeaderAADIsUnambiguous` | Header travels in the AEAD's authenticated data. |
| K2 | implemented | Only stores this release initialized are readable | `internal/crypto/keyring_store.go::checkKeyringMarker` | `internal/crypto/keyring_test.go::TestOpenKeyringStoreRejectsUnsupportedMarkerVersion` | Rejection names the backup-archive remedy; no migration path exists. |
| K3 | implemented | Every encrypted object is bound to its own logical identity | `internal/crypto/term_envelope.go`; `internal/crypto/keyring.go::aadFor` | `internal/keys/keys_test.go::TestCredentialDoesNotOpenUnderAnotherAddress`; `internal/backup/recovered/store_test.go::TestLoadRecoveredEntryRejectsCrossBatchSubstitution` | Identity is logical, never a path. |
| K4 | implemented | A passphrase change replaces the term key rather than rewrapping it | `internal/storepass/rotate.go::Rotate` | `internal/storepass/rotate_test.go::TestRotateReplacesTheTermKey` | A probe sealed before rotation must not open after it. |
| K5 | implemented | An edited root cannot compel work this release did not choose | `internal/crypto/keyring.go::checkKDFParams` | `internal/crypto/keyring_test.go::TestOpenKeyringRejectsForeignKDFParameters` | Checked before derivation; the AEAD cannot help there. |
| K6 | implemented | This release holds exactly one term | `internal/crypto/keyring.go::OpenKeyring` | `internal/crypto/keyring_test.go::TestOpenKeyringRejectsMultipleTerms`; `::TestOpenKeyringZeroesRejectedTermKeys` | The v2 root shape is installed, but relaxing the one-term runtime gate must land with authority-set opening and the R5 pending-transition guard. |
| K7 | implemented | Passphrase and integrity-key derivation exist only inside `internal/crypto` | `internal/crypto` package boundary; `Keyring.SignIntegrity` / `VerifyIntegrity` | `test/arch/kdf_confinement_test.go::TestKeyDerivationLivesOnlyInCrypto`; `::TestRawTermKeysAreNotAdoptedOutsideTests`; `::TestTestFixturesStayOutOfProduction`; `internal/crypto/keyring_test.go::TestKeyringIntegrityOperationsMatchTheDerivedKeys` | Production callers receive MACs rather than raw derived integrity keys. The architecture tests parse files directly, so `//go:build testmode` code is covered. |
| K8 | **not implemented** | Every durable class has an explicit term-authority classification | `internal/rotationinventory`; `internal/genstore/records.go`; `internal/genstore/validate.go`; `internal/policy/integrity.go`; `internal/noderole/integrity.go` (partial foundation) | `internal/rotationinventory/scan_test.go::TestScanClassifiesEveryK8DurableClass`; `snapshot_test.go::TestSnapshotWriteReadPinsExactEncryptedFile`; `baseline_test.go::TestBaselineWriteReadAndAuthority`; `::TestReconcileBaselineForPreflight`; `internal/genstore/genstore_test.go::TestGenerationInventoryAndSealAuthenticateMemberTerms`; `::TestAnchoredHistoricalSealAndExactMemberOpen`; wrong-context, wrong-term, sealed-plaintext mutation, recursive-snapshot, oversize, durability-failure, and unknown-artifact negative controls; generation-seal and sidecar tests | The taxonomy, settled-store scanner, strict sealed snapshot and baseline codecs/storage, exact root-reference verifier, per-member seal terms, exact historical anchors, anchor-gated retired-term open, and mutation matrix are implemented. Pending-root commit integration must reference the snapshot and complete anchor set; pinned-input rewrap, completion-baseline ordering, rollback consumption, and final exact-path/target-authority verification remain the pre-append gate. |
| R1 | deferred | Live store data is never stranded on an unauthorized term during rotation | Phase-3 authority-set open and resumable rewrap | `docs/formal/rotation_transition.tla::R1_LiveDataNeverStranded` | Machine-checked transition target; implementation gates are PHASE3_ONBOARDING items 4, 6, and 7. |
| R2 | deferred | Only cutover-pinned objects may reach the target term | Phase-3 sealed snapshot and authority-set open | `docs/formal/rotation_transition.tla::R2_OnlyPinnedObjectsReachNewTerm` | Machine-checked transition target; implementation gates are PHASE3_ONBOARDING items 1, 4, and 7. |
| R3 | deferred | A completed clean rotation leaves rollback available | `internal/rotationinventory/baseline.go` (record/storage foundation); transition completion and rollback wiring deferred | `internal/rotationinventory/baseline_test.go::TestBaselineWriteReadAndAuthority`; `docs/formal/rotation_transition.tla::R3_CompletedRotationLeavesRollbackAvailable` | Strict current-term baseline storage is implemented, but completion does not yet write it before close and rollback does not yet consume it. Implementation gates remain PHASE3_ONBOARDING items 2 and 9. |
| R4 | deferred | Rotation never erases pre-cutover divergence | `internal/rotationinventory/baseline.go::EvaluateRollbackCutover` (decision foundation); transition wiring deferred | `internal/rotationinventory/baseline_test.go::TestEvaluateRollbackCutoverUsesEffectiveAuthority`; `docs/formal/rotation_transition.tla::R4_DivergenceNeverErased` | The pure decision preserves manifest/prior-baseline divergence, but snapshot construction and completion are not yet wired to it. Implementation gates remain PHASE3_ONBOARDING items 2 and 9. |
| R5 | deferred | Resume never appends a second term to a pending rotation | Phase-3 `StartRotation` pending guard | `docs/formal/rotation_transition.tla::R5_NoSecondAppend`; `rotation_transition_negative.cfg` | Machine-checked with a third resident term; the standard harness requires the unguarded-resume mutation to violate R5. The implementation gate is PHASE3_ONBOARDING item 5. |

## Machine-Checkable Coverage

### Rotation transition module

[formal/rotation_transition.tla](formal/rotation_transition.tla) is a temporal
transition model for append, rewrap, baseline, close, crash/resume, and
filesystem-attacker interleavings. The positive configuration checks 52
distinct states at depth 9 with no counterexamples.
[formal/rotation_transition_negative.cfg](formal/rotation_transition_negative.cfg)
enables an unguarded resume append; the standard harness requires the resulting
third resident term to violate R5 after 21 distinct states at depth 4.

| Invariant | TLA+ predicate |
|---|---|
| R1 (live data remains readable) | `R1_LiveDataNeverStranded` |
| R2 (only cutover-pinned objects are promoted) | `R2_OnlyPinnedObjectsReachNewTerm` |
| R3 (clean completion preserves rollback) | `R3_CompletedRotationLeavesRollbackAvailable` |
| R4 (divergence is never erased) | `R4_DivergenceNeverErased` |
| R5 (resume does not append again) | `R5_NoSecondAppend` |

R2 and R3 retain their documented source mutations. R5's mutation is a
first-class expected-failure run in `docs/formal/metrics.json`, so CI fails if
the negative control stops producing the named counterexample or if the
positive model admits it.

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
which TLC confirms over every input combination. I9 is the
centerpiece: it could not be machine-checked in the sign-boundary
module because verdict was a free oracle; here verdict is derived from
rule application, so I9 becomes a real property TLC verifies.

### Composition module

[formal/composition.tla](formal/composition.tla) (see
[FORMAL_TLA_COMPOSITION_MODEL.md](FORMAL_TLA_COMPOSITION_MODEL.md))
joins the two component modules. The verdict that sign_boundary
treats as a free oracle is here derived by running
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
`Safety`. A separate liveness run (`lifecycle_liveness.cfg`, no symmetry —
unsound for TLC liveness) adds `SignerRestart` (recurring signing
operations) and verifies `Progress` under `LiveSpec`: writer-priority
starvation freedom (a queued decommission finishes; every held lease
releases), 150 distinct states, depth 14. Mutation: removing
`~WriterPending` from `SignerAcquire` yields a starvation lasso.

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
(Pending Approvals Fail On Successful Decommission) is machine-checked
in the approval coordinator module below, which supplies the
pending-approval state machine that L8 needs.

### Approval coordinator module

[formal/approval_coordinator.tla](formal/approval_coordinator.tla) (see
[FORMAL_TLA_APPROVAL_COORDINATOR_MODEL.md](FORMAL_TLA_APPROVAL_COORDINATOR_MODEL.md))
models the per-request approval state machine. Like `lifecycle.tla` it has real
transitions in `Next`: requests interleave over a shared single-delivery turn
with operator decisions, timeout, cancellation, operator-client disconnect,
client displacement, and decommission. TLC checked under
`Requests = {r1, r2, r3}`: the safety run (with symmetry) generated 196
distinct states at depth 11 with no counterexamples for `Safety`; the liveness
run (`approval_coordinator_liveness.cfg`, no symmetry — TLC liveness checking
is unsound under symmetry) generated 833 distinct states and verified
`Progress` under `LiveSpec`.

| Invariant | TLA+ predicate |
|---|---|
| AP4 (Single Delivery In Flight) | `AP4_SingleDelivery` |
| AP5 (Cancellation Always Enabled) | `AP5_CancelAlwaysEnabled` |
| AP6 (Decommission Leaves No Pending) | `AP6_DecommissionLeavesNoPending` |
| AP7 (No Orphaned Delivery On Displacement) | `AP7_NoOrphanedDelivery` |
| L8 (No Approval After Decommission) | `L8_NoApproveAfterDecommission` |
| Progress (queued/delivered requests terminate; liveness) | `Progress` under `LiveSpec` |
| turn/state consistency | `TypeOK` |

L8 is the headline: it was the only `deferred` invariant, held back because it
crosses the lifecycle/approval boundary. It is checked via the
`badApproveAfterDecommission` history flag and validated by mutation test
(removing the `~decommissioned` guard from `Deliver` produces a counterexample).
AP1 (single resolution), AP2 (only approve permits a signature), and AP3
(response ID binding) are modeled by construction — absorbing terminal states and
per-request action identity — not as separate predicates.

### Approval composition module

[formal/approval_composition.tla](formal/approval_composition.tla) (see
[FORMAL_TLA_APPROVAL_COMPOSITION_MODEL.md](FORMAL_TLA_APPROVAL_COMPOSITION_MODEL.md))
joins the coordinator's terminal outcome with the policy pipeline: it replaces
`policy_precedence.tla`'s free four-valued `approval` oracle with the value
derived from the coordinator outcome and feeds it end to end into signing output.
Like `composition.tla` it is one-shot; TLC checked under `MaxRequestEntries = 3`,
`MaxDummies = 2`, generating 47,304 distinct states, depth 1, no counterexamples.
These are cross-module seam claims rather than new numbered invariants.

| Claim | TLA+ predicate |
|---|---|
| `approval` derived from coordinator outcome | `ApprovalDerivedFromCoordinator` |
| Coordinator consulted iff review-class verdict | `ConsultedIffReview` |
| Review-class signs only if coordinator approved (AP2) | `CoordinatorApproveRequiredToSign` |
| Every non-approve coordinator outcome rejects | `NonApproveCoordinatorRejects` |
| Fail-all yields no signed output, end to end (L8) | `FailAllProducesNoSignedOutput` |
| Hard deny dominates the coordinator (I9) | `HardDenyDominatesCoordinator` |
| Policy outcome binds signing output | `PolicyOutcomeBindsOutput` |

Validated by mutation test: mapping the `Failed` (fail-all) outcome to `approve`
produces a counterexample where a fail-all'd review-class request signs.

### Lifecycle composition module

[formal/lifecycle_composition.tla](formal/lifecycle_composition.tla) (see
[FORMAL_TLA_LIFECYCLE_COMPOSITION_MODEL.md](FORMAL_TLA_LIFECYCLE_COMPOSITION_MODEL.md))
joins the temporal lifecycle lock race with a lease-gated signing step, checking
end to end that a signer produces output only while holding a lease acquired before
decommission. Like `lifecycle.tla` it is a temporal-transition spec; TLC checked
under `SignerProcs = {s1, s2}` with symmetry, generating 226 distinct states, depth
12, no counterexamples. A separate liveness run
(`lifecycle_composition_liveness.cfg`, no symmetry) verifies `Progress` under
`LiveSpec`: every held lease eventually completes (no request left forever
neither signed nor rejected) and a queued decommission finishes — 392 distinct
states, depth 12; mutation: dropping the `SignerSign` fairness conjunct yields
a lasso. It re-checks lifecycle L4-L7 under the extended model and
adds two seam claims; the policy decision is consumed as the boolean `policySigned`
(its derivation is in `composition.tla` / `approval_composition.tla`).

| Claim | TLA+ predicate |
|---|---|
| L4-L7 (carried) | `L4_LeaseGatesSigning` .. `L7_RegistryRemoveDoesNotPreventCompletion` |
| Output requires a held lease + signing policy | `LifecycleGatesOutput` |
| Rejected (post-decommission) signer produces no output | `RejectedProducesNoOutput` |

Validated by mutation test: making the signing step ignore `policySigned` (always
producing output) yields a counterexample.

### Session ownership module

[formal/session_ownership.tla](formal/session_ownership.tla) (see
[FORMAL_TLA_SESSION_OWNERSHIP_MODEL.md](FORMAL_TLA_SESSION_OWNERSHIP_MODEL.md))
models admin-session ownership against one identity: authentication unlocks the
identity before ownership is established, so the invariant is that no failure
between unlock and promotion strands the identity unlocked with no live
authenticated session responsible for re-locking (`lock_on_disconnect`). It is
a temporal-transition spec; TLC checked under `Sessions = {a1, a2, a3}` with
symmetry, generating 90 distinct states, depth 8, no counterexamples.

| Invariant | TLA+ predicate | Code anchor | Test anchor |
|---|---|---|---|
| SO1 (single active owner) | `SO1_SingleActiveOwner` | `internal/signerapp/adminserver/manager.go::PromoteToActive` (atomic swap under the manager mutex); `::ClearActive` | `internal/signerapp/daemon/ipc_displacement_test.go::TestOfferDisplacementKeepsExistingClientUntilReplacementPromoted` |
| SO2 (no stranded unlock) | `SO2_UnlockedHasOwner` | `internal/signerapp/daemon/ipc.go::handleRegisteredClient` disconnect defer (`authenticated && (wasActiveClient \|\| !HasClient)`); `internal/signerapp/adminserver/displacement.go::OfferDisplacement` / `::DisplaceSession` (replacement promoted before the old owner is closed) | `internal/signerapp/daemon/ipc_disconnect_test.go::TestAdminAuthPromotionFailureCleansUnlockedIdentity`; `::TestAdminDisconnectAppliesLockOnDisconnect`; `internal/signerapp/daemon/ipc_displacement_test.go::TestDisplacementReplacementAuthFailureKeepsOldOwner` |

Validated by mutation tests: reverting the cleanup condition to the pre-fix
`authenticated && wasActiveClient` violates SO2 in three states (the
stranded-unlock audit finding); the pre-fix displacement ordering (owner
cleared at confirm time) under the fixed condition still satisfies SO2 but
over-locks the identity under the incoming replacement, which is why the fix
changed both the condition and the ordering.

### Guarded assembly module

[formal/guarded_assembly.tla](formal/guarded_assembly.tla) (see
[FORMAL_TLA_GUARDED_ASSEMBLY_MODEL.md](FORMAL_TLA_GUARDED_ASSEMBLY_MODEL.md))
machine-checks the assembly-verification core of the guarded signing model:
a one-shot enumeration (sign_boundary style) over presented component
signatures (right/wrong key, role domain, txid binding) and passthrough
bytes, with the decision procedure transcribing
`internal/signerapp/signing/component_assemble.go`. TLC checked under
`MaxEntries = 2`, generating 270,920 distinct states, depth 1, no
counterexamples.

| Invariant | TLA+ predicate |
|---|---|
| A1 (role domain separation) | `A1_RoleDomainSeparation` |
| A6 (user signature verified) | `A6_UserSignatureVerified` |
| A7 (sentry signature verified) | `A7_SentrySignatureVerified` |
| A8 (passthrough txid binding) | `A8_PassthroughTxidBound` |
| A14 (assembled txn binding) | `A14_AssembledTxnBound` |
| abort-on-first-failure | `NoPartialOutput` |

Validated by mutation tests: dropping the role check from `Verifies`
(cross-role replay) and dropping the passthrough txid comparison each
violate `Safety` in an initial state.

### Bounded sentry module

[formal/bounded_sentry.tla](formal/bounded_sentry.tla) (see
[FORMAL_TLA_BOUNDED_SENTRY_MODEL.md](FORMAL_TLA_BOUNDED_SENTRY_MODEL.md))
machine-checks the combined planning and assembly choreography. It is a
depth-4 transition system covering user-side base release, the later sentry
request/release, final bounded assembly, and the sentry-free external-admin
branch. TLC generated 99,584 distinct states with no counterexamples. Target
count is intentionally absent: the predicates are group-wide, so a
target-count field only duplicated states without adding coverage.

| Invariant | TLA+ predicate |
|---|---|
| BS1 (first-party user-first choreography) | `BS1_UserFirst` |
| BS2 (admin bypasses sentry) | `BS2_AdminBypassesSentry` |
| BS3 (both spend authorities verified) | `BS3_SpendAuthoritiesVerified` |
| BS4 (declared arguments only) | `BS4_DeclaredArgumentsOnly` |
| BS5 (canonical group bound) | `BS5_CanonicalGroupBound` |
| BS6 (invalid path cannot output) | `BS6_InvalidNeverOutputs` |
| BS7 (atomic output) | `BS7_AtomicOutput` |

The named invariants are constructed to expose early sentry routing, sentry use
on admin, omitted signature verification, omitted source/coverage/byte checks,
and partial output as counterexamples.

### Plugin signing module

[formal/plugin_signing.tla](formal/plugin_signing.tla) (see
[FORMAL_TLA_PLUGIN_SIGNING_MODEL.md](FORMAL_TLA_PLUGIN_SIGNING_MODEL.md))
machine-checks the plugin signing trust boundary's decision procedure: a
one-shot enumeration over both surviving group modes (pregrouped-signed,
presign-plan), per-slot validation outcomes, and gate decisions. TLC checked
under `MaxSlots = 3`, generating 3,852 distinct states, depth 1, no
counterexamples. PS1 is structural (Go type construction) and deliberately
has no TLC predicate.

| Invariant | TLA+ predicate |
|---|---|
| PS2 (group digest integrity) | `PS2_GroupDigestVerified` |
| PS3 (mandatory review, fail-closed) | `PS3_MandatoryReviewFailClosed` |
| PS4 (plan preservation) | `PS4_PlanPreserved` |
| PS5 (byte match + index discipline) | `PS5_SignedSlotByteMatch` |
| PS6 (managed approval gate) | `PS6_ManagedApprovalGated` |
| PS7 (no ungated submission) | `PS7_NoUngatedSubmission` |

Validated by mutation tests: dropping the digest conjunct violates PS2;
dropping the review conjunct violates PS3/PS7 (the removed-`localSigners`
bypass class, machine-reproduced).

### Unmodeled invariants

The following invariants have no TLA+ representation yet:
- Most of I4-I6 and CS1-CS4 (planning details and client simulation composition).
- P1, P2, P3, P8, P9, P10 (snapshot semantics, slot scope, routing,
  key overrides).
- L1, L2, L3, L9-L11 (lifecycle non-concurrency claims). L8 is now
  machine-checked in `approval_coordinator.tla`.
- All of S1-S13 (signing authority) — **by decision, not omission** (2026-07-03
  review): S1/S3-S5/S8/S11/S12 are structural or definitional (a module would
  verify its own encoding), S2/S6/S7/S9 are single-guard checks whose only
  nontrivial content (cryptography, cross-path enforcement) is exactly what
  TLC must abstract away, and S10's snapshot-copy design holds by
  construction (pinned by `TestPlannerUsesSingleIdentitySnapshot`). S13
  (filename↔address binding with collision fallback) is the sole
  revisit-candidate, and only if the key-file scan ever gains a
  winner-picking rule instead of skip-and-warn.
- A2-A5, A9-A13, A15 (guarded signing: component-sign-time checks, endpoint
  routing, client shape checks, identity mode). A1/A6/A7/A8/A14 are
  machine-checked in `guarded_assembly.tla`. The separate bounded-sentry
  planning and assembly path is machine-checked in `bounded_sentry.tla`.
- AP1-AP3 (approval coordinator) are modeled by construction rather than as
  predicates; AP4-AP7 and L8 are machine-checked in `approval_coordinator.tla`.

Lifecycle-aware composition has shipped as
[formal/lifecycle_composition.tla](formal/lifecycle_composition.tla) (above).
With the signing-authority surface resolved by decision, the remaining
candidates are the M3 backlog English models (LogicSig budget and
template/bytecode generation) and a legacy guarded sentry
component-sign-time module (A3-A5) if one is ever needed.

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
