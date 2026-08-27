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
| I5 | implemented | Pre-Grouped Immutability | `internal/signerapp/signing/planner_runtime.go::calculateLogicSigResources` (pre-grouped/passthrough groups needing dummies are rejected rather than mutated) | `internal/signerapp/signing/planner_runtime_test.go::TestCalculateLogicSigResourcesRejectsUnderprovisionedImmutablePassthrough`; `::TestValidateGroupConsistency` | Enforcement is reject-on-underprovision: an immutable group that would need dummies fails closed instead of being regrouped. |
| I6 | implemented | Policy and Approval Boundary | `internal/signerapp/signing/service.go::signGroupWithPlanContext` passes plan-derived txns to evaluators | `internal/signerapp/signing/service_test.go::TestSignGroupWithPlanEvaluatesFinalizedTxnsNotCallerDrafts` covers divergent draft/finalized fee verdicts in both directions. | |
| I7 | implemented | Signing Output Rules; I7 | `internal/signerapp/signing/execution.go` (foreign slot -> "") | `internal/signerapp/daemon/plan_sign_parity_test.go::TestPlanAllowsMixedSignAndForeignGroupAndPreservesCanonicalTransactions` asserts the signer-owned output is populated and the foreign output is `""` after `/sign`. | |
| I8 | implemented | Signing Output Rules; I8 | `internal/signerapp/signing/execution.go` passes through `signed_txn_hex` | `test/integration/passthrough_test.go:217` asserts `groupResp.Signed[1] == stxnBHex` after `/sign`; `:461` confirms preservation through resign | Direct byte-equality assertion exists. |
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
| P2 | implemented | Runtime Snapshot Semantics; P2 | `internal/signerapp/policyruntime/policy.go` (snapshot capture per-request); `internal/signerapp/daemon/signing_service.go::newSigningServiceWithAudit`; `internal/signerapp/daemon/approval_service.go::newApprovalServiceWithAudit`; `internal/signerapp/signing/service.go::signGroupWithPlanContext` | `internal/signerapp/productruntime/productruntime_test.go::TestRuntimePolicySnapshotStoresDefensiveCopies`; `internal/signerapp/daemon/signing_service_test.go::TestNewSigningServiceForRuntimeCapturesPolicyAndUserAutoApproveSnapshot`; `internal/signerapp/signing/service_test.go::TestSignGroupWithPlanDoesNotReevaluatePolicyAfterApproval` | Defensive policy copies, sign-service policy/default capture, and no post-approval policy re-evaluation are covered. |
| P3 | implemented | Planned Request | `internal/signerapp/signing/service.go::signGroupWithPlanContext` passes `allTxns` (plan output) to evaluators | `internal/signerapp/signing/service_test.go::TestSignGroupWithPlanEvaluatesFinalizedTxnsNotCallerDrafts` pins that policy follows finalized data when caller draft bytes diverge. | |
| P4 | implemented | Deny Dominance | `internal/signerapp/signing/approval.go::EvaluateAutoRejectionRules` is called first | `internal/signerapp/signing/service_test.go::TestSignGroupWithPlanUserAutoApproveStillRejectsPolicyViolation` | Machine-checked via `policy_precedence.tla::P4_DenyDominance`. |
| P5 | derived | Decision Procedure | Order-of-evaluation in `signGroupWithPlanContext` and `EvaluateAlwaysReviewRules` | `internal/signerapp/signing/service_test.go::TestSignGroupWithPlanAlwaysReviewWarningsOverridesUserAutoApprove`; `*TransferRoutingReviewOverrides*` | Holds by construction of the short-circuit decision procedure. Machine-checked via `policy_precedence.tla::P5_ReviewDominance`. |
| P6 | derived | Decision Procedure | Order-of-evaluation in `signGroupWithPlanContext`; `EvaluateAutoApprovalRules` is third in the chain | `internal/signerapp/signing/service_test.go::TestSignGroupWithPlanAutoApproveSelfNoOpTransferSkipsManualReview` | Machine-checked via `policy_precedence.tla::P6_ApproveAfterDenyReview`. |
| P7 | derived | Decision Procedure | `user_auto_approve` consulted only after policy verdict miss | `internal/signerapp/signing/service_test.go::TestSignGroupWithPlanAlwaysReviewWarningsOverridesUserAutoApprove`; `::TestSignGroupWithPlanTransferRoutingReviewOverridesUserAutoApprove`; `::TestSignGroupWithPlanUsesSingleTxnApprovalForServerAddedDummies`; `internal/signerapp/daemon/audit_test.go::TestHandleSignWritesHTTPAttributedAuditEntries` | Machine-checked via `policy_precedence.tla::P7_OperatorDefaultLast`. |
| P8 | implemented | Passthrough and Foreign Policy Scope | signer-owned evaluators skip passthrough/foreign positions by index map; `EvaluateAlwaysReviewRules` still inspects their warning-bearing fields | `internal/signerapp/signing/service_test.go::TestEvaluateAutoRejectionRulesSkipsForeignAndDummyTransactions`; `*SkipsTransferRoutingForPassthroughForeignAndDummySlots*`; `internal/signerapp/signing/always_review_test.go::TestEvaluateAlwaysReviewRulesForcesReviewOnDangerousPassthrough` | External slots remain visible to group context, approval rendering, and audit. |
| P9 | implemented | P9 | `internal/policy/transfer_routing_eval.go` returns `Reject`/`Review`/no-verdict only | `internal/policy/transfer_routing_eval_test.go`; `internal/policy/ruleids_test.go` | |
| P10 | implemented | Effective Policy Selection; P10 | `internal/policy/config.go::ForKey`; `internal/signerapp/signing/service.go::authPolicyKeysFromRequest` passes auth addresses to policy evaluators | `internal/signerapp/signing/always_review_test.go::TestEvaluateAlwaysReviewRulesUsesKeyOverride`; `service_test.go::TestEvaluateAutoRejectionRulesAppliesKeyOverrides` | |

## Runtime Reload Order

| ID | Status | Contract | Test anchor |
|---|---|---|---|
| RL1 | implemented | Reload runs the configured pre-scan hook, reloads durable template and key-type state, then scans keys while holding the process store-mutation exclusion contract. | `internal/signerapp/templates/reload_test.go::TestReloadRunsBeforeKeyScanHookBeforeTemplatesAndScan`; `internal/signerapp/productruntime/productruntime_test.go::TestWatcherReloadUsesMutationLock` |

## Signing Authority Model

Source: [FORMAL_SIGNING_AUTHORITY_MODEL.md](FORMAL_SIGNING_AUTHORITY_MODEL.md)

| ID | Status | Source § | Code anchor | Test anchor | Notes |
|---|---|---|---|---|---|
| S1 | implemented | S1 | `internal/keys/keys.go` scan reads stored payload; `internal/signerapp/signing/execution.go` signs from stored authority | Integration: `test/integration/basic_falcon_test.go` and related Falcon tests exercise stored-authority signing. | |
| S2 | implemented | LogicSig v1 Metadata; S2 | Sign-time: `internal/signerapp/signing/execution.go:215,395` (`SigningMetadataVersion == 0` -> `missingLogicSigSigningMetadata`); restore-time strict parsing: `internal/backup/direct_restore.go::inspectCredentialBackupEntry` -> `internal/keys.ParsePayload` | Restore parsing: `internal/keys/payload_codec_test.go`; standalone portability: `test/integration/backup_portability_test.go::TestBackupRestoreStandaloneNoTemplateSucceedsWithoutLocalTemplate`; sign path: `internal/signerapp/signing/execution_test.go::TestExecutorSignGenericLSigRejectsMissingSigningMetadata`; `*AssembleDSALogicSigRejectsMissingSigningMetadata` | |
| S3 | implemented | S3 | `internal/keys.Payload.Selector` derives address from bytecode | `internal/keys/payload_codec_test.go`; `internal/keys/template_fingerprint_test.go` | |
| S4 | implemented | S4 | `internal/signingargs` orders runtime args by stored signing_args | `internal/signerapp/signing/runtime_args_test.go` | |
| S5 | implemented | S5 | `internal/keys/keys.go` reads stored payload only; reload paths preserve already-registered templates | `internal/signerapp/daemon/template_reload_test.go::TestReloadKeysKeepsOriginalGenericTemplateDefinition`; `*PreservesAlreadyRegisteredGenericDefinition` | |
| S6 | implemented | Off-Curve Requirement; S6 | `internal/lsigsalt` enforces off-curve at create; `internal/keys.Payload.Validate` rejects on-curve stored LogicSig bytecode during parse/scan/restore | `internal/keys/payload_codec_test.go`; `internal/keys/keys_test.go::TestScanKeysDirectoryWithKeyringRejectsDSALSigInvalidBytecode` | |
| S7 | implemented | Derivation Record Consistency, Not Address Authority; S7 | `internal/keys.Payload.Validate` requires or forbids `salt_counter` according to `lsig_derivation`; address identity still comes from stored bytecode | `internal/keys/payload_codec_test.go::TestAutoSaltedLogicSigPayloadContract`; manual-counter validation and scan/restore cases in `internal/keys/payload_codec_test.go` and `internal/keys/keys_test.go` | `algod_v13_auto_salt` omits the counter; compatible manual-counter records require it. |
| S8 | implemented | S8 | Template fingerprint check is inventory-only; not consulted at sign time | `internal/keys/template_fingerprint_test.go::TestTemplateFingerprintComparison`; `*Unavailable`. Sign-time isolation follows from S5 anchors. | |
| S9 | implemented | S9 | `internal/keys.ParsePayload` rejects duplicate JSON object members, unknown fields, and obsolete payload aliases | `internal/keys/payload_codec_test.go` | Fresh-system canonical schema removes cosmetic alias normalization. |
| S10 | implemented | Runtime Key Index; S10 | `internal/signerapp/productruntime/runtime.go::KeyIndexSnapshot`; `internal/signerapp/signing/planner.go::PlanGroup`; `internal/signerapp/signing/planner_runtime.go::verifySignableKeys` | `internal/signerapp/productruntime/productruntime_test.go::TestKeyIndexSnapshotMaterializesConsistentCopy`; `internal/signerapp/signing/planner_runtime_test.go::TestPlannerUsesSingleRuntimeSnapshot` | Planning materializes key files, key types, LogicSig resource profiles, and signer-local known addresses from one copied snapshot. |
| S11 | implemented | Auth Address Binding; S11 | `internal/signerapp/signing/planner_runtime.go` resolves auth addresses through `PlannerRuntimeSnapshot.KeyFiles` | `internal/signerapp/signing/planner_runtime_test.go::TestVerifySignableKeysRequiresKeyFileInSnapshot`; `::TestVerifySignableKeysRequiresKeyTypeMetadata` | |
| S12 | implemented | S12 | `internal/signerapp/signing/service.go::authPolicyKeysFromRequest` uses `txReq.AuthAddress` for policy override selection; `policyCfg.ForKey` consumes it | `internal/signerapp/signing/always_review_test.go::TestEvaluateAlwaysReviewRulesUsesKeyOverride`; `service_test.go::TestEvaluateAutoRejectionRulesAppliesKeyOverrides` | |
| S13 | implemented | Canonical Filename Binding; S13 | `internal/keys/managed_files.go` owns `CanonicalName = Selector || ExtensionForCategory`; scan rejects selector and category/extension mismatches; save, backup/restore, deletion, rotation, and watching consume the central classes | `internal/keys/managed_files_test.go`; `internal/keys/keys_test.go::TestScanKeysDirectoryWithKeyring`; `internal/keys/save_test.go::TestSavePayloadWritesWitnessPublicMetadata`; `internal/keys/managed_files_test.go::TestManagedCredentialDestinationRejectsContradictoryClass`; `test/arch/managed_credential_files_test.go` | Account authority is `.key`; sentry witness authority is `.sen`; `.wit` is excluded. Accepted-selector collision invalidation remains a defensive fallback. |

## Guarded Signing Model

Source: [FORMAL_GUARDED_SIGNING_MODEL.md](FORMAL_GUARDED_SIGNING_MODEL.md)

| ID | Status | Source § | Code anchor | Test anchor | Notes |
|---|---|---|---|---|---|
| A1 | implemented | A1 | `internal/sentry/message/message.go`; `internal/signerapp/signing/component.go::prepareComponentSigning` | `internal/signerapp/signing/component_test.go::TestPrepareComponentSigningUsesSentryRoleDomain`; `::TestAssembleDecodedGuardedRejectsWrongUserSignature` | Role byte separates user and sentry signatures for the same target txid. Machine-checked in `guarded_assembly.tla` (`A1_RoleDomainSeparation`). |
| A2 | implemented | A2 | `internal/signerapp/signing/sentry_gate.go`; `internal/signerapp/signing/execution.go` | `internal/signerapp/signing/execution_test.go::TestExecutorRejectsSentryKeyTypesBeforeSessionLoad`; `::TestExecutorSignCryptoKeyRejectsSentryKeyTypesBeforeProviderLookup` | Covers witness keys and the dedicated guarded account key type; bounded-sentry ordinary-sign rejection is tested separately. |
| A3 | implemented | A3 | `internal/signerapp/signing/component_sign.go::signPreparedUserComponents`; `::loadGuardedAccountSigningKey` | `internal/signerapp/signing/component_test.go::TestSignPreparedUserComponentsSignsGuardedAccountMessages`; `::TestSignPreparedUserComponentsSignsGuardedAuthorizerMessages` | User component signing proves `component_key` is a local guarded account key; sender may differ and is bound by assembly. |
| A4 | implemented | A4 | `internal/signerapp/signing/service.go::signComponentWithContext` (entry: `unified_component.go::SignComponentsWithContext`); `internal/signerapp/signing/sentry_policy.go`; `internal/policy` | `internal/signerapp/signing/component_test.go::TestSignComponentSentryRequiresPolicyBeforeKeyLoad`; `::TestSignComponentSentryRejectsNonTransferBeforeKeyLoad`; `::TestSignComponentSentryRejectsRouteMissBeforeKeyLoad`; `::TestSignComponentSentryRejectsInheritedReviewRouteMissBeforeKeyLoad`; `::TestSignComponentSentryRejectsRekeyBeforeKeyLoad` | Sentry policy is deterministic: no review and no operator default. |
| A5 | implemented | A5 | `internal/signerapp/signing/component_sign.go::loadSentryComponentKey`; `internal/witness` | `internal/signerapp/signing/component_test.go::TestSignPreparedSentryComponentsRejectsWrongKeyType`; `::TestLoadSentryComponentKeyRejectsMismatchedPublicPrivateKey`; `::TestSignPreparedSentryComponentsSignsFalcon1024Messages` | Witness Key ID, category, key type, and public/private pair must agree. |
| A6 | implemented | A6 | `internal/signerapp/signing/component_assemble.go::assembleGuardedTarget` | `internal/signerapp/signing/component_test.go::TestAssembleDecodedGuardedRejectsWrongUserSignature`; `::TestAssembleDecodedGuardedVerifiesAndBuildsSignedGroup` | User signature is checked against the user public key stored in the local guarded account key. Machine-checked in `guarded_assembly.tla` (`A6_UserSignatureVerified`). |
| A7 | implemented | A7 | `internal/signerapp/signing/component_assemble.go::assembleGuardedTarget` | `internal/signerapp/signing/component_test.go::TestAssembleDecodedGuardedRejectsWrongSentrySignature`; `::TestAssembleDecodedGuardedVerifiesFalconSentryAndBuildsSignedGroup` | Sentry signature is checked against the sentry public key embedded in local key metadata/bytecode, not endpoint metadata. Machine-checked in `guarded_assembly.tla` (`A7_SentrySignatureVerified`). |
| A8 | implemented | A8 | `internal/signerapp/signing/component_assemble.go::validateGuardedPassthrough` | `internal/signerapp/signing/component_test.go::TestAssembleDecodedGuardedRejectsMismatchedPassthrough`; `::TestAssembleDecodedGuardedVerifiesAndBuildsSignedGroup` | Passthrough bytes are preserved only when their decoded txid matches the canonical group entry. Machine-checked in `guarded_assembly.tla` (`A8_PassthroughTxidBound`). |
| A9 | implemented | A9 | `internal/engine/guarded/discovery.go::resolveSentryEndpoints` | `internal/engine/guarded/discovery_resolver_test.go::TestLiveSentryResolverRemovesImplicitPrimarySignerFallback`; `::TestLiveSentryResolverUsesDeterministicAliasPrefix`; `::TestLiveSentryResolverHostKeyMismatchAbortsGlobalSearch` | `/keys` resolves an operation-scoped route only; every required key needs exactly one live configured endpoint, and there is no implicit primary-signer fallback. |
| A10 | implemented | A10 | `internal/engine/guarded/submit.go::requestOneSentryComponentSignatureSet`; `internal/sentry/canonical` | `cmd/apshell/deps_test.go::TestClientDoesNotLinkFalcon` | Client collects and forwards component signatures without cryptographic verification; the deps test pins the client binary to exclude `internal/sentry/verify` and the Falcon libraries. |
| A11 | implemented | A11 | `internal/engine/guarded/submit.go::collectComponentSignatures`; `pkg/signerapi/sentry.go` | `internal/engine/guarded/submit_test.go::TestCollectComponentSignaturesRejectsMalformedResponses` (`collectComponentSignatures` enforces exact coverage + scheme directly) | Client requires exact response coverage and expected scheme before forwarding signatures to assembly. |
| A12 | implemented | A12 | `internal/engine/guarded/discovery.go`; `internal/apshellapp/endpoints.go` | `internal/engine/guarded/discovery_resolver_test.go::TestLiveSentryResolverLimitsConcurrentProbes`; `::TestLiveSentryResolverRejectsEndpointOverflowBeforeProbing`; `internal/apshellapp/endpoints_test.go::TestEndpointDiscoverSentriesIsReadOnly`; `::TestEndpointDiscoverSentriesRejectsDuplicatePublication` | Routing discovery is bounded and operation-scoped; the shell diagnostic is read-only, and malformed or duplicate live metadata fails closed. |
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
| BS4 | implemented | BS4 | `internal/signerapp/signing/service.go::AssembleWithContext`; `internal/signerapp/signing/bounded_sentry.go::assembleBoundedTarget`; bounded argument assembly in `internal/signerapp/signing/execution.go` | `internal/engine/guarded/submit_test.go::TestCollectComponentSignaturesRejectsMalformedResponses`; `internal/signerapp/signing/execution_test.go::TestAssembleBoundedArgsPreservesInteriorEmptySlots` | Exact target coverage and source/path masks gate assembly; derived inputs remain signer-owned. Machine-checked in `bounded_sentry.tla` (`BS4_DeclaredArgumentsOnly`). |
| BS5 | implemented | BS5 | `internal/engine/guarded/submit.go::verifyAssembledAgainstFrozen`; `internal/signerapp/signing/service.go::AssembleWithContext`; `internal/signerapp/signing/bounded_sentry.go::assembleBoundedTarget` | `internal/engine/guarded/submit_test.go::TestVerifyAssembledAgainstFrozen`; `internal/signerapp/signing/bounded_sentry_test.go::TestBoundedAssemblyReceiptBindsRuntimeAndMetadata` | Receipt, passthrough, and final bytes bind the frozen plan. Machine-checked in `bounded_sentry.tla` (`BS5_CanonicalGroupBound`). |
| BS6 | implemented | BS6 | `internal/signerapp/signing/bounded_sentry.go::validateBoundedComponentPlan`; ordinary-sign rejection in `internal/signerapp/signing/service.go` | `internal/signerapp/signing/bounded_sentry_test.go::TestValidateBoundedComponentPlanRequiresSentrySpend` | Invalid, admin, and non-spend shapes cannot enter bounded-sentry spend output. Machine-checked in `bounded_sentry.tla` (`BS6_InvalidNeverOutputs`). |
| BS7 | implemented | BS7 | `internal/signerapp/signing/service.go::AssembleWithContext`; `internal/signerapp/signing/bounded_sentry.go::assembleBoundedTarget`; `internal/engine/guarded/submit.go::signAndSubmitBoundedSentryGroup` | `internal/signerapp/signing/bounded_sentry_test.go::TestAssembleBoundedTargetVerifiesBothAuthorities`; `internal/engine/guarded/simulate_submit_test.go::TestBoundedSentrySimulateUsesUserFirstChoreography` | Every failed stage returns no signed group; only final assembly reaches submission/simulation. Machine-checked in `bounded_sentry.tla` (`BS7_AtomicOutput`). |

## Approval Coordinator Model

Source: [FORMAL_APPROVAL_COORDINATOR_MODEL.md](FORMAL_APPROVAL_COORDINATOR_MODEL.md)

| ID | Status | Source § | Code anchor | Test anchor | Notes |
|---|---|---|---|---|---|
| AP1 | implemented | AP1 | `internal/signerapp/approval/coordinator.go::HandleSignResponse` (delete-before-deliver); `::trySendSignResponse` (non-blocking, closes channel) | `internal/signerapp/approval/coordinator_test.go::TestCoordinatorLateResponseAfterTimeoutIsIgnored` | At most one terminal outcome per request; late/duplicate events are dropped. |
| AP2 | implemented | AP2 | `internal/signerapp/approval/coordinator.go::RequestSigningApprovalResponseContext`; `internal/signerapp/signing/approval.go::requestSigningApproval` (returns `response.Approved`) | `internal/signerapp/approval/coordinator_test.go::TestCoordinatorCancelSignRequestDismissesPendingApproval`; `::TestCoordinatorFailAllUnblocksPendingRequest` | Only an operator approve yields `Approved=true`; every other outcome denies the signature (approval half of `SignedOutputRequiresPolicyApproval`). |
| AP3 | implemented | AP3 | `internal/signerapp/approval/coordinator.go::HandleSignResponse` (keyed by `msg.ID`) | `internal/signerapp/approval/coordinator_test.go::TestCoordinatorMismatchedResponseIDDoesNotSatisfyActiveRequest` | A response satisfies a request only on exact ID match. |
| AP4 | implemented | AP4 | `internal/signerapp/approval/coordinator.go::acquireDeliveryTurnContext`; `::releaseDeliveryTurn` (`deliveryInFlight`, `deliveryQueue`) | `internal/signerapp/approval/coordinator_test.go::TestCoordinatorSerializesSigningRequests`; `::TestCoordinatorSerializesAcrossApprovalTypes` | One request delivered at a time; FIFO across signing and token-provisioning requests. |
| AP5 | implemented | AP5 | `internal/signerapp/approval/coordinator.go::CancelSignRequest`; `::BeginSignRequest`; `::consumeCanceledSignRequest` | `internal/signerapp/approval/coordinator_test.go::TestCoordinatorCancelSignRequestBeforeApprovalIsPending`; `::TestCoordinatorQueuedSigningApprovalContextCancelReturnsBeforeDeliveryTurn`; `::TestCoordinatorCancelSignRequestCancelsConcurrentSameIDRequests`; `::TestCoordinatorCancelSignRequestUnknownIsNotFound` | Cancellation reaches queued, delivered, and not-yet-waiting requests; unknown ID is `not_found`. |
| AP6 | implemented | AP6 | `internal/signerapp/approval/coordinator.go::FailAllPendingRequests`; production callers cover disconnect, displacement, and lock | `internal/signerapp/approval/coordinator_test.go::TestCoordinatorFailAllClearsPendingMaps`; `::TestCoordinatorFailAllUnblocksPendingRequest`; `internal/signerapp/daemon/hub_test.go::TestFailAllPendingRequests` | Fail-all terminates every then-pending request not-approved. Machine-checked by `AP6_FailAllLeavesNoPending`; end-to-end no-output is checked by `approval_composition.tla::FailAllProducesNoSignedOutput`. |
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
| PS6 | implemented | PS6 | `internal/engine/plugin_presign.go` (managed slots sign-mode, plugin/dummy slots passthrough in one `/sign` request); `internal/signerapp/signing/approval.go:335` (auto-approval disabled for passthrough/foreign/pre-grouped groups; mixed-mode display); `always_review.go` (dangerous-field forced review) | `internal/signerapp/signing/always_review_test.go::TestEvaluateAlwaysReviewRulesForcesReviewOnDangerousPassthrough`; `test/integration/passthrough_test.go` (PassthroughMixedGroup end to end) | Machine-checked in `plugin_signing.tla` (`PS6_ManagedApprovalGated`). The approval pipeline's own invariants are the AP rows. |
| PS7 | implemented | PS7 | Mode dispatch `internal/apshellcli/external_plugins.go`; `internal/engine/plugin_transactions.go::ProcessTransactionIntents` (raw-only); `internal/apshellapp/submission.go` (localSigners rejection) | `internal/apshellapp/submission_pregrouped_test.go::TestSubmitPluginTransactionsRejectsLocalSigners`; `internal/engine/plugin_pregrouped_test.go::TestProcessSignedTransactionIntents` | Machine-checked in `plugin_signing.tla` (`PS7_NoUngatedSubmission`). The removed `localSigners` path was the violation of this invariant. |

## Open Cross-Cutting Gaps

No open cross-cutting gaps. The concrete sketches that previously lived
in [FORMAL_TEST_GAPS.md](FORMAL_TEST_GAPS.md) have all been closed or
are deferred behind explicit design decisions; see that file for the
status of deferred items.

## Store Cryptography

Source: [ARCH_GENERATIONS.md](ARCH_GENERATIONS.md)

| ID | Status | Property | Code anchor | Test anchor | Notes |
|---|---|---|---|---|---|
| S1-S2 | implemented | One authenticated root selects exactly one old-or-new authority state | `internal/crypto/store_root.go`; `internal/genstore/root_commit.go` | `internal/crypto/store_root_test.go::TestStoreRootSealOpenRoundTrip`; `internal/genstore/root_commit_test.go::TestStoreRootCommitInitialAndOrdinarySelection` | Selection, epoch, current term, and wrapped keyring are one commit record. |
| S3 | implemented | A root never selects an unpublished or unsynced generation | `internal/genstore/commit.go`; `internal/genstore/root_commit.go` | `internal/genstore/commit_test.go::TestMintCrashBeforeRootReplacementLeavesParentSelected`; `::TestMintApplyFailureLeavesRootExact` | Publication and directory sync precede root replacement. |
| S4-S5 | implemented | Passphrase change publishes only complete new-term state derived from exact authenticated outgoing bytes | `internal/storepass/rotate.go`; `internal/genstore/records.go`; `internal/genstore/validate.go` | `internal/storepass/rotate_test.go::TestRotatePublishesCompleteFreshTermSuccessor`; `::TestRotatePreRootFailureLeavesOldAuthorityAndQuarantinableSuccessor` | There is no pending transition or resume protocol. |
| S6-S7 | implemented | Historical terms require exact anchors and non-current generations are immutable | `internal/crypto/keyring.go`; `internal/genstore/validate.go` | `internal/genstore/genstore_test.go::TestUnanchoredSealRejectsRetiredMemberTerm`; `::TestAnchoredHistoricalSealAndExactMemberOpen` | Possessing a resident term is insufficient historical authority. |
| S8-S9 | implemented | Invalid selection is never adopted, and root/key authority changes require one rename | `internal/genstore/store_root.go`; `internal/genstore/root_commit.go` | `internal/genstore/store_root_test.go::TestResolveStoreRootFailsClosedOnMissingSelectedGeneration`; `internal/genstore/root_commit_test.go::TestCommitStoreRootPreservesWrappedKeyringFromFreshRead` | Root-changing operations reread and authenticate exact bytes under the mutation lock. |
| S10-S11 | implemented | Restore rollback eligibility is authenticated; recovery restore never fabricates damaged destination authority | `internal/genstore/records.go`; `internal/signerapp/backupadmin/direct_restore.go`; `direct_rollback.go` | `internal/genstore/genstore_test.go::TestRollbackCapabilityCarriesOnlyAcrossExactCleanInventory`; `internal/signerapp/backupadmin/direct_restore_test.go::TestDirectRollbackRefusesDivergedRestoreGeneration` | Broader authority damage routes to rebuild. |
| S12 | implemented | Deleted archives stay within closed count and byte limits | `internal/genstore/archive_capacity.go`; `archive_prune.go` | `internal/genstore/archive_capacity_test.go`; `archive_prune_test.go` | Delete and mint preflight reserve emergency deletion headroom; explicit prune is audited. |
| S13-S14 | implemented | Ambiguous publications are quarantined or preserved, and quarantine has no authority | `internal/genstore/reconcile.go`; `quarantine.go` | `internal/genstore/reconcile_test.go::TestReconcileStoreRootAuthenticatesSelectionAndQuarantinesAttempt`; `internal/genstore/quarantine_test.go::TestClassifyQuarantineCandidateDoesNotRequireTermKey`; `::TestPruneQuarantinedCannotDeleteActiveGeneration` | Unknown-term ciphertext remains quarantinable after a root rollback across changepass. Unsafe candidates stay in place and block progress. |

## Machine-Checkable Coverage

### Atomic store-root module

[formal/store_root_commit.tla](formal/store_root_commit.tla) models publication,
outgoing sealing, exact-input pinning, the single root rename, durability, and
non-authoritative reconciliation quarantine. The positive configuration checks
14 distinct states at depth 9 with no counterexample. The expected-failure
[formal/store_root_commit_negative.cfg](formal/store_root_commit_negative.cfg)
disables exact outgoing-seal verification and must violate
`S5_NoUnpinnedPromotion` after 13 distinct states at depth 7.

| Invariant | TLA+ predicate |
|---|---|
| S1-S2 (one atomic authority selection) | `S1_OneSelectedAuthority`, `S2_AtomicCutover` |
| S3 (only durable publication can be selected) | `S3_PublishedCompleteness` |
| S4 (new generation uses the new term) | `S4_NewTermCurrentState` |
| S5 (only exact pinned input is promoted) | `S5_NoUnpinnedPromotion` |
| S13-S14 (quarantine is non-destructive and non-authoritative) | `S13_NonDestructiveAmbiguity`, `S14_QuarantineNonAuthority` |

The negative control is a first-class expected-failure run in
`docs/formal/metrics.json`, so CI fails if the mutation stops producing the
named counterexample or if the positive model admits it.

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

### Approval coordinator module

[formal/approval_coordinator.tla](formal/approval_coordinator.tla) models requests interleaving over one delivery turn with operator decisions, timeout, cancellation, disconnect, and client displacement. `Safety` checks AP4, AP5, AP6, and AP7. AP6 is `AP6_FailAllLeavesNoPending`, backed by the sticky `badPendingAfterFailAll` flag updated by both modeled fail-all actions. AP7 separately prevents a displaced client from orphaning a delivered prompt. AP1-AP3 hold by construction. `LiveSpec` retains weak fairness for delivery and timeout and checks `Progress`.

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
| Fail-all yields no signed output, end to end | `FailAllProducesNoSignedOutput` |
| Hard deny dominates the coordinator (I9) | `HardDenyDominatesCoordinator` |
| Policy outcome binds signing output | `PolicyOutcomeBindsOutput` |

Validated by mutation test: mapping the `Failed` (fail-all) outcome to `approve`
produces a counterexample where a fail-all'd review-class request signs.

### Session ownership module

[formal/session_ownership.tla](formal/session_ownership.tla) (see
[FORMAL_TLA_SESSION_OWNERSHIP_MODEL.md](FORMAL_TLA_SESSION_OWNERSHIP_MODEL.md))
models process-wide admin-session ownership: authentication unlocks the product
runtime before ownership is established, so the invariant is that no failure
between unlock and promotion strands the product runtime unlocked with no live
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
- RL1 (reload order) remains a Go-level contract without a TLA+
  representation. The reason-independent fail-all property is machine-checked
  as AP6 in `approval_coordinator.tla` and through
  `FailAllProducesNoSignedOutput` in `approval_composition.tla`.
- All of S1-S13 (signing authority) — **by decision, not omission** (2026-07-03
  review): S1/S3-S5/S8/S11/S12 are structural or definitional (a module would
  verify its own encoding), S2/S6/S7/S9 are single-guard checks whose only
  nontrivial content (cryptography, cross-path enforcement) is exactly what
  TLC must abstract away, and S10's snapshot-copy design holds by
  construction (pinned by `TestPlannerUsesSingleRuntimeSnapshot`). S13
  (filename↔address binding with collision fallback) is the sole
  revisit-candidate, and only if the key-file scan ever gains a
  winner-picking rule instead of skip-and-warn.
- A2-A5, A9-A13, A15 (guarded signing: component-sign-time checks, endpoint
  routing, client shape checks, identity mode). A1/A6/A7/A8/A14 are
  machine-checked in `guarded_assembly.tla`. The separate bounded-sentry
  planning and assembly path is machine-checked in `bounded_sentry.tla`.
- AP1-AP3 (approval coordinator) are modeled by construction rather than as
  predicates; AP4-AP7 are machine-checked in `approval_coordinator.tla`.

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
