// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package protocol

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestMessageTypeConstantsAreUnique(t *testing.T) {
	types := []string{
		MsgTypeAuthRequired,
		MsgTypeAuth,
		MsgTypeAuthResult,
		MsgTypeUnlock,
		MsgTypeUnlockResult,
		MsgTypeLockIdentity,
		MsgTypeLockIdentityResult,
		MsgTypeInitializeStore,
		MsgTypeInitializeStoreResult,
		MsgTypeChangeStorePass,
		MsgTypeChangeStorePassResult,
		MsgTypeBackup,
		MsgTypeBackupResult,
		MsgTypeListBackups,
		MsgTypeBackupsList,
		MsgTypeDeleteBackup,
		MsgTypeDeleteBackupResult,
		MsgTypePreviewRestore,
		MsgTypeRestorePreview,
		MsgTypeRestoreBackup,
		MsgTypeRestoreBackupResult,
		MsgTypeSignRequest,
		MsgTypeSignRequestCanceled,
		MsgTypeSignResponse,
		MsgTypeStatus,
		MsgTypeError,
		MsgTypeTokenProvisioningRequest,
		MsgTypeTokenProvisioningResponse,
		MsgTypeRevokeToken,
		MsgTypeRevokeTokenResult,
		MsgTypeListKeys,
		MsgTypeKeysList,
		MsgTypeGenerateKey,
		MsgTypeGenerateResult,
		MsgTypeDeleteKey,
		MsgTypeDeleteResult,
		MsgTypeExportKey,
		MsgTypeExportResult,
		MsgTypeImportKey,
		MsgTypeImportResult,
		MsgTypeGetKeyDetails,
		MsgTypeKeyDetails,
		MsgTypeListLibraryTemplates,
		MsgTypeLibraryTemplates,
		MsgTypeInstallLibraryTemplate,
		MsgTypeInstallLibraryTemplateResult,
		MsgTypeListInstalledTemplates,
		MsgTypeInstalledTemplates,
		MsgTypeShowInstalledTemplate,
		MsgTypeShowInstalledTemplateResult,
		MsgTypeShowLibraryTemplate,
		MsgTypeShowLibraryTemplateResult,
		MsgTypeImportInstalledTemplate,
		MsgTypeImportInstalledTemplateResult,
		MsgTypeRemoveInstalledTemplate,
		MsgTypeRemoveInstalledTemplateResult,
		MsgTypeActivateKeyType,
		MsgTypeActivateKeyTypeResult,
		MsgTypeDeactivateKeyType,
		MsgTypeDeactivateKeyTypeResult,
		MsgTypeListKeyTypes,
		MsgTypeKeyTypes,
		MsgTypeKeysChanged,
		MsgTypeSignerLocked,
		MsgTypeGetAdminSettings,
		MsgTypeAdminSettings,
		MsgTypeUpdateAdminSetting,
		MsgTypeUpdateAdminSettingResult,
		MsgTypeGetPolicySettings,
		MsgTypePolicySettings,
		MsgTypeGetPolicySnapshot,
		MsgTypePolicySnapshot,
		MsgTypeReplacePolicy,
		MsgTypeReplacePolicyResult,
		MsgTypeValidatePolicy,
		MsgTypeValidatePolicyResult,
		MsgTypeUpdatePolicySetting,
		MsgTypeUpdatePolicySettingResult,
		MsgTypeUpdatePolicyASAAmounts,
		MsgTypeUpdatePolicyASAResult,
		MsgTypeSearchASAMetadata,
		MsgTypeASAMetadataResults,
		MsgTypeResolveASAMetadata,
		MsgTypeASAMetadataResult,
		MsgTypeClientExists,
		MsgTypeDisplaceConfirm,
		MsgTypeDisplaced,
	}

	seen := make(map[string]struct{}, len(types))
	for _, msgType := range types {
		if _, ok := seen[msgType]; ok {
			t.Fatalf("duplicate message type constant: %q", msgType)
		}
		seen[msgType] = struct{}{}
	}
}

func TestCoreMessageJSONShapes(t *testing.T) {
	tests := []struct {
		name    string
		msg     any
		wantMap map[string]any
	}{
		{
			name: "sign_request",
			msg: SignRequestMessage{
				BaseMessage: BaseMessage{Type: MsgTypeSignRequest, ID: "sign-1"},
				Address:     "ADDR1",
				TxnSender:   "ADDR2",
				Description: "pay 1 algo",
				Timestamp:   1700000000,
				FirstValid:  123,
				LastValid:   456,
				Violations: []PolicyViolation{{
					Field:    "RekeyTo",
					Value:    "ADDR3",
					Severity: "critical",
					Message:  "rekey detected",
				}},
			},
			wantMap: map[string]any{
				"type":        MsgTypeSignRequest,
				"id":          "sign-1",
				"address":     "ADDR1",
				"txn_sender":  "ADDR2",
				"description": "pay 1 algo",
				"timestamp":   float64(1700000000),
				"first_valid": float64(123),
				"last_valid":  float64(456),
				"violations": []any{
					map[string]any{
						"field":    "RekeyTo",
						"value":    "ADDR3",
						"severity": "critical",
						"message":  "rekey detected",
					},
				},
			},
		},
		{
			name: "sign_request_canceled",
			msg: SignRequestCanceledMessage{
				BaseMessage: BaseMessage{Type: MsgTypeSignRequestCanceled, ID: "sign-1"},
				Reason:      "client_canceled",
			},
			wantMap: map[string]any{
				"type":   MsgTypeSignRequestCanceled,
				"id":     "sign-1",
				"reason": "client_canceled",
			},
		},
		{
			name: "token_provisioning_request",
			msg: TokenProvisioningRequestMessage{
				BaseMessage:    BaseMessage{Type: MsgTypeTokenProvisioningRequest, ID: "token-1"},
				IdentityID:     "default",
				SSHFingerprint: "SHA256:abc",
				RemoteAddr:     "127.0.0.1:1234",
				Timestamp:      1700000001,
			},
			wantMap: map[string]any{
				"type":            MsgTypeTokenProvisioningRequest,
				"id":              "token-1",
				"identity_id":     "default",
				"ssh_fingerprint": "SHA256:abc",
				"remote_addr":     "127.0.0.1:1234",
				"timestamp":       float64(1700000001),
			},
		},
		{
			name: "admin_settings",
			msg: AdminSettingsMessage{
				BaseMessage:          BaseMessage{Type: MsgTypeAdminSettings, ID: "settings-1"},
				UserAutoApprove:      true,
				LockOnDisconnect:     false,
				PassphraseTimeout:    "15m",
				PassphraseMethod:     "ipc",
				NodeRole:             "signer",
				SSHEnabled:           true,
				SSHListenAddress:     "127.0.0.1",
				SSHPort:              1127,
				SSHFingerprint:       "SHA256:host",
				SSHClients:           2,
				SignerPort:           11270,
				TEALCompileNet:       "testnet",
				EndpointAdvertiseURL: "ssh://signer.example:1127",
				EndpointDisplayURL:   "ssh://192.168.1.42:1127",
				Theme:                "dark",
			},
			wantMap: map[string]any{
				"type":                   MsgTypeAdminSettings,
				"id":                     "settings-1",
				"user_auto_approve":      true,
				"lock_on_disconnect":     false,
				"passphrase_timeout":     "15m",
				"passphrase_method":      "ipc",
				"node_role":              "signer",
				"ssh_enabled":            true,
				"ssh_listen_address":     "127.0.0.1",
				"ssh_port":               float64(1127),
				"ssh_fingerprint":        "SHA256:host",
				"ssh_clients":            float64(2),
				"signer_port":            float64(11270),
				"teal_compile_network":   "testnet",
				"endpoint_advertise_url": "ssh://signer.example:1127",
				"endpoint_display_url":   "ssh://192.168.1.42:1127",
				"theme":                  "dark",
			},
		},
		{
			name: "keys_changed",
			msg: KeysChangedMessage{
				BaseMessage: BaseMessage{Type: MsgTypeKeysChanged, ID: "keys-1"},
				KeyCount:    7,
			},
			wantMap: map[string]any{
				"type":      MsgTypeKeysChanged,
				"id":        "keys-1",
				"key_count": float64(7),
			},
		},
		{
			name: "signer_locked",
			msg: SignerLockedMessage{
				BaseMessage: BaseMessage{Type: MsgTypeSignerLocked, ID: "lock-1"},
				Reason:      "manual lock",
			},
			wantMap: map[string]any{
				"type":   MsgTypeSignerLocked,
				"id":     "lock-1",
				"reason": "manual lock",
			},
		},
		{
			name: "auth_result",
			msg: AuthResultMessage{
				BaseMessage: BaseMessage{Type: MsgTypeAuthResult, ID: "auth-1"},
				Success:     false,
				Code:        ErrCodeInvalidPassphrase,
				Error:       "invalid passphrase",
			},
			wantMap: map[string]any{
				"type":    MsgTypeAuthResult,
				"id":      "auth-1",
				"success": false,
				"code":    ErrCodeInvalidPassphrase,
				"error":   "invalid passphrase",
			},
		},
		{
			name: "unlock_result",
			msg: UnlockResultMessage{
				BaseMessage: BaseMessage{Type: MsgTypeUnlockResult, ID: "unlock-1"},
				Success:     true,
				KeyCount:    4,
			},
			wantMap: map[string]any{
				"type":      MsgTypeUnlockResult,
				"id":        "unlock-1",
				"success":   true,
				"key_count": float64(4),
			},
		},
		{
			name: "lock_identity",
			msg: LockIdentityMessage{
				BaseMessage: BaseMessage{Type: MsgTypeLockIdentity, ID: "lock-identity-1"},
				Reason:      "apadmin manual lock",
			},
			wantMap: map[string]any{
				"type":   MsgTypeLockIdentity,
				"id":     "lock-identity-1",
				"reason": "apadmin manual lock",
			},
		},
		{
			name: "lock_identity_result",
			msg: LockIdentityResultMessage{
				BaseMessage: BaseMessage{Type: MsgTypeLockIdentityResult, ID: "lock-identity-1"},
				Success:     false,
				Code:        ErrCodeAuthorizationDenied,
				Error:       "authorization denied",
			},
			wantMap: map[string]any{
				"type":    MsgTypeLockIdentityResult,
				"id":      "lock-identity-1",
				"success": false,
				"code":    ErrCodeAuthorizationDenied,
				"error":   "authorization denied",
			},
		},
		{
			name: "initialize_store",
			msg: InitializeStoreMessage{
				BaseMessage: BaseMessage{Type: MsgTypeInitializeStore, ID: "init-1"},
				Passphrase:  NewSensitiveBytes("new-passphrase"),
			},
			wantMap: map[string]any{
				"type":       MsgTypeInitializeStore,
				"id":         "init-1",
				"passphrase": "new-passphrase",
			},
		},
		{
			name: "initialize_store_result",
			msg: InitializeStoreResultMessage{
				BaseMessage:   BaseMessage{Type: MsgTypeInitializeStoreResult, ID: "init-1"},
				Success:       true,
				MetadataDir:   "/data/identities/default",
				HelperWarning: "helper write failed",
			},
			wantMap: map[string]any{
				"type":           MsgTypeInitializeStoreResult,
				"id":             "init-1",
				"success":        true,
				"metadata_dir":   "/data/identities/default",
				"helper_warning": "helper write failed",
			},
		},
		{
			name: "backup",
			msg: BackupMessage{
				BaseMessage:      BaseMessage{Type: MsgTypeBackup, ID: "backup-1"},
				ExportPassphrase: NewSensitiveBytes("export-passphrase"),
				Addresses:        []string{"ADDR1"},
			},
			wantMap: map[string]any{
				"type":              MsgTypeBackup,
				"id":                "backup-1",
				"export_passphrase": "export-passphrase",
				"addresses":         []any{"ADDR1"},
			},
		},
		{
			name: "backups_list",
			msg: BackupsListMessage{
				BaseMessage: BaseMessage{Type: MsgTypeBackupsList, ID: "backups-1"},
				Backups: []BackupInfo{{
					Path:      "/data/identities/default/backups/backup.tar.gz",
					FileName:  "backup.tar.gz",
					CreatedAt: 1710000000,
					Size:      4096,
				}},
			},
			wantMap: map[string]any{
				"type": MsgTypeBackupsList,
				"id":   "backups-1",
				"backups": []any{
					map[string]any{
						"path":       "/data/identities/default/backups/backup.tar.gz",
						"file_name":  "backup.tar.gz",
						"created_at": float64(1710000000),
						"size":       float64(4096),
					},
				},
			},
		},
		{
			name: "restore_preview",
			msg: RestorePreviewMessage{
				BaseMessage: BaseMessage{Type: MsgTypeRestorePreview, ID: "restore-preview-1"},
				ArchivePath: "/data/identities/default/backups/backup.tar.gz",
				Keys: []RestoreKeyInfo{{
					Address:       "ADDR1",
					KeyType:       "ed25519",
					AlreadyExists: true,
					HasTemplate:   true,
					TemplateType:  "generic",
				}},
				Errors: []RestoreError{{
					Address: "ADDR2",
					Error:   "failed to decrypt backup",
				}},
			},
			wantMap: map[string]any{
				"type":         MsgTypeRestorePreview,
				"id":           "restore-preview-1",
				"archive_path": "/data/identities/default/backups/backup.tar.gz",
				"keys": []any{
					map[string]any{
						"address":        "ADDR1",
						"key_type":       "ed25519",
						"already_exists": true,
						"has_template":   true,
						"template_type":  "generic",
					},
				},
				"errors": []any{
					map[string]any{
						"address": "ADDR2",
						"error":   "failed to decrypt backup",
					},
				},
			},
		},
		{
			name: "restore_backup_result",
			msg: RestoreBackupResultMessage{
				BaseMessage: BaseMessage{Type: MsgTypeRestoreBackupResult, ID: "restore-1"},
				ArchivePath: "/data/identities/default/backups/backup.tar.gz",
				Success:     true,
				Restored: []RestoreKeyInfo{{
					Address: "ADDR1",
					KeyType: "ed25519",
				}},
				Warnings: []RestoreWarning{{
					Address: "ADDR1",
					KeyType: "aplane.timed-whitelist.v1",
					Warning: "skipped bundled template for aplane.timed-whitelist.v1: backup template conflicts with existing keystore definition",
				}},
				KeyCount: 5,
			},
			wantMap: map[string]any{
				"type":         MsgTypeRestoreBackupResult,
				"id":           "restore-1",
				"archive_path": "/data/identities/default/backups/backup.tar.gz",
				"success":      true,
				"restored": []any{
					map[string]any{
						"address":  "ADDR1",
						"key_type": "ed25519",
					},
				},
				"warnings": []any{
					map[string]any{
						"address":  "ADDR1",
						"key_type": "aplane.timed-whitelist.v1",
						"warning":  "skipped bundled template for aplane.timed-whitelist.v1: backup template conflicts with existing keystore definition",
					},
				},
				"key_count": float64(5),
			},
		},
		{
			name: "library_templates",
			msg: LibraryTemplatesMessage{
				BaseMessage: BaseMessage{Type: MsgTypeLibraryTemplates, ID: "tmpl-list-1"},
				Templates: []LibraryTemplateInfo{{
					KeyType:      "aplane.timed-whitelist.v1",
					TemplateType: "generic",
					DisplayName:  "Timed Whitelist",
					FileName:     "aplane.timed-whitelist.v1.yaml",
					Parameters: []TemplateParamInfo{{
						Name:      "unlock_round",
						Label:     "Unlock Round",
						Type:      "uint64",
						Required:  true,
						Min:       uint64Ptr(1),
						MaxLength: 20,
					}},
					Installed: true,
				}},
			},
			wantMap: map[string]any{
				"type": MsgTypeLibraryTemplates,
				"id":   "tmpl-list-1",
				"templates": []any{
					map[string]any{
						"key_type":      "aplane.timed-whitelist.v1",
						"template_type": "generic",
						"display_name":  "Timed Whitelist",
						"file_name":     "aplane.timed-whitelist.v1.yaml",
						"parameters": []any{
							map[string]any{
								"name":       "unlock_round",
								"label":      "Unlock Round",
								"type":       "uint64",
								"required":   true,
								"min":        float64(1),
								"max_length": float64(20),
							},
						},
						"installed": true,
					},
				},
			},
		},
		{
			name: "install_library_template_result",
			msg: InstallLibraryTemplateResultMessage{
				BaseMessage:   BaseMessage{Type: MsgTypeInstallLibraryTemplateResult, ID: "tmpl-install-1"},
				Success:       true,
				KeyType:       "aplane.timed-whitelist.v1",
				TemplateType:  "generic",
				AlreadyExists: true,
			},
			wantMap: map[string]any{
				"type":           MsgTypeInstallLibraryTemplateResult,
				"id":             "tmpl-install-1",
				"success":        true,
				"key_type":       "aplane.timed-whitelist.v1",
				"template_type":  "generic",
				"already_exists": true,
			},
		},
		{
			name: "installed_templates",
			msg: InstalledTemplatesMessage{
				BaseMessage: BaseMessage{Type: MsgTypeInstalledTemplates, ID: "installed-list-1"},
				Templates: []InstalledTemplateInfo{{
					KeyType:      "escrow-v1",
					TemplateType: "generic",
					Size:         123,
					Enabled:      true,
				}},
			},
			wantMap: map[string]any{
				"type": MsgTypeInstalledTemplates,
				"id":   "installed-list-1",
				"templates": []any{
					map[string]any{
						"key_type":      "escrow-v1",
						"template_type": "generic",
						"size":          float64(123),
						"enabled":       true,
					},
				},
			},
		},
		{
			name: "show_installed_template_result",
			msg: ShowInstalledTemplateResultMessage{
				BaseMessage:  BaseMessage{Type: MsgTypeShowInstalledTemplateResult, ID: "show-installed-1"},
				Success:      true,
				KeyType:      "escrow-v1",
				TemplateType: "generic",
				TemplateYAML: SensitiveBytes("schema_version: 1\n"),
			},
			wantMap: map[string]any{
				"type":          MsgTypeShowInstalledTemplateResult,
				"id":            "show-installed-1",
				"success":       true,
				"key_type":      "escrow-v1",
				"template_type": "generic",
				"template_yaml": "schema_version: 1\n",
			},
		},
		{
			name: "show_library_template_result",
			msg: ShowLibraryTemplateResultMessage{
				BaseMessage:   BaseMessage{Type: MsgTypeShowLibraryTemplateResult, ID: "show-library-1"},
				Success:       true,
				KeyType:       "escrow-v1",
				TemplateType:  "generic",
				SourcePath:    "/tmp/aplane/library/templates/escrow.yaml",
				SourceSHA256:  "0123456789abcdef",
				SourceModTime: 1778600000,
				TemplateYAML:  SensitiveBytes("schema_version: 1\n"),
			},
			wantMap: map[string]any{
				"type":          MsgTypeShowLibraryTemplateResult,
				"id":            "show-library-1",
				"success":       true,
				"key_type":      "escrow-v1",
				"template_type": "generic",
				"source_path":   "/tmp/aplane/library/templates/escrow.yaml",
				"source_sha256": "0123456789abcdef",
				"source_mtime":  float64(1778600000),
				"template_yaml": "schema_version: 1\n",
			},
		},
		{
			name: "import_installed_template_result",
			msg: ImportInstalledTemplateResultMessage{
				BaseMessage:   BaseMessage{Type: MsgTypeImportInstalledTemplateResult, ID: "import-installed-1"},
				Success:       true,
				KeyType:       "escrow-v1",
				TemplateType:  "generic",
				AlreadyExists: true,
			},
			wantMap: map[string]any{
				"type":           MsgTypeImportInstalledTemplateResult,
				"id":             "import-installed-1",
				"success":        true,
				"key_type":       "escrow-v1",
				"template_type":  "generic",
				"already_exists": true,
			},
		},
		{
			name: "remove_installed_template_result",
			msg: RemoveInstalledTemplateResultMessage{
				BaseMessage:  BaseMessage{Type: MsgTypeRemoveInstalledTemplateResult, ID: "remove-installed-1"},
				Success:      true,
				KeyType:      "escrow-v1",
				TemplateType: "generic",
				Removed:      true,
			},
			wantMap: map[string]any{
				"type":          MsgTypeRemoveInstalledTemplateResult,
				"id":            "remove-installed-1",
				"success":       true,
				"key_type":      "escrow-v1",
				"template_type": "generic",
				"removed":       true,
			},
		},
		{
			name: "activate_key_type_result",
			msg: ActivateKeyTypeResultMessage{
				BaseMessage:   BaseMessage{Type: MsgTypeActivateKeyTypeResult, ID: "activate-keytype-1"},
				Success:       true,
				KeyType:       "aplane.falcon1024_ed25519.v1",
				AlreadyExists: true,
			},
			wantMap: map[string]any{
				"type":           MsgTypeActivateKeyTypeResult,
				"id":             "activate-keytype-1",
				"success":        true,
				"key_type":       "aplane.falcon1024_ed25519.v1",
				"already_exists": true,
			},
		},
		{
			name: "deactivate_key_type_result",
			msg: DeactivateKeyTypeResultMessage{
				BaseMessage: BaseMessage{Type: MsgTypeDeactivateKeyTypeResult, ID: "deactivate-keytype-1"},
				Success:     true,
				KeyType:     "aplane.falcon1024_ed25519.v1",
				Removed:     true,
			},
			wantMap: map[string]any{
				"type":     MsgTypeDeactivateKeyTypeResult,
				"id":       "deactivate-keytype-1",
				"success":  true,
				"key_type": "aplane.falcon1024_ed25519.v1",
				"removed":  true,
			},
		},
		{
			name: "key_types",
			msg: KeyTypesMessage{
				BaseMessage: BaseMessage{Type: MsgTypeKeyTypes, ID: "keytypes-1"},
				KeyTypes: []KeyTypeInfo{{
					KeyType:           "aplane.timed-whitelist.v1",
					Family:            "timed-whitelist",
					DisplayName:       "Timed Whitelist",
					Description:       "Lock until a round",
					RequiresLogicSig:  true,
					MnemonicWordCount: 0,
					CreationParams: []TemplateParamInfo{{
						Name:      "unlock_round",
						Label:     "Unlock Round",
						Type:      "uint64",
						Required:  true,
						Min:       uint64Ptr(1),
						MaxLength: 20,
					}},
				}},
			},
			wantMap: map[string]any{
				"type": MsgTypeKeyTypes,
				"id":   "keytypes-1",
				"key_types": []any{
					map[string]any{
						"key_type":            "aplane.timed-whitelist.v1",
						"family":              "timed-whitelist",
						"display_name":        "Timed Whitelist",
						"description":         "Lock until a round",
						"requires_logicsig":   true,
						"mnemonic_word_count": float64(0),
						"mnemonic_import":     false,
						"mnemonic_scheme":     "",
						"creation_params": []any{
							map[string]any{
								"name":       "unlock_round",
								"label":      "Unlock Round",
								"type":       "uint64",
								"required":   true,
								"min":        float64(1),
								"max_length": float64(20),
							},
						},
						"runtime_args": nil,
					},
				},
			},
		},
		{
			name: "keys_list",
			msg: KeysListMessage{
				BaseMessage: BaseMessage{Type: MsgTypeKeysList, ID: "keys-1"},
				Keys: []KeyInfo{{
					Address:                  "ADDR1",
					KeyType:                  "ed25519",
					Name:                     "treasury",
					TemplateProvenanceStatus: "conflict",
					TemplateProvenanceNote:   "changed",
				}},
			},
			wantMap: map[string]any{
				"type": MsgTypeKeysList,
				"id":   "keys-1",
				"keys": []any{
					map[string]any{
						"address":                    "ADDR1",
						"key_type":                   "ed25519",
						"name":                       "treasury",
						"template_provenance_status": "conflict",
						"template_provenance_note":   "changed",
					},
				},
			},
		},
		{
			name: "update_admin_setting_result",
			msg: UpdateAdminSettingResultMessage{
				BaseMessage: BaseMessage{Type: MsgTypeUpdateAdminSettingResult, ID: "setting-1"},
				Success:     true,
				Key:         "lock_on_disconnect",
				Value:       "false",
			},
			wantMap: map[string]any{
				"type":    MsgTypeUpdateAdminSettingResult,
				"id":      "setting-1",
				"success": true,
				"key":     "lock_on_disconnect",
				"value":   "false",
			},
		},
		{
			name: "policy_settings",
			msg: PolicySettingsMessage{
				BaseMessage:                 BaseMessage{Type: MsgTypePolicySettings, ID: "policy-1"},
				RejectForeignRekey:          true,
				RejectCloseRemainder:        true,
				RejectAssetClose:            false,
				RejectClawback:              false,
				AlwaysReviewWarnings:        true,
				AutoApproveSelfNoOpTransfer: true,
				MaxFeeMicroAlgos:            "1000",
				ReviewAlgoPayments:          map[string]string{"testnet": "5", "voi_mainnet": "1"},
				MaxAlgoPayments:             map[string]string{"testnet": "10.5", "voi_mainnet": "2"},
				PolicyNetworks:              []string{"testnet", "voi_mainnet"},
				ReviewASAAmounts: map[string]string{
					"testnet":     "123:5",
					"voi_mainnet": "42:1",
				},
				MaxASAAmounts: map[string]string{
					"mainnet":     "1:2",
					"testnet":     "123:45,456:78",
					"voi_mainnet": "42:7",
				},
				PolicyASAMetadata: map[string][]ASAMetadataInfo{
					"testnet": {{
						AssetID:  123,
						Name:     "USD Coin",
						UnitName: "USDC",
						Decimals: 6,
						Source:   "cache",
					}},
				},
				MaxASAAmountsMainnet: "1:2",
				MaxASAAmountsTestnet: "123:45,456:78",
			},
			wantMap: map[string]any{
				"type":                            MsgTypePolicySettings,
				"id":                              "policy-1",
				"reject_foreign_rekey":            true,
				"reject_close_remainder":          true,
				"reject_asset_close":              false,
				"reject_clawback":                 false,
				"always_review_warnings":          true,
				"auto_approve_self_noop_transfer": true,
				"max_fee_microalgos":              "1000",
				"review_algo_payments":            map[string]any{"testnet": "5", "voi_mainnet": "1"},
				"max_algo_payments":               map[string]any{"testnet": "10.5", "voi_mainnet": "2"},
				"policy_networks":                 []any{"testnet", "voi_mainnet"},
				"review_asa_amounts":              map[string]any{"testnet": "123:5", "voi_mainnet": "42:1"},
				"max_asa_amounts":                 map[string]any{"mainnet": "1:2", "testnet": "123:45,456:78", "voi_mainnet": "42:7"},
				"policy_asa_metadata":             map[string]any{"testnet": []any{map[string]any{"asset_id": float64(123), "name": "USD Coin", "unit_name": "USDC", "decimals": float64(6), "source": "cache"}}},
				"max_asa_amounts_mainnet":         "1:2",
				"max_asa_amounts_testnet":         "123:45,456:78",
			},
		},
		{
			name: "update_policy_setting_result",
			msg: UpdatePolicySettingResultMessage{
				BaseMessage: BaseMessage{Type: MsgTypeUpdatePolicySettingResult, ID: "policy-set-1"},
				Success:     true,
				Key:         "reject_foreign_rekey",
				Value:       "false",
			},
			wantMap: map[string]any{
				"type":    MsgTypeUpdatePolicySettingResult,
				"id":      "policy-set-1",
				"success": true,
				"key":     "reject_foreign_rekey",
				"value":   "false",
			},
		},
		{
			name: "get_policy_snapshot",
			msg: GetPolicySnapshotMessage{
				BaseMessage: BaseMessage{Type: MsgTypeGetPolicySnapshot, ID: "policy-snapshot-1"},
				Target:      "sentry",
			},
			wantMap: map[string]any{
				"type":   MsgTypeGetPolicySnapshot,
				"id":     "policy-snapshot-1",
				"target": "sentry",
			},
		},
		{
			name: "policy_snapshot",
			msg: PolicySnapshotMessage{
				BaseMessage:  BaseMessage{Type: MsgTypePolicySnapshot, ID: "policy-snapshot-1"},
				Success:      true,
				Target:       "sentry",
				IdentityID:   "default",
				PolicyYAML:   "reject_foreign_rekey: true\n",
				PolicySHA256: "abc123",
				Canonical:    true,
			},
			wantMap: map[string]any{
				"type":          MsgTypePolicySnapshot,
				"id":            "policy-snapshot-1",
				"success":       true,
				"target":        "sentry",
				"identity_id":   "default",
				"policy_yaml":   "reject_foreign_rekey: true\n",
				"policy_sha256": "abc123",
				"canonical":     true,
			},
		},
		{
			name: "replace_policy",
			msg: ReplacePolicyMessage{
				BaseMessage:           BaseMessage{Type: MsgTypeReplacePolicy, ID: "policy-replace-1"},
				Target:                "sentry",
				PolicyYAML:            "reject_foreign_rekey: false\n",
				ExpectedCurrentSHA256: "abc123",
			},
			wantMap: map[string]any{
				"type":                    MsgTypeReplacePolicy,
				"id":                      "policy-replace-1",
				"target":                  "sentry",
				"policy_yaml":             "reject_foreign_rekey: false\n",
				"expected_current_sha256": "abc123",
			},
		},
		{
			name: "replace_policy_result",
			msg: ReplacePolicyResultMessage{
				BaseMessage:  BaseMessage{Type: MsgTypeReplacePolicyResult, ID: "policy-replace-1"},
				Success:      true,
				Target:       "sentry",
				IdentityID:   "default",
				PolicyYAML:   "reject_foreign_rekey: false\n",
				PolicySHA256: "def456",
				Canonical:    true,
			},
			wantMap: map[string]any{
				"type":          MsgTypeReplacePolicyResult,
				"id":            "policy-replace-1",
				"success":       true,
				"target":        "sentry",
				"identity_id":   "default",
				"policy_yaml":   "reject_foreign_rekey: false\n",
				"policy_sha256": "def456",
				"canonical":     true,
			},
		},
		{
			name: "validate_policy",
			msg: ValidatePolicyMessage{
				BaseMessage: BaseMessage{Type: MsgTypeValidatePolicy, ID: "policy-validate-1"},
				Target:      "sentry",
				PolicyYAML:  "sentry:\n  transfer_policy:\n    schema_version: 1\n",
			},
			wantMap: map[string]any{
				"type":        MsgTypeValidatePolicy,
				"id":          "policy-validate-1",
				"target":      "sentry",
				"policy_yaml": "sentry:\n  transfer_policy:\n    schema_version: 1\n",
			},
		},
		{
			name: "validate_policy_result",
			msg: ValidatePolicyResultMessage{
				BaseMessage: BaseMessage{Type: MsgTypeValidatePolicyResult, ID: "policy-validate-1"},
				Success:     true,
				Target:      "sentry",
				IdentityID:  "default",
			},
			wantMap: map[string]any{
				"type":        MsgTypeValidatePolicyResult,
				"id":          "policy-validate-1",
				"success":     true,
				"target":      "sentry",
				"identity_id": "default",
			},
		},
		{
			name: "update_policy_asa_amounts",
			msg: UpdatePolicyASAAmountsMessage{
				BaseMessage: BaseMessage{Type: MsgTypeUpdatePolicyASAAmounts, ID: "policy-asa-1"},
				ReviewASAAmounts: map[string]string{
					"testnet":     "123:5",
					"voi_mainnet": "42:1",
				},
				MaxASAAmounts: map[string]string{
					"mainnet":     "1:2",
					"testnet":     "123:45,456:78",
					"voi_mainnet": "42:7",
				},
				ReviewAlgoPayments: map[string]string{
					"testnet":     "1",
					"voi_mainnet": "2",
				},
				MaxAlgoPayments: map[string]string{
					"mainnet":     "1",
					"testnet":     "2",
					"voi_mainnet": "3",
				},
				Mainnet: "1:2",
				Testnet: "123:45,456:78",
			},
			wantMap: map[string]any{
				"type":                 MsgTypeUpdatePolicyASAAmounts,
				"id":                   "policy-asa-1",
				"review_asa_amounts":   map[string]any{"testnet": "123:5", "voi_mainnet": "42:1"},
				"max_asa_amounts":      map[string]any{"mainnet": "1:2", "testnet": "123:45,456:78", "voi_mainnet": "42:7"},
				"review_algo_payments": map[string]any{"testnet": "1", "voi_mainnet": "2"},
				"max_algo_payments":    map[string]any{"mainnet": "1", "testnet": "2", "voi_mainnet": "3"},
				"mainnet":              "1:2",
				"testnet":              "123:45,456:78",
			},
		},
		{
			name: "update_policy_asa_result",
			msg: UpdatePolicyASAAmountsResultMessage{
				BaseMessage: BaseMessage{Type: MsgTypeUpdatePolicyASAResult, ID: "policy-asa-1"},
				Success:     true,
			},
			wantMap: map[string]any{
				"type":    MsgTypeUpdatePolicyASAResult,
				"id":      "policy-asa-1",
				"success": true,
			},
		},
		{
			name: "search_asa_metadata",
			msg: SearchASAMetadataMessage{
				BaseMessage: BaseMessage{Type: MsgTypeSearchASAMetadata, ID: "asa-search-1"},
				Network:     "testnet",
				Query:       "USDC",
			},
			wantMap: map[string]any{
				"type":    MsgTypeSearchASAMetadata,
				"id":      "asa-search-1",
				"network": "testnet",
				"query":   "USDC",
			},
		},
		{
			name: "asa_metadata_results",
			msg: ASAMetadataResultsMessage{
				BaseMessage: BaseMessage{Type: MsgTypeASAMetadataResults, ID: "asa-search-1"},
				Network:     "testnet",
				Query:       "USDC",
				Results: []ASAMetadataInfo{{
					AssetID:  10458941,
					Name:     "USD Coin",
					UnitName: "USDC",
					Decimals: 6,
					Source:   "cache",
				}},
			},
			wantMap: map[string]any{
				"type":    MsgTypeASAMetadataResults,
				"id":      "asa-search-1",
				"network": "testnet",
				"query":   "USDC",
				"results": []any{
					map[string]any{
						"asset_id":  float64(10458941),
						"name":      "USD Coin",
						"unit_name": "USDC",
						"decimals":  float64(6),
						"source":    "cache",
					},
				},
			},
		},
		{
			name: "resolve_asa_metadata",
			msg: ResolveASAMetadataMessage{
				BaseMessage: BaseMessage{Type: MsgTypeResolveASAMetadata, ID: "asa-resolve-1"},
				Network:     "testnet",
				AssetID:     10458941,
			},
			wantMap: map[string]any{
				"type":     MsgTypeResolveASAMetadata,
				"id":       "asa-resolve-1",
				"network":  "testnet",
				"asset_id": float64(10458941),
			},
		},
		{
			name: "asa_metadata_result",
			msg: ASAMetadataResultMessage{
				BaseMessage: BaseMessage{Type: MsgTypeASAMetadataResult, ID: "asa-resolve-1"},
				Network:     "testnet",
				Asset: &ASAMetadataInfo{
					AssetID:  10458941,
					Name:     "USD Coin",
					UnitName: "USDC",
					Decimals: 6,
					Source:   "cache",
				},
			},
			wantMap: map[string]any{
				"type":    MsgTypeASAMetadataResult,
				"id":      "asa-resolve-1",
				"network": "testnet",
				"asset": map[string]any{
					"asset_id":  float64(10458941),
					"name":      "USD Coin",
					"unit_name": "USDC",
					"decimals":  float64(6),
					"source":    "cache",
				},
			},
		},
		{
			name: "client_exists",
			msg: ClientExistsMessage{
				BaseMessage: BaseMessage{Type: MsgTypeClientExists, ID: "client-1"},
			},
			wantMap: map[string]any{
				"type": MsgTypeClientExists,
				"id":   "client-1",
			},
		},
		{
			name: "displace_confirm",
			msg: DisplaceConfirmMessage{
				BaseMessage: BaseMessage{Type: MsgTypeDisplaceConfirm, ID: "client-1"},
			},
			wantMap: map[string]any{
				"type": MsgTypeDisplaceConfirm,
				"id":   "client-1",
			},
		},
		{
			name: "displaced",
			msg: DisplacedMessage{
				BaseMessage: BaseMessage{Type: MsgTypeDisplaced, ID: "client-2"},
				Reason:      "replaced by new admin session",
			},
			wantMap: map[string]any{
				"type":   MsgTypeDisplaced,
				"id":     "client-2",
				"reason": "replaced by new admin session",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := MarshalAdminMessage(tt.msg)
			if err != nil {
				t.Fatalf("Marshal() error = %v", err)
			}
			var got map[string]any
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("Unmarshal() error = %v", err)
			}
			if msgType, _ := tt.wantMap["type"].(string); msgType != "" {
				if kind, ok := InferMessageKind(msgType); ok {
					tt.wantMap["kind"] = string(kind)
				}
			}
			if !reflect.DeepEqual(got, tt.wantMap) {
				t.Fatalf("JSON shape mismatch\n got: %#v\nwant: %#v", got, tt.wantMap)
			}
		})
	}
}

func uint64Ptr(v uint64) *uint64 {
	return &v
}

func TestSensitiveBytesMarshalUnmarshalAndZero(t *testing.T) {
	backupData := []byte(`{"kind":"request","type":"backup","id":"backup-1","export_passphrase":"backup-secret"}`)
	var backupMsg BackupMessage
	if err := json.Unmarshal(backupData, &backupMsg); err != nil {
		t.Fatalf("Unmarshal(backup) error = %v", err)
	}
	if got := string(backupMsg.ExportPassphrase); got != "backup-secret" {
		t.Fatalf("backup ExportPassphrase = %q, want backup-secret", got)
	}
	backupMsg.ExportPassphrase.Zero()
	if string(backupMsg.ExportPassphrase) == "backup-secret" {
		t.Fatal("backup Zero() left passphrase contents intact")
	}

	data := []byte(`{"kind":"request","type":"preview_restore","id":"preview-1","archive_path":"backup.tar.gz","export_passphrase":"secret"}`)
	var msg PreviewRestoreMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got := string(msg.ExportPassphrase); got != "secret" {
		t.Fatalf("ExportPassphrase = %q, want secret", got)
	}

	clone := msg.ExportPassphrase.Clone()
	if string(clone) != "secret" {
		t.Fatalf("Clone() = %q, want secret", string(clone))
	}
	msg.ExportPassphrase.Zero()
	if string(msg.ExportPassphrase) == "secret" {
		t.Fatal("Zero() left passphrase contents intact")
	}
	if string(clone) != "secret" {
		t.Fatalf("Zero() mutated clone to %q", string(clone))
	}

	escaped := []byte(`{"kind":"request","type":"preview_restore","id":"preview-escaped","archive_path":"backup.tar.gz","export_passphrase":"sec\u0072et\n"}`)
	var escapedMsg PreviewRestoreMessage
	if err := json.Unmarshal(escaped, &escapedMsg); err != nil {
		t.Fatalf("Unmarshal(escaped) error = %v", err)
	}
	if got := string(escapedMsg.ExportPassphrase); got != "secret\n" {
		t.Fatalf("escaped ExportPassphrase = %q, want secret newline", got)
	}

	marshaled, err := MarshalAdminMessage(PreviewRestoreMessage{
		BaseMessage:      BaseMessage{Type: MsgTypePreviewRestore, ID: "preview-2"},
		ArchivePath:      "backup.tar.gz",
		ExportPassphrase: NewSensitiveBytes("secret"),
	})
	if err != nil {
		t.Fatalf("MarshalAdminMessage() error = %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(marshaled, &got); err != nil {
		t.Fatalf("Unmarshal(marshaled) error = %v", err)
	}
	if got["export_passphrase"] != "secret" {
		t.Fatalf("export_passphrase = %#v, want JSON string", got["export_passphrase"])
	}
}

// TestSensitiveBytesUTF8RoundTrip pins the documented contract: SensitiveBytes
// carries UTF-8 text and survives marshal/unmarshal byte-for-byte, including
// multi-byte runes. (Non-UTF-8 binary must not use this type — a JSON string
// would corrupt it to U+FFFD on the peer.)
func TestSensitiveBytesUTF8RoundTrip(t *testing.T) {
	original := NewSensitiveBytes("p\u00e4ss\u00fcw\u00f6rd \u26a0 \U0001f510 \u3053\u3093\u306b\u3061\u306f")
	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	var decoded SensitiveBytes
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if string(decoded) != string(original) {
		t.Fatalf("round-trip = %q, want %q", decoded, original)
	}
}

func TestAdminPassphraseMessagesKeepStringJSONShape(t *testing.T) {
	tests := []struct {
		name       string
		raw        []byte
		msg        any
		fieldNames []string
		values     []string
		check      func(*testing.T, any)
		zero       func(any)
	}{
		{
			name:       "auth",
			raw:        []byte(`{"kind":"request","type":"auth","id":"auth-1","passphrase":"auth-secret","identity_id":"default"}`),
			msg:        &AuthMessage{},
			fieldNames: []string{"passphrase"},
			values:     []string{"auth-secret"},
			check: func(t *testing.T, msg any) {
				t.Helper()
				auth := msg.(*AuthMessage)
				if got := string(auth.Passphrase); got != "auth-secret" {
					t.Fatalf("AuthMessage.Passphrase = %q, want auth-secret", got)
				}
			},
			zero: func(msg any) {
				msg.(*AuthMessage).Passphrase.Zero()
			},
		},
		{
			name:       "unlock",
			raw:        []byte(`{"kind":"request","type":"unlock","id":"unlock-1","passphrase":"unlock-secret"}`),
			msg:        &UnlockMessage{},
			fieldNames: []string{"passphrase"},
			values:     []string{"unlock-secret"},
			check: func(t *testing.T, msg any) {
				t.Helper()
				unlock := msg.(*UnlockMessage)
				if got := string(unlock.Passphrase); got != "unlock-secret" {
					t.Fatalf("UnlockMessage.Passphrase = %q, want unlock-secret", got)
				}
			},
			zero: func(msg any) {
				msg.(*UnlockMessage).Passphrase.Zero()
			},
		},
		{
			name:       "initialize_store",
			raw:        []byte(`{"kind":"request","type":"initialize_store","id":"init-1","passphrase":"init-secret"}`),
			msg:        &InitializeStoreMessage{},
			fieldNames: []string{"passphrase"},
			values:     []string{"init-secret"},
			check: func(t *testing.T, msg any) {
				t.Helper()
				init := msg.(*InitializeStoreMessage)
				if got := string(init.Passphrase); got != "init-secret" {
					t.Fatalf("InitializeStoreMessage.Passphrase = %q, want init-secret", got)
				}
			},
			zero: func(msg any) {
				msg.(*InitializeStoreMessage).Passphrase.Zero()
			},
		},
		{
			name:       "change_store_passphrase",
			raw:        []byte(`{"kind":"request","type":"change_store_passphrase","id":"change-1","current_passphrase":"old-secret","new_passphrase":"new-secret"}`),
			msg:        &ChangeStorePassphraseMessage{},
			fieldNames: []string{"current_passphrase", "new_passphrase"},
			values:     []string{"old-secret", "new-secret"},
			check: func(t *testing.T, msg any) {
				t.Helper()
				change := msg.(*ChangeStorePassphraseMessage)
				if got := string(change.CurrentPassphrase); got != "old-secret" {
					t.Fatalf("ChangeStorePassphraseMessage.CurrentPassphrase = %q, want old-secret", got)
				}
				if got := string(change.NewPassphrase); got != "new-secret" {
					t.Fatalf("ChangeStorePassphraseMessage.NewPassphrase = %q, want new-secret", got)
				}
			},
			zero: func(msg any) {
				change := msg.(*ChangeStorePassphraseMessage)
				change.CurrentPassphrase.Zero()
				change.NewPassphrase.Zero()
			},
		},
		{
			name:       "export_key",
			raw:        []byte(`{"kind":"request","type":"export_key","id":"export-1","address":"ADDR","passphrase":"export-secret"}`),
			msg:        &ExportKeyMessage{},
			fieldNames: []string{"passphrase"},
			values:     []string{"export-secret"},
			check: func(t *testing.T, msg any) {
				t.Helper()
				export := msg.(*ExportKeyMessage)
				if got := string(export.Passphrase); got != "export-secret" {
					t.Fatalf("ExportKeyMessage.Passphrase = %q, want export-secret", got)
				}
			},
			zero: func(msg any) {
				msg.(*ExportKeyMessage).Passphrase.Zero()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := json.Unmarshal(tt.raw, tt.msg); err != nil {
				t.Fatalf("Unmarshal() error = %v", err)
			}
			tt.check(t, tt.msg)

			marshaled, err := MarshalAdminMessage(tt.msg)
			if err != nil {
				t.Fatalf("MarshalAdminMessage() error = %v", err)
			}
			var got map[string]any
			if err := json.Unmarshal(marshaled, &got); err != nil {
				t.Fatalf("Unmarshal(marshaled) error = %v", err)
			}
			for i, fieldName := range tt.fieldNames {
				if got[fieldName] != tt.values[i] {
					t.Fatalf("%s = %#v, want JSON string %q", fieldName, got[fieldName], tt.values[i])
				}
			}

			tt.zero(tt.msg)
			for i, fieldName := range tt.fieldNames {
				marshaled, err := MarshalAdminMessage(tt.msg)
				if err != nil {
					t.Fatalf("MarshalAdminMessage(zeroed) error = %v", err)
				}
				var zeroed map[string]any
				if err := json.Unmarshal(marshaled, &zeroed); err != nil {
					t.Fatalf("Unmarshal(zeroed) error = %v", err)
				}
				if zeroed[fieldName] == tt.values[i] {
					t.Fatalf("%s retained passphrase contents after Zero()", fieldName)
				}
			}
		})
	}
}

func TestParseAdminBaseMessageRejectsMissingKind(t *testing.T) {
	data := []byte(`{"type":"keys_changed","key_count":2}`)

	_, err := ParseAdminBaseMessage(data)
	if err == nil {
		t.Fatal("ParseAdminBaseMessage() error = nil, want missing-kind error")
	}
}

func TestIPCErrorCodeMapsStableConditions(t *testing.T) {
	tests := []struct {
		errMsg string
		want   string
	}{
		{errMsg: "invalid message format", want: ErrCodeInvalidMessageFormat},
		{errMsg: "expected auth message", want: ErrCodeExpectedAuthMessage},
		{errMsg: "invalid auth message format", want: ErrCodeInvalidAuthMessage},
		{errMsg: "authentication failed", want: ErrCodeAuthenticationFailed},
		{errMsg: "invalid passphrase", want: ErrCodeInvalidPassphrase},
		{errMsg: "auth ok but unlock failed: signer is locked", want: ErrCodeUnlockFailed},
		{errMsg: "failed to load keys: policy integrity mismatch", want: ErrCodeUnlockFailed},
		{errMsg: "invalid export key message", want: ErrCodeInvalidRequest},
		{errMsg: "invalid whale song", want: ErrCodeInternal},
		{errMsg: "unknown message type: wat", want: ErrCodeUnknownMessageType},
		{errMsg: "no identity bound to session", want: ErrCodeNoIdentityBound},
		{errMsg: "authorization denied", want: ErrCodeAuthorizationDenied},
		{errMsg: "Signer is locked", want: ErrCodeSignerLocked},
		{errMsg: "Key not found: ADDR", want: ErrCodeKeyNotFound},
		{errMsg: "some internal error", want: ErrCodeInternal},
	}

	for _, tt := range tests {
		if got := IPCErrorCode(tt.errMsg); got != tt.want {
			t.Fatalf("IPCErrorCode(%q) = %q, want %q", tt.errMsg, got, tt.want)
		}
	}
}
