// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package arch_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sharedModeAllowlist is the literal-specific production-code inventory of
// remaining group-bearing modes. The per-literal shape prevents an approved
// file from silently acquiring a different shared mode later.
var sharedModeAllowlist = map[string]map[string]struct{}{
	"internal/apshellapp/modes.go":     {"0o750": {}},
	"internal/backup/copy.go":          {"0750": {}},
	"internal/backup/service.go":       {"0750": {}},
	"internal/clientdata/lock.go":      {"0o770": {}, "0o660": {}},
	"internal/clientstate/watcher.go":  {"0o770": {}},
	"internal/engine/txnwrite.go":      {"0750": {}},
	"internal/signerapp/daemon/ipc.go": {"0660": {}},
	"internal/storeperm/audit.go":      {"0o770": {}, "0o660": {}, "0o640": {}, "0o750": {}},
}

func TestLegacySharedModesStayOutOfSignerStoreWriters(t *testing.T) {
	root := repositoryRoot(t)
	set := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			name := entry.Name()
			if name == ".git" || name == "vendor" || name == "temp" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		file, err := parser.ParseFile(set, path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(file, func(node ast.Node) bool {
			literal, ok := node.(*ast.BasicLit)
			if !ok || literal.Kind != token.INT || !isSharedModeLiteral(literal.Value) {
				return true
			}
			allowedModes := sharedModeAllowlist[rel]
			if _, allowed := allowedModes[literal.Value]; !allowed {
				t.Errorf("%s:%d uses group-bearing mode %s outside the audited allowlist", rel, set.Position(literal.Pos()).Line, literal.Value)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func isSharedModeLiteral(value string) bool {
	switch value {
	case "0770", "0o770", "0660", "0o660", "0640", "0o640", "0750", "0o750":
		return true
	default:
		return false
	}
}

func TestSystemdUnitsKeepProtectedRuntimeBoundary(t *testing.T) {
	root := repositoryRoot(t)
	for _, rel := range []string{"installer/apsigner.service", "installer/apsigner.service.template"} {
		data, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		for _, required := range []string{
			"RuntimeDirectory=apsigner",
			"RuntimeDirectoryMode=0750",
			"UMask=0077",
			"NoNewPrivileges=true",
			"PrivateTmp=true",
		} {
			if !strings.Contains(text, required) {
				t.Errorf("%s is missing %q", rel, required)
			}
		}
	}
}

func TestInstallerPreflightsBeforeStoreChildMutation(t *testing.T) {
	root := repositoryRoot(t)
	mainInstaller := readTextFile(t, filepath.Join(root, "install.sh"))
	assertTextOrder(t, "install.sh", mainInstaller,
		`ensure_prod_data_dir_permissions "$DATA_DIR"`,
		`"$BIN_SRC/apstore" -d "$DATA_DIR" permissions preflight`,
		`"$SCRIPT_DIR/installer/scripts/systemd-setup.sh" "${SYSTEMD_SETUP_ARGS[@]}"`,
		`ensure_prod_backup_permissions "$DATA_DIR"`,
		`install_prod_uninstaller "$DATA_DIR"`,
		`install_template_library "$DATA_DIR" "$SVC_USER" "$SVC_GROUP"`,
	)
	for _, forbidden := range []string{
		"repair_prod_store_lock_permissions",
		`chmod 2750 "$install_dir"`,
	} {
		if strings.Contains(mainInstaller, forbidden) {
			t.Errorf("install.sh retains forbidden pre-migration operation %q", forbidden)
		}
	}

	setup := readTextFile(t, filepath.Join(root, "installer", "scripts", "systemd-setup.sh"))
	assertTextOrder(t, "installer/scripts/systemd-setup.sh", setup,
		`chmod 700 "$DATA_DIR"`,
		`"$BINDIR/apstore" -d "$DATA_DIR" permissions preflight`,
		`publish_managed_metadata \`,
		`publish_managed_metadata "$PROD_MARKER_PATH"`,
		`"$BINDIR/apstore" -d "$DATA_DIR" permissions migrate`,
		`' > "$SERVICE_DEST"`,
		`for f in "$DATA_DIR"/identities/*/passphrase.cred`,
	)
}

func TestInstallerShellAvoidsLegacySharedStoreModes(t *testing.T) {
	root := repositoryRoot(t)
	for _, rel := range []string{
		"install.sh",
		"installer/scripts/systemd-setup.sh",
	} {
		text := readTextFile(t, filepath.Join(root, filepath.FromSlash(rel)))
		for _, forbidden := range []string{"0770", "2770", "0660", "2750"} {
			if strings.Contains(text, forbidden) {
				t.Errorf("%s contains legacy shared signer-store mode %s", rel, forbidden)
			}
		}
	}
}

func TestGeneratedEnvironmentPreservesConfiguredIPCPath(t *testing.T) {
	root := repositoryRoot(t)
	installer := readTextFile(t, filepath.Join(root, "install.sh"))
	for _, required := range []string{
		`SIGNER_IPC_PATH="$(read_top_level_string "$DATA_DIR/config.yaml" "ipc_path")"`,
		`[ -n "$SIGNER_IPC_PATH" ] || SIGNER_IPC_PATH="/run/apsigner/aplane.sock"`,
		`export APSIGNER_IPC_PATH=$SIGNER_IPC_PATH_SHELL`,
	} {
		if !strings.Contains(installer, required) {
			t.Errorf("install.sh is missing generated IPC-path contract %q", required)
		}
	}
	if strings.Contains(installer, `export APSIGNER_IPC_PATH="/run/apsigner/aplane.sock"`) {
		t.Error("install.sh still hardcodes the system IPC path in generated apenv.sh")
	}
}

func TestInstallerCanonicalizesBinaryDirectoryPhysically(t *testing.T) {
	root := repositoryRoot(t)
	setup := readTextFile(t, filepath.Join(root, "installer", "scripts", "systemd-setup.sh"))
	if !strings.Contains(setup, `BINDIR="$(cd "$BINDIR" && pwd -P)"`) {
		t.Error("systemd-setup.sh does not physically canonicalize BINDIR before its store-boundary check")
	}
}

func TestEnvironmentAuditUsesManagedSocketWithoutSharedTempFiles(t *testing.T) {
	root := repositoryRoot(t)
	audit := readTextFile(t, filepath.Join(root, "installer", "scripts", "aplane-env-audit.sh"))
	for _, required := range []string{
		`SIGNER_PROD_MANAGED=1`,
		`[ "$resolved_ipc_path" = "$SIGNER_DATA/aplane.sock" ]`,
		`signer_ipc_path="/run/apsigner/aplane.sock"`,
		`version_output="$("$bin" --version 2>/dev/null)"`,
	} {
		if !strings.Contains(audit, required) {
			t.Errorf("aplane-env-audit.sh is missing %q", required)
		}
	}
	if strings.Contains(audit, "/tmp/aplane-audit-version") {
		t.Error("aplane-env-audit.sh retains a predictable shared-temp version probe")
	}
}

func readTextFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func assertTextOrder(t *testing.T, label, text string, ordered ...string) {
	t.Helper()
	offset := 0
	for _, marker := range ordered {
		relative := strings.Index(text[offset:], marker)
		if relative < 0 {
			t.Fatalf("%s does not contain %q after byte %d", label, marker, offset)
		}
		offset += relative + len(marker)
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}
