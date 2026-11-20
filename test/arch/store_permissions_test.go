// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package arch_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// sharedModeAllowlist is the literal-specific production-code inventory of
// remaining group-bearing modes. The per-literal shape prevents an approved
// file from silently acquiring a different shared mode later.
var sharedModeAllowlist = map[string]map[string]struct{}{
	"internal/apshellapp/modes.go":            {"0o750": {}},
	"internal/backup/copy.go":                 {"0750": {}},
	"internal/backup/service.go":              {"0750": {}},
	"internal/clientdata/lock.go":             {"0o770": {}, "0o660": {}},
	"internal/clientstate/watcher.go":         {"0o770": {}},
	"internal/engine/txnwrite.go":             {"0750": {}},
	"internal/fsutil/durable.go":              {"0o640": {}},
	"internal/signerapp/daemon/ipc.go":        {"0660": {}},
	"internal/storeperm/audit.go":             {"0o770": {}, "0o660": {}, "0o640": {}, "0o750": {}},
	"internal/storeperm/service_principal.go": {"0o750": {}},
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
		`permissions prepare-managed-root \`,
		`"$BINDIR/apstore" -d "$DATA_DIR" permissions preflight`,
		`"$BINDIR/apstore" -d "$DATA_DIR" permissions convert-managed \`,
		`' > "$SERVICE_DEST"`,
		`cred_file="$DATA_DIR/identities/default/passphrase.cred"`,
	)
	for _, forbidden := range []string{
		`chown "$SVC_USER:$SVC_GROUP" "$DATA_DIR"`,
		`chmod 700 "$DATA_DIR"`,
		`mkdir -p "$DATA_DIR"`,
	} {
		if strings.Contains(setup, forbidden) {
			t.Errorf("systemd-setup.sh retains unsafe root pathname mutation %q", forbidden)
		}
	}
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
		`SIGNER_IPC_PATH="$("$BINDIR/approbe" signer-ipc-path -d "$DATA_DIR")"`,
		`export APLANE_INSTALL_ROOT=$OPERATOR_ROOT_SHELL`,
		`export APLANE_BINDIR=$BINDIR_SHELL`,
		`export APSIGNER_DATA=$DATA_DIR_SHELL`,
		`export APSIGNER_IPC_PATH=$SIGNER_IPC_PATH_SHELL`,
		`export APCLIENT_DATA=$APCLIENT_DIR_SHELL`,
		`RESOLVED_SIGNER_IPC_PATH="$("$BINDIR/approbe" signer-ipc-path -d "$DATA_DIR")"`,
	} {
		if !strings.Contains(installer, required) {
			t.Errorf("install.sh is missing generated IPC-path contract %q", required)
		}
	}
	if strings.Contains(installer, `export APSIGNER_IPC_PATH="/run/apsigner/aplane.sock"`) {
		t.Error("install.sh still hardcodes the system IPC path in generated apenv.sh")
	}
	if strings.Contains(installer, "read_top_level_string") {
		t.Error("install.sh still parses ipc_path independently of the Go resolver")
	}
}

func TestLocalInstallerSecuresSocketAncestor(t *testing.T) {
	root := repositoryRoot(t)
	installer := readTextFile(t, filepath.Join(root, "install.sh"))
	assertTextOrder(t, "install.sh", installer,
		`prepare_builtin_plugin_payloads`,
		`chmod 700 "$LOCAL_PATH"`,
		`mkdir -p "$SIGNER_BINDIR" "$CLIENT_BINDIR"`,
		`chmod 700 "$INSTALL_ROOT"`,
	)
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
		`approbe_ipc_args=(signer-ipc-path -d "$SIGNER_DATA")`,
		`approbe_ipc_args+=(--honor-ipc-env)`,
		`version_output="$("$bin" --version 2>/dev/null)"`,
	} {
		if !strings.Contains(audit, required) {
			t.Errorf("aplane-env-audit.sh is missing %q", required)
		}
	}
	if strings.Contains(audit, "/tmp/aplane-audit-version") {
		t.Error("aplane-env-audit.sh retains a predictable shared-temp version probe")
	}
	if strings.Contains(audit, `yaml_value "$SIGNER_CONFIG" ipc_path`) {
		t.Error("aplane-env-audit.sh still parses ipc_path independently of approbe")
	}
}

// TestEnvironmentAuditReadsInstalledLayouts runs the audit on scratch installs
// whose config files come from install.sh's own writers, and on the
// four-space endpoints.yaml apshell rewrites, here holding a second node on
// this machine as well.
func TestEnvironmentAuditReadsInstalledLayouts(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not available")
	}
	root := repositoryRoot(t)
	installer := readTextFile(t, filepath.Join(root, "install.sh"))
	var writers []string
	for _, name := range []string{
		"write_signer_config",
		"write_apshell_local_config",
		"write_apshell_endpoint_registry",
		"write_apshell_cosigner_endpoint_registry",
		"write_apshell_endpoint_registry_for_role",
	} {
		writers = append(writers, shellFunction(t, installer, name))
	}
	apshellWritten := func(primaryPort int) string {
		return fmt.Sprintf("schema_version: 2\ndefault: primary\nendpoints:\n"+
			"    cos.a:\n        role: cosigner\n        url: ssh://localhost:2227\n"+
			"    primary:\n        role: signer\n        url: ssh://127.0.0.1:%d\n", primaryPort)
	}
	cases := []struct {
		name      string
		role      string // the installer writes endpoints.yaml for this role
		endpoints string // otherwise this is endpoints.yaml
		want      string
	}{
		{name: "signer", role: "signer", want: `PASS SSH port match\s+primary: 1127`},
		{name: "cosigner", role: "cosigner", want: `PASS SSH port match\s+local-cosigner: 1127`},
		{name: "beside another node", endpoints: apshellWritten(1127), want: `PASS SSH port match\s+primary: 1127`},
		{name: "mismatch", endpoints: apshellWritten(1128),
			want: `WARN SSH port mismatch\s+no endpoint on this machine uses signer port 1127: cos\.a=2227 primary=1128`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			signer := filepath.Join(home, "aplane", "apsigner")
			client := filepath.Join(home, "aplane", "apclient")
			identity := filepath.Join(signer, "identities", "default")
			for _, dir := range []string{
				filepath.Join(signer, ".ssh"),
				filepath.Join(identity, ".ssh"),
				filepath.Join(identity, "generations", "g1", "keys"),
				filepath.Join(identity, "generations", ".staging-g2"),
				filepath.Join(client, ".ssh"),
			} {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Chmod(signer, 0o700); err != nil {
				t.Fatal(err)
			}
			for _, file := range []string{
				filepath.Join(identity, ".keystore"),
				filepath.Join(identity, "store-root.enc"),
				filepath.Join(identity, ".ssh", "authorized_keys"),
				filepath.Join(signer, ".ssh", "ssh_host_key"),
				filepath.Join(client, ".ssh", "id_ed25519"),
				filepath.Join(client, ".ssh", "known_hosts"),
			} {
				if err := os.WriteFile(file, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			script := strings.Join(writers, "\n") + `
write_signer_config "$1/config.yaml" 11270 1127
write_apshell_local_config "$2/config.yaml"
if [ -n "$3" ]; then
    write_apshell_endpoint_registry_for_role "$2/endpoints.yaml" "$3" 127.0.0.1 1127
fi
`
			if out, err := exec.Command(bash, "-c", script, "bash", signer, client, tc.role).CombinedOutput(); err != nil {
				t.Fatalf("installer writers: %v\n%s", err, out)
			}
			if tc.endpoints != "" {
				if err := os.WriteFile(filepath.Join(client, "endpoints.yaml"), []byte(tc.endpoints), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			audit := exec.Command(bash, filepath.Join(root, "installer", "scripts", "aplane-env-audit.sh"),
				"--signer-data", signer, "--client-data", client)
			audit.Env = []string{"HOME=" + home, "PATH=/usr/bin:/bin"}
			out, err := audit.CombinedOutput()
			if err != nil {
				t.Fatalf("audit: %v\n%s", err, out)
			}
			for _, want := range []string{
				tc.want,
				`PASS client endpoints\s`,
				`PASS store root\s`,
				`PASS generations\s+\S+ \(1\)`,
			} {
				if !regexp.MustCompile(`(?m)^` + want).Match(out) {
					t.Errorf("audit output lacks %q:\n%s", want, out)
				}
			}
			if tc.name != "mismatch" && strings.Contains(string(out), "WARN SSH port mismatch") {
				t.Errorf("audit reports a port mismatch:\n%s", out)
			}
			if strings.Contains(string(out), "key directory") {
				t.Errorf("audit still looks for a pre-generations key directory:\n%s", out)
			}
		})
	}
}

// TestInstallerAndAuditReadEndpointsAlike keeps install.sh's copy of the
// audit's endpoints.yaml and URL helpers the same as the audit's, apart from
// indentation, so the installer's port check and the audit agree.
func TestInstallerAndAuditReadEndpointsAlike(t *testing.T) {
	root := repositoryRoot(t)
	installer := readTextFile(t, filepath.Join(root, "install.sh"))
	audit := readTextFile(t, filepath.Join(root, "installer", "scripts", "aplane-env-audit.sh"))
	for _, name := range []string{
		"yaml_scalars", "yaml_value", "endpoint_authority", "endpoint_host", "endpoint_port", "is_loopback_host",
	} {
		installed := strings.Fields(shellFunction(t, installer, name))
		audited := strings.Fields(shellFunction(t, audit, name))
		if !slices.Equal(installed, audited) {
			t.Errorf("install.sh and aplane-env-audit.sh define %s differently", name)
		}
	}
}

// shellFunction returns one top-level function, name() { ... }, from a script.
func shellFunction(t *testing.T, script, name string) string {
	t.Helper()
	_, rest, found := strings.Cut(script, "\n"+name+"() {\n")
	body, _, closed := strings.Cut(rest, "\n}\n")
	if !found || !closed {
		t.Fatalf("script has no function %s", name)
	}
	return name + "() {\n" + body + "\n}"
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
