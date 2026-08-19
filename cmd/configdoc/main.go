// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// configdoc generates markdown documentation from Go struct tags.
// Usage: go run ./cmd/configdoc > docs/CONFIG_REFERENCE.md
package main

import (
	"fmt"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"os"
	"reflect"
	"strings"

	"github.com/aplane-algo/aplane/internal/config"
)

// EnvVar represents an environment variable configuration
type EnvVar struct {
	Name        string
	Description string
	UsedBy      string
}

func main() {
	fmt.Println("# Configuration Reference")
	fmt.Println()
	fmt.Println("Auto-generated from Go struct tags. Do not edit manually.")
	fmt.Println()
	fmt.Println("---")
	fmt.Println()

	// apshell config
	fmt.Println("## apshell Configuration")
	fmt.Println()
	fmt.Println("File: `config.yaml` in apshell data directory (`-d` or `APCLIENT_DATA`)")
	fmt.Println()
	printStructTable(reflect.TypeOf(config.Config{}))
	fmt.Println()
	printClientEndpointReference()
	fmt.Println()

	// apsigner config
	fmt.Println("## apsigner Configuration")
	fmt.Println()
	fmt.Println("File: `config.yaml` in apsigner data directory (`-d` or `APSIGNER_DATA`, required)")
	fmt.Println()
	printStructTable(reflect.TypeOf(serverconfig.ServerConfig{}))
	fmt.Println()
	fmt.Println("Product-local `identities/default/config.yaml` contains settings only.")
	fmt.Println("Node role is stored separately in root `node.yaml`.")
	fmt.Println()

	// Environment variables
	fmt.Println("## Environment Variables")
	fmt.Println()
	printEnvVars()
}

func printStructTable(t reflect.Type) {
	printStructTableWithPrefix(t, "")
}

func printStructTableWithPrefix(t reflect.Type, prefix string) {
	if prefix == "" {
		fmt.Println("| Field | Type | Default | Description |")
		fmt.Println("|-------|------|---------|-------------|")
	}

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if field.Tag.Get("configdoc") == "skip" {
			continue
		}

		// Get yaml tag first, fall back to json tag
		tag := field.Tag.Get("yaml")
		if tag == "" {
			tag = field.Tag.Get("json")
		}
		if tag == "" || tag == "-" {
			continue
		}
		// Handle tag options like "omitempty"
		fieldName := strings.Split(tag, ",")[0]
		if prefix != "" {
			fieldName = prefix + "." + fieldName
		}

		// Check if this is a nested struct (pointer to struct)
		if field.Type.Kind() == reflect.Ptr && field.Type.Elem().Kind() == reflect.Struct {
			// Get description for the nested struct itself
			desc := field.Tag.Get("description")
			if desc == "" {
				desc = "(nested config block)"
			}
			fmt.Printf("| `%s` | object | (none) | %s |\n", fieldName, desc)
			// Recursively print nested struct fields
			printStructTableWithPrefix(field.Type.Elem(), fieldName)
			continue
		}

		if field.Type.Kind() == reflect.Struct {
			desc := field.Tag.Get("description")
			if desc == "" {
				desc = "(nested config block)"
			}
			def := field.Tag.Get("default")
			if def == "" {
				def = "(none)"
			}
			fmt.Printf("| `%s` | object | %s | %s |\n", fieldName, def, desc)
			printStructTableWithPrefix(field.Type, fieldName)
			continue
		}

		// Check if this is a map type with struct values (e.g., AlgodConfig map[string]*AlgodNetworkConfig)
		if field.Type.Kind() == reflect.Map {
			desc := field.Tag.Get("description")
			if desc == "" {
				desc = "(map config block)"
			}
			fmt.Printf("| `%s` | map | (none) | %s |\n", fieldName, desc)
			// If the map value is a pointer to struct, print its fields with a <network> placeholder
			valType := field.Type.Elem()
			if valType.Kind() == reflect.Ptr && valType.Elem().Kind() == reflect.Struct {
				printStructTableWithPrefix(valType.Elem(), fieldName+".<network>")
			}
			continue
		}

		// Get description
		desc := field.Tag.Get("description")
		if desc == "" {
			desc = "(no description)"
		}

		// Get default
		def := field.Tag.Get("default")
		switch def {
		case "":
			def = "(none)"
		case `""`:
			def = "(empty string)"
		}

		// Get type name
		typeName := formatType(field.Type)

		fmt.Printf("| `%s` | %s | `%s` | %s |\n", fieldName, typeName, def, desc)
	}
}

func printClientEndpointReference() {
	fmt.Println("## apshell Endpoint Registry")
	fmt.Println()
	fmt.Println("File: `endpoints.yaml` in apshell data directory (`-d` or `APCLIENT_DATA`)")
	fmt.Println()
	fmt.Println("Signer and sentry endpoint routing lives here, not in `config.yaml`.")
	fmt.Println()
	fmt.Println("| Field | Type | Default | Description |")
	fmt.Println("|-------|------|---------|-------------|")
	fmt.Println("| `schema_version` | int | `2` | Endpoint registry schema version |")
	fmt.Println("| `default` | string | `(operator-chosen)` | Default signer endpoint alias |")
	fmt.Println("| `endpoints.<alias>.role` | string | `(none)` | Endpoint role: `signer` or `sentry` |")
	fmt.Println("| `endpoints.<alias>.url` | string | `(none)` | Endpoint URL: `ssh://host[:port]`, loopback `http://...`, `https://...`, or `self` where supported |")
	fmt.Println("| `endpoints.<alias>.signer_port` | int | `11270` | Remote apsigner REST port for `ssh://` endpoints |")
	fmt.Println("| `endpoints.<alias>.local_port` | int | `0` | Local tunnel port for `ssh://` endpoints; `0` chooses automatically |")
	fmt.Println("| `endpoints.<alias>.identity_file` | string | `.ssh/id_ed25519` | SSH private key path, resolved relative to `APCLIENT_DATA` |")
	fmt.Println("| `endpoints.<alias>.known_hosts_path` | string | `.ssh/known_hosts` | SSH known-hosts path, resolved relative to `APCLIENT_DATA` |")
	fmt.Println("| `endpoints.<alias>.token_file` | string | `aplane.token` or `tokens/<alias>.token` | Endpoint API token file, resolved relative to `APCLIENT_DATA` |")
}

func formatType(t reflect.Type) string {
	switch t.Kind() {
	case reflect.String:
		return "string"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return "int"
	case reflect.Bool:
		return "bool"
	case reflect.Slice:
		return "[]" + formatType(t.Elem())
	case reflect.Ptr:
		return "*" + formatType(t.Elem())
	default:
		return t.String()
	}
}

func printEnvVars() {
	envVars := []EnvVar{
		{"APCLIENT_DATA", "Data directory for apshell (config, plugin catalog, and scripts)", "apshell, aplocalnet"},
		{"APSIGNER_DATA", "Data directory for apsigner (config, keys, IPC socket)", "apsigner, apadmin, apapprover, apstore, appass, aplocalnet"},
		{"APCONSOLE_CONFIG", "Optional explicit apconsole.yaml path for the unified console; explicit path/env/flag values must agree", "apconsole"},
		{"APLANE_INSTALL_ROOT", "Installer default install root / operator-root used when the path argument is omitted", "install.sh, bootstrap-install.sh"},
		{"APLANE_BINDIR", "Installer default systemd bindir used when --bindir is omitted", "install.sh, bootstrap-install.sh"},
		{"APLANE_SKIP_LOCALNET_SETUP", "Set to 1 to skip LocalNet setup during install", "install.sh"},
		{"APLANE_SYSTEMD_MANAGED", "Set to 1 to mark the signer instance as systemd-managed (manual startup blocked unless overridden)", "apsigner"},
		{"APLANE_LOCALNET_ALGOD_URL", "Optional AlgoKit LocalNet algod override", "aplocalnet, algokit-localnet plugin"},
		{"APLANE_LOCALNET_KMD_URL", "Optional AlgoKit LocalNet KMD override", "aplocalnet, algokit-localnet plugin"},
		{"APLANE_LOCALNET_TOKEN", "Optional AlgoKit LocalNet algod/KMD token override", "aplocalnet, algokit-localnet plugin"},
		{"APLANE_LOCALNET_WALLET", "Optional KMD wallet name for LocalNet funding", "algokit-localnet plugin"},
		{"APLANE_LOCALNET_WALLET_PASSWORD", "Optional KMD wallet password for LocalNet funding", "algokit-localnet plugin"},
		{"TEST_PASSPHRASE", "Passphrase for automated testing (auto-unlocks apsigner)", "apsigner, apadmin"},
		{"TEST_FUNDING_MNEMONIC", "25-word native Falcon-1024 mnemonic for funding integration test accounts", "integration tests"},
		{"TEST_FUNDING_ACCOUNT", "Native Falcon address for balance checking in integration tests", "integration tests"},
		{"DISABLE_MEMORY_LOCK", "Set to any value to disable memory locking (for debugging)", "apsigner"},
		{"APSHELL_DEBUG", "Set to any value to enable debug logging", "apshell"},
		{"XDG_RUNTIME_DIR", "Standard private runtime directory useful for custom ipc_path placement", "apsigner"},
	}

	fmt.Println("| Variable | Description | Used By |")
	fmt.Println("|----------|-------------|---------|")

	for _, env := range envVars {
		fmt.Printf("| `%s` | %s | %s |\n", env.Name, env.Description, env.UsedBy)
	}

	// Add config search paths
	fmt.Println()
	fmt.Println("### Data Directory Configuration")
	fmt.Println()
	fmt.Println("Both apshell and apsigner require a data directory to be specified.")
	fmt.Println()
	fmt.Println("**apshell:**")
	fmt.Println("- `-d <path>` flag, or")
	fmt.Println("- `APCLIENT_DATA` environment variable")
	fmt.Println()
	fmt.Println("**apsigner/apadmin/apapprover/apstore/appass:**")
	fmt.Println("- `-d <path>` flag, or")
	fmt.Println("- `APSIGNER_DATA` environment variable")
	fmt.Println("- no default data directory is assumed")
	fmt.Println()
	fmt.Println("### Passphrase Precedence")
	fmt.Println()
	fmt.Println("For apsigner passphrase sources:")
	fmt.Println("1. `TEST_PASSPHRASE` environment variable (highest priority)")
	fmt.Println("2. product-local `identities/default/unlock.yaml` passphrase command, falling back to process-global `passphrase_command_argv` in config.yaml (headless mode)")
	fmt.Println("3. Interactive prompt via apadmin IPC (default)")
}

func init() {
	// Ensure we exit cleanly
	if len(os.Args) > 1 && os.Args[1] == "--help" {
		fmt.Println("Usage: go run ./cmd/configdoc > docs/USER_CONFIG_REFERENCE.md")
		fmt.Println()
		fmt.Println("Generates markdown documentation from Go struct tags.")
		os.Exit(0)
	}
}
