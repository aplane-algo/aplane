// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

// configdoc generates markdown documentation from Go struct tags.
// Usage: go run ./cmd/configdoc > doc/CONFIG_REFERENCE.md
package main

import (
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/aplane-algo/aplane/internal/util"
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
	fmt.Println("File: `config.yaml` in apshell data directory (`-d` or `APSHELL_DATA`)")
	fmt.Println()
	printStructTable(reflect.TypeOf(util.Config{}))
	fmt.Println()

	// apsignerd config
	fmt.Println("## apsignerd Configuration")
	fmt.Println()
	fmt.Println("File: `config.yaml` in apsignerd data directory (`-d` or `APSIGNER_DATA`)")
	fmt.Println()
	printStructTable(reflect.TypeOf(util.ServerConfig{}))
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
		{"APSHELL_DATA", "Data directory for apshell (config and plugins)", "apshell"},
		{"APSIGNER_DATA", "Data directory for apsignerd (config, keys, IPC socket)", "apsignerd, apadmin, apapprover, apstore"},
		{"TEST_PASSPHRASE", "Passphrase for automated testing (auto-unlocks apsignerd)", "apsignerd, apadmin"},
		{"TEST_FUNDING_MNEMONIC", "25-word mnemonic for funding integration test accounts", "integration tests"},
		{"TEST_FUNDING_ACCOUNT", "Testnet address for balance checking in integration tests", "integration tests"},
		{"DISABLE_MEMORY_LOCK", "Set to any value to disable memory locking (for debugging)", "apsignerd"},
		{"ANTHROPIC_API_KEY", "API key for Anthropic Claude (AI code generation)", "apshell"},
		{"OPENAI_API_KEY", "API key for OpenAI GPT (AI code generation)", "apshell"},
		{"APSHELL_DEBUG", "Set to any value to enable debug logging", "apshell"},
		{"XDG_RUNTIME_DIR", "Standard path for runtime files (used for IPC socket default)", "apsignerd"},
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
	fmt.Println("Both apshell and apsignerd require a data directory to be specified.")
	fmt.Println()
	fmt.Println("**apshell:**")
	fmt.Println("- `-d <path>` flag, or")
	fmt.Println("- `APSHELL_DATA` environment variable")
	fmt.Println()
	fmt.Println("**apsignerd/apadmin/apapprover/apstore:**")
	fmt.Println("- `-d <path>` flag, or")
	fmt.Println("- `APSIGNER_DATA` environment variable")
	fmt.Println()
	fmt.Println("### Passphrase Precedence")
	fmt.Println()
	fmt.Println("For apsignerd passphrase sources:")
	fmt.Println("1. `TEST_PASSPHRASE` environment variable (highest priority)")
	fmt.Println("2. `passphrase_command_argv` config option (headless mode)")
	fmt.Println("3. Interactive prompt via apadmin IPC (default)")
}

func init() {
	// Ensure we exit cleanly
	if len(os.Args) > 1 && os.Args[1] == "--help" {
		fmt.Println("Usage: go run ./cmd/configdoc > doc/CONFIG_REFERENCE.md")
		fmt.Println()
		fmt.Println("Generates markdown documentation from Go struct tags.")
		os.Exit(0)
	}
}
