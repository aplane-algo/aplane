// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	"golang.org/x/term"
)

func cmdSetPassfile() error {
	configPath := filepath.Join(dataDirectory, "config.yaml")

	// Guard: already configured
	has, err := configHasKey(configPath, "passphrase_command_argv")
	if err != nil {
		return fmt.Errorf("checking config: %w", err)
	}
	if has {
		return fmt.Errorf("%s already contains passphrase_command_argv; run 'appass clear' first", configPath)
	}

	// Guard: don't downgrade from systemd-creds
	svc, err := parseServiceFile(defaultServiceFile)
	if err != nil {
		return fmt.Errorf("reading service file: %w", err)
	}
	if svc.HasLoadCred {
		return fmt.Errorf("service file has LoadCredentialEncrypted (systemd-creds); use 'set systemd-creds' instead of downgrading to passfile")
	}

	// Check pass-file binary exists
	passFileBin := filepath.Join(svc.BinDir, "pass-file")
	if _, err := os.Stat(passFileBin); err != nil {
		return fmt.Errorf("pass-file not found at %s; ensure it is installed alongside apsignerd", passFileBin)
	}

	fmt.Println("=== pass-file auto-unlock setup ===")
	fmt.Println("")
	fmt.Println("  WARNING: This stores the passphrase in a plaintext file.")
	fmt.Println("  Suitable for development/testing only. For production, use")
	fmt.Println("  'appass set systemd-creds' (TPM2-backed encryption) instead.")
	fmt.Println("")
	fmt.Printf("  Data dir:  %s\n", dataDirectory)
	fmt.Printf("  Binary:    %s/apsignerd\n", svc.BinDir)
	fmt.Printf("  User:      %s\n", svc.User)
	fmt.Printf("  Group:     %s\n", svc.Group)
	fmt.Println("")

	// Prompt for passphrase
	fmt.Println("Enter the passphrase for the keystore.")
	fmt.Println("This must match the passphrase used (or to be used) with apstore init.")
	fmt.Println("")

	fmt.Print("Passphrase: ")
	pass1, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return fmt.Errorf("reading passphrase: %w", err)
	}

	fmt.Print("Confirm:    ")
	pass2, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return fmt.Errorf("reading confirmation: %w", err)
	}

	if string(pass1) != string(pass2) {
		return fmt.Errorf("passphrases do not match")
	}
	if len(pass1) == 0 {
		return fmt.Errorf("passphrase must not be empty")
	}

	// Write passphrase file
	passphrasePath := filepath.Join(dataDirectory, "passphrase")
	fmt.Printf("Writing passphrase file %s...\n", passphrasePath)
	if err := os.WriteFile(passphrasePath, pass1, 0600); err != nil {
		return fmt.Errorf("writing passphrase file: %w", err)
	}

	// Chown to service user
	if err := chownToUser(passphrasePath, svc.User, svc.Group); err != nil {
		return fmt.Errorf("chown passphrase file: %w", err)
	}

	// Update config.yaml: remove passphrase_timeout if it exists (avoid duplicates),
	// then append the auto-unlock settings.
	fmt.Printf("Updating %s...\n", configPath)
	if err := configRemoveKeys(configPath, []string{"passphrase_timeout"}); err != nil {
		return fmt.Errorf("updating config: %w", err)
	}
	lines := []string{
		fmt.Sprintf(`passphrase_command_argv: ["%s", "passphrase"]`, passFileBin),
		`passphrase_timeout: "0"`,
	}
	if err := configAppendLines(configPath, lines); err != nil {
		return fmt.Errorf("updating config: %w", err)
	}

	fmt.Println("")
	fmt.Println("=== Setup complete ===")
	fmt.Println("")
	fmt.Println("Next steps:")
	fmt.Printf("  1. If the keystore is not yet initialized:\n")
	fmt.Printf("       sudo apstore -d %s init\n", dataDirectory)
	fmt.Println("     Use the same passphrase you entered above.")
	fmt.Println("  2. Start (or restart) the service:")
	fmt.Println("       sudo systemctl restart apsigner")
	fmt.Println("  3. Check status:")
	fmt.Println("       systemctl status apsigner")

	return nil
}

func cmdSetSystemcreds() error {
	configPath := filepath.Join(dataDirectory, "config.yaml")

	// Guard: already configured
	has, err := configHasKey(configPath, "passphrase_command_argv")
	if err != nil {
		return fmt.Errorf("checking config: %w", err)
	}
	if has {
		return fmt.Errorf("%s already contains passphrase_command_argv; run 'appass clear' first", configPath)
	}

	// Check systemd-creds is available
	if _, err := exec.LookPath("systemd-creds"); err != nil {
		return fmt.Errorf("systemd-creds not found; requires systemd >= 250")
	}

	// Parse service file
	svc, err := parseServiceFile(defaultServiceFile)
	if err != nil {
		return fmt.Errorf("reading service file: %w", err)
	}

	// Check pass-systemd-creds binary exists
	passCredsBin := filepath.Join(svc.BinDir, "pass-systemd-creds")
	if _, err := os.Stat(passCredsBin); err != nil {
		return fmt.Errorf("pass-systemd-creds not found at %s; ensure it is installed alongside apsignerd", passCredsBin)
	}

	fmt.Println("=== systemd-creds auto-unlock setup ===")
	fmt.Println("")
	fmt.Printf("  Data dir:  %s\n", dataDirectory)
	fmt.Printf("  Binary:    %s/apsignerd\n", svc.BinDir)
	fmt.Printf("  User:      %s\n", svc.User)
	fmt.Printf("  Group:     %s\n", svc.Group)
	fmt.Println("")

	// Prompt for passphrase
	fmt.Println("Enter the passphrase for the keystore.")
	fmt.Println("This must match the passphrase used (or to be used) with apstore init.")
	fmt.Println("The passphrase will be encrypted via systemd-creds (TPM2/host key).")
	fmt.Println("")

	fmt.Print("Passphrase: ")
	pass1, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return fmt.Errorf("reading passphrase: %w", err)
	}

	fmt.Print("Confirm:    ")
	pass2, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return fmt.Errorf("reading confirmation: %w", err)
	}

	if string(pass1) != string(pass2) {
		return fmt.Errorf("passphrases do not match")
	}
	if len(pass1) == 0 {
		return fmt.Errorf("passphrase must not be empty")
	}

	// Encrypt passphrase via pass-systemd-creds write
	credFile := filepath.Join(dataDirectory, "passphrase.cred")
	fmt.Printf("Encrypting passphrase to %s...\n", credFile)
	cmd := exec.Command(passCredsBin, "write", credFile)
	cmd.Stdin = bytes.NewReader(pass1)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("pass-systemd-creds write failed: %w", err)
	}
	if !bytes.Equal(pass1, out) {
		return fmt.Errorf("round-trip verification failed: encrypted passphrase does not match")
	}

	// Credential file must be root-owned (systemd reads it via LoadCredentialEncrypted)
	if err := os.Chown(credFile, 0, 0); err != nil {
		return fmt.Errorf("chown credential file: %w", err)
	}
	if err := os.Chmod(credFile, 0600); err != nil {
		return fmt.Errorf("chmod credential file: %w", err)
	}

	// Run systemd-setup.sh to regenerate service file with LoadCredentialEncrypted
	setupScript := filepath.Join(dataDirectory, "scripts", "systemd-setup.sh")
	if _, err := os.Stat(setupScript); err != nil {
		return fmt.Errorf("systemd-setup.sh not found at %s; ensure scripts are installed", setupScript)
	}

	fmt.Println("Regenerating service file with LoadCredentialEncrypted...")
	setupCmd := exec.Command(setupScript, svc.User, svc.Group, svc.BinDir, "--auto-unlock")
	setupCmd.Stdout = os.Stdout
	setupCmd.Stderr = os.Stderr
	if err := setupCmd.Run(); err != nil {
		return fmt.Errorf("systemd-setup.sh failed: %w", err)
	}

	// Update config.yaml: remove passphrase_timeout if it exists (avoid duplicates),
	// then append the auto-unlock settings.
	fmt.Printf("Updating %s...\n", configPath)
	if err := configRemoveKeys(configPath, []string{"passphrase_timeout"}); err != nil {
		return fmt.Errorf("updating config: %w", err)
	}
	lines := []string{
		fmt.Sprintf(`passphrase_command_argv: ["%s", "passphrase.cred"]`, passCredsBin),
		`passphrase_timeout: "0"`,
	}
	if err := configAppendLines(configPath, lines); err != nil {
		return fmt.Errorf("updating config: %w", err)
	}

	fmt.Println("")
	fmt.Println("=== Setup complete ===")
	fmt.Println("")
	fmt.Println("Next steps:")
	fmt.Printf("  1. If the keystore is not yet initialized:\n")
	fmt.Printf("       sudo apstore -d %s init\n", dataDirectory)
	fmt.Println("     Use the same passphrase you entered above.")
	fmt.Println("  2. Start (or restart) the service:")
	fmt.Println("       sudo systemctl restart apsigner")
	fmt.Println("  3. Check status:")
	fmt.Println("       systemctl status apsigner")

	return nil
}

// chownToUser changes file ownership to the given user and group names.
func chownToUser(path, username, groupname string) error {
	u, err := user.Lookup(username)
	if err != nil {
		return fmt.Errorf("looking up user %q: %w", username, err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return fmt.Errorf("parsing uid: %w", err)
	}

	g, err := user.LookupGroup(groupname)
	if err != nil {
		return fmt.Errorf("looking up group %q: %w", groupname, err)
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return fmt.Errorf("parsing gid: %w", err)
	}

	return os.Chown(path, uid, gid)
}
