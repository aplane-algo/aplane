// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/aplane-algo/aplane/internal/signerapp/unlockconfig"
)

const systemdCredentialName = "aplane-passphrase"

// executeSetPassfile sets up appass-file auto-unlock.
// passphrase is the raw passphrase bytes. svc and isLocal describe the environment.
func executeSetPassfile(dataDir, identityID string, passphrase []byte, svc *serviceInfo, isLocal bool) (string, error) {
	if err := requireSignerStopped(dataDir); err != nil {
		return "", err
	}

	currentMethod, err := currentAutoUnlockMethod(dataDir, identityID)
	if err != nil {
		return "", err
	}

	// In systemd mode, require root.
	if !isLocal && os.Getuid() != 0 {
		return "", fmt.Errorf("systemd mode: must be run as root (use sudo)")
	}

	// Guard unexpected service state. A managed systemd-creds -> passfile migration is allowed.
	if !isLocal && svc.HasLoadCred && currentMethod != "systemd-creds" {
		return "", fmt.Errorf("service has LoadCredentialEncrypted but config is not in systemd-creds mode; clear the service state before switching to passfile")
	}

	// Check appass-file binary exists
	passFileBin := filepath.Join(svc.BinDir, "appass-file")
	if _, err := os.Stat(passFileBin); err != nil {
		return "", fmt.Errorf("appass-file not found at %s; ensure it is installed alongside apsigner", passFileBin)
	}

	// Write passphrase file to identity-scoped directory
	identityDir := filepath.Join(dataDir, "identities", identityID)
	if err := os.MkdirAll(identityDir, 0700); err != nil {
		return "", fmt.Errorf("creating identity directory: %w", err)
	}
	passphrasePath := filepath.Join(identityDir, "passphrase")
	tmpPassphrase, err := os.CreateTemp(identityDir, "passphrase.tmp-*")
	if err != nil {
		return "", fmt.Errorf("creating passphrase temp file: %w", err)
	}
	tmpPath := tmpPassphrase.Name()
	cleanupTemp := true
	defer func() {
		_ = tmpPassphrase.Close()
		if cleanupTemp {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmpPassphrase.Write(passphrase); err != nil {
		return "", fmt.Errorf("writing passphrase temp file: %w", err)
	}
	if err := tmpPassphrase.Chmod(0o600); err != nil {
		return "", fmt.Errorf("chmod passphrase temp file: %w", err)
	}
	if err := tmpPassphrase.Close(); err != nil {
		return "", fmt.Errorf("closing passphrase temp file: %w", err)
	}

	if err := os.Rename(tmpPath, passphrasePath); err != nil {
		return "", fmt.Errorf("writing passphrase file: %w", err)
	}
	cleanupTemp = false

	// Chown to service user (only needed in systemd mode where we run as root).
	if !isLocal {
		if err := chownToUser(passphrasePath, svc.User, svc.Group); err != nil {
			return "", fmt.Errorf("chown passphrase file: %w", err)
		}
	}

	// Write identity-scoped unlock config
	unlockCfg := &unlockconfig.UnlockConfig{
		PassphraseCommandArgv: []string{passFileBin, passphrasePath},
	}
	if err := unlockconfig.SaveUnlockConfig(dataDir, identityID, unlockCfg); err != nil {
		return "", fmt.Errorf("saving unlock config: %w", err)
	}
	if !isLocal {
		if err := setProdUnlockConfigPermissions(dataDir, identityID, svc); err != nil {
			return "", err
		}
	}

	var warning string
	if currentMethod == "systemd-creds" {
		if err := cleanupSystemdCreds(dataDir, identityID, isProdMode()); err != nil {
			warning = fmt.Sprintf("switched to passfile, but failed to remove old systemd-creds state: %v", err)
		}
	}

	return warning, nil
}

// executeSetSystemcreds sets up systemd-creds auto-unlock.
// This always requires root and a systemd service installation.
func executeSetSystemcreds(dataDir, identityID string, passphrase []byte, svc *serviceInfo) (string, error) {
	if err := requireSignerStopped(dataDir); err != nil {
		return "", err
	}

	currentMethod, err := currentAutoUnlockMethod(dataDir, identityID)
	if err != nil {
		return "", err
	}

	// Check systemd-creds is available
	if _, err := exec.LookPath("systemd-creds"); err != nil {
		return "", fmt.Errorf("systemd-creds not found; requires systemd >= 250")
	}

	// Check appass-systemd-creds binary exists
	passCredsBin := filepath.Join(svc.BinDir, "appass-systemd-creds")
	if _, err := os.Stat(passCredsBin); err != nil {
		return "", fmt.Errorf("appass-systemd-creds not found at %s; ensure it is installed alongside apsigner", passCredsBin)
	}

	identityDir := filepath.Join(dataDir, "identities", identityID)
	if err := os.MkdirAll(identityDir, 0700); err != nil {
		return "", fmt.Errorf("creating identity directory: %w", err)
	}

	// Encrypt passphrase via appass-systemd-creds write
	credFile := filepath.Join(identityDir, "passphrase.cred")
	tmpCredFile, err := os.CreateTemp(identityDir, "passphrase.cred.tmp-*")
	if err != nil {
		return "", fmt.Errorf("creating credential temp file: %w", err)
	}
	tmpCredPath := tmpCredFile.Name()
	_ = tmpCredFile.Close()
	cleanupTemp := true
	defer func() {
		if cleanupTemp {
			_ = os.Remove(tmpCredPath)
		}
	}()

	cmd := exec.Command(passCredsBin, "write", tmpCredPath)
	cmd.Stdin = bytes.NewReader(passphrase)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("appass-systemd-creds write failed: %w", err)
	}
	if !bytes.Equal(passphrase, out) {
		return "", fmt.Errorf("round-trip verification failed: encrypted passphrase does not match")
	}

	// Credential file must be root-owned
	if err := os.Chown(tmpCredPath, 0, 0); err != nil {
		return "", fmt.Errorf("chown credential file: %w", err)
	}
	if err := os.Chmod(tmpCredPath, 0600); err != nil {
		return "", fmt.Errorf("chmod credential file: %w", err)
	}
	if err := os.Rename(tmpCredPath, credFile); err != nil {
		return "", fmt.Errorf("install credential file: %w", err)
	}
	cleanupTemp = false

	if err := ensureLoadCredentialInService(credFile); err != nil {
		return "", err
	}

	// Write identity-scoped unlock config
	unlockCfg := &unlockconfig.UnlockConfig{
		PassphraseCommandArgv: []string{passCredsBin, credFile},
	}
	if err := unlockconfig.SaveUnlockConfig(dataDir, identityID, unlockCfg); err != nil {
		return "", fmt.Errorf("saving unlock config: %w", err)
	}
	if err := setProdUnlockConfigPermissions(dataDir, identityID, svc); err != nil {
		return "", err
	}

	var warning string
	if currentMethod == "passfile" {
		passFile := filepath.Join(identityDir, "passphrase")
		if _, err := os.Stat(passFile); err == nil {
			if err := os.Remove(passFile); err != nil {
				warning = fmt.Sprintf("switched to systemd-creds, but failed to remove old passphrase file: %v", err)
			}
		}
	}

	return warning, nil
}

// executeClear removes auto-unlock configuration and associated files.
func executeClear(dataDir, identityID string) (string, error) {
	if err := requireSignerStopped(dataDir); err != nil {
		return "", err
	}

	prodMode := isProdMode()

	// In systemd mode, require root.
	if prodMode && os.Getuid() != 0 {
		return "", fmt.Errorf("systemd mode: must be run as root (use sudo)")
	}

	method, err := currentAutoUnlockMethod(dataDir, identityID)
	if err != nil {
		return "", err
	}

	if method == "none" {
		return "", nil // nothing to clear
	}

	// Remove identity-scoped unlock config
	if err := unlockconfig.ClearUnlockConfig(dataDir, identityID); err != nil {
		return "", fmt.Errorf("clearing unlock config: %w", err)
	}

	// Method-specific cleanup
	identityDir := filepath.Join(dataDir, "identities", identityID)
	var warning string
	switch method {
	case "passfile":
		passFile := filepath.Join(identityDir, "passphrase")
		if _, err := os.Stat(passFile); err == nil {
			if err := os.Remove(passFile); err != nil {
				warning = fmt.Sprintf("switched to prompt mode, but failed to remove old passphrase file: %v", err)
			}
		}

	case "systemd-creds":
		if err := cleanupSystemdCreds(dataDir, identityID, prodMode); err != nil {
			warning = fmt.Sprintf("switched to prompt mode, but failed to remove old systemd-creds state: %v", err)
		}
	}

	return warning, nil
}

func currentAutoUnlockMethod(dataDir, identityID string) (string, error) {
	unlockCfg, err := unlockconfig.LoadUnlockConfig(dataDir, identityID)
	if err == nil && unlockCfg.HasPassphraseCommand() {
		return detectMethod(unlockCfg.PassphraseCommandArgv), nil
	}
	return "none", nil
}

func cleanupSystemdCreds(dataDir, identityID string, prodMode bool) error {
	if prodMode {
		if err := removeLoadCredentialFromService(); err != nil {
			return err
		}
	}

	credFile := filepath.Join(dataDir, "identities", identityID, "passphrase.cred")
	if _, err := os.Stat(credFile); err == nil {
		if err := os.Remove(credFile); err != nil {
			return fmt.Errorf("removing credential file: %w", err)
		}
	}
	return nil
}

// isProdMode returns true if a systemd service file exists.
func isProdMode() bool {
	for _, path := range candidateServiceFiles() {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	return false
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

func setProdUnlockConfigPermissions(dataDir, identityID string, svc *serviceInfo) error {
	if svc == nil {
		return fmt.Errorf("service info unavailable")
	}
	path := unlockconfig.UnlockConfigPath(dataDir, identityID)
	if err := chownToUser(path, svc.User, svc.Group); err != nil {
		return fmt.Errorf("chown unlock config: %w", err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		return fmt.Errorf("chmod unlock config: %w", err)
	}
	return nil
}

// removeLoadCredentialFromService removes any LoadCredentialEncrypted line
// from the systemd service file and runs daemon-reload.
func removeLoadCredentialFromService() error {
	servicePath := currentServiceFile()
	data, err := os.ReadFile(servicePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not read service file %s: %v\n", servicePath, err)
		return nil
	}

	var kept []string
	removed := false
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "LoadCredentialEncrypted") {
			removed = true
			continue
		}
		kept = append(kept, line)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading service file: %w", err)
	}

	if !removed {
		return nil
	}

	output := strings.Join(kept, "\n") + "\n"
	if err := os.WriteFile(servicePath, []byte(output), 0644); err != nil {
		return fmt.Errorf("writing service file: %w", err)
	}

	cmd := exec.Command("systemctl", "daemon-reload")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("daemon-reload failed: %w", err)
	}

	return nil
}

func ensureLoadCredentialInService(credFile string) error {
	servicePath := currentServiceFile()
	data, err := os.ReadFile(servicePath)
	if err != nil {
		return fmt.Errorf("reading service file %s: %w", servicePath, err)
	}

	loadLine := fmt.Sprintf("LoadCredentialEncrypted=%s:%s", systemdCredentialName, credFile)

	var output []string
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	inserted := false
	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "LoadCredentialEncrypted=") {
			if !inserted {
				output = append(output, loadLine)
				inserted = true
			}
			continue
		}

		output = append(output, line)
		if !inserted && strings.TrimSpace(line) == "[Service]" {
			output = append(output, loadLine)
			inserted = true
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading service file: %w", err)
	}

	if !inserted {
		return fmt.Errorf("service file %s has no [Service] section", servicePath)
	}

	updated := strings.Join(output, "\n") + "\n"
	if err := os.WriteFile(servicePath, []byte(updated), 0644); err != nil {
		return fmt.Errorf("writing service file: %w", err)
	}

	cmd := exec.Command("systemctl", "daemon-reload")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("daemon-reload failed: %w", err)
	}

	return nil
}
