// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/signerapp/unlockconfig"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

const systemdCredentialName = "aplane-passphrase"

// commandTimeout bounds each external command an action runs. The working
// screen ignores keys until the action is done, so a hung systemctl or
// systemd-creds must end the action with an error rather than hold appass.
// commandWaitDelay bounds the wait for its output once it is stopped. Tests
// shorten both.
var (
	commandTimeout   = time.Minute
	commandWaitDelay = 5 * time.Second
)

// boundedCommand returns the command name with args, stopped if it runs
// longer than commandTimeout, and a finish function that releases it and
// reports a stop as a timeout.
func boundedCommand(name string, args ...string) (*exec.Cmd, func(error) error) {
	timeout := commandTimeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = commandWaitDelay
	return cmd, func(err error) error {
		defer cancel()
		if err != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("%s did not finish within %s and was stopped: %w", filepath.Base(name), timeout, err)
		}
		return err
	}
}

// daemonReload makes systemd reread the unit appass just edited.
func daemonReload() error {
	cmd, finish := boundedCommand("systemctl", "daemon-reload")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := finish(cmd.Run()); err != nil {
		return fmt.Errorf("daemon-reload failed: %w", err)
	}
	return nil
}

// errEmptyPassphrase refuses an auto-unlock secret that could never unlock
// the store: the signer refuses an empty passphrase.
var errEmptyPassphrase = errors.New("passphrase must not be empty")

// executeSetPassfile sets up appass-file auto-unlock.
// passphrase is the raw passphrase bytes. svc and isLocal describe the environment.
func executeSetPassfile(dataDir string, passphrase []byte, svc *serviceInfo, isLocal bool) (string, error) {
	if len(passphrase) == 0 {
		return "", errEmptyPassphrase
	}
	if err := requireSignerStopped(dataDir); err != nil {
		return "", err
	}

	state, err := loadUnlockState(dataDir)
	if err != nil {
		return "", err
	}

	// In systemd mode, require root.
	if !isLocal && os.Getuid() != 0 {
		return "", fmt.Errorf("systemd mode: must be run as root (use sudo)")
	}

	// Guard unexpected service state. A managed systemd-creds -> passfile migration is allowed.
	if !isLocal && svc.HasLoadCred && !state.cleanSystemdCreds {
		return "", fmt.Errorf("service has LoadCredentialEncrypted but config is not in systemd-creds mode; clear the service state before switching to passfile")
	}

	// Check appass-file binary exists
	passFileBin := filepath.Join(svc.BinDir, "appass-file")
	if _, err := os.Stat(passFileBin); err != nil {
		return "", fmt.Errorf("appass-file not found at %s; ensure it is installed alongside apsigner", passFileBin)
	}

	// Write the passphrase file to the product store.
	identityDir := storepaths.NewPaths(dataDir).ProductDir()
	if err := os.MkdirAll(identityDir, 0700); err != nil {
		return "", fmt.Errorf("creating identity directory: %w", err)
	}
	passphrasePath := filepath.Join(identityDir, "passphrase")
	var serviceUID, serviceGID int
	if !isLocal {
		serviceUID, serviceGID = svc.StoreUID, svc.StoreGID
		if err := fsutil.WriteServiceOwnedFileDurable(passphrasePath, passphrase, serviceUID, serviceGID); err != nil {
			return "", fmt.Errorf("writing service-owned passphrase file: %w", err)
		}
	} else if err := fsutil.WriteFileDurable(passphrasePath, passphrase); err != nil {
		return "", fmt.Errorf("writing passphrase file: %w", err)
	}

	// Write the product store's unlock config.
	unlockCfg := &unlockconfig.UnlockConfig{
		PassphraseCommandArgv: []string{passFileBin, passphrasePath},
	}
	if !isLocal {
		err = unlockconfig.SaveUnlockConfigForService(dataDir, unlockCfg, serviceUID, serviceGID)
	} else {
		err = unlockconfig.SaveUnlockConfig(dataDir, unlockCfg)
	}
	if err != nil {
		return "", fmt.Errorf("saving unlock config: %w", err)
	}

	var warning string
	if state.cleanSystemdCreds {
		if err := cleanupSystemdCreds(dataDir, isLocal); err != nil {
			warning = fmt.Sprintf("switched to passfile, but failed to remove old systemd-creds state: %v", err)
		}
	}

	return warning, nil
}

// executeSetSystemcreds sets up systemd-creds auto-unlock.
// This always requires root and a systemd service installation.
func executeSetSystemcreds(dataDir string, passphrase []byte, svc *serviceInfo) (string, error) {
	if len(passphrase) == 0 {
		return "", errEmptyPassphrase
	}
	if err := requireSignerStopped(dataDir); err != nil {
		return "", err
	}

	state, err := loadUnlockState(dataDir)
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

	identityDir := storepaths.NewPaths(dataDir).ProductDir()
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
	defer func() { _ = os.Remove(tmpCredPath) }()

	cmd, finish := boundedCommand(passCredsBin, "write", tmpCredPath)
	cmd.Stdin = bytes.NewReader(passphrase)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	err = finish(err)
	// out is the passphrase read back for the round-trip check.
	defer clear(out)
	if err != nil {
		return "", fmt.Errorf("appass-systemd-creds write failed: %w", err)
	}
	if !bytes.Equal(passphrase, out) {
		return "", fmt.Errorf("round-trip verification failed: encrypted passphrase does not match")
	}

	credentialBytes, _, err := fsutil.ReadRegularFileLimited(tmpCredPath, 1024*1024)
	if err != nil {
		return "", fmt.Errorf("read generated credential file: %w", err)
	}
	if err := fsutil.WriteFileDurableWithProfile(credFile, credentialBytes, fsutil.RootCredentialFileProfile); err != nil {
		return "", fmt.Errorf("install credential file: %w", err)
	}

	if err := ensureLoadCredentialInService(credFile); err != nil {
		return "", err
	}

	// Write the product store's unlock config.
	unlockCfg := &unlockconfig.UnlockConfig{
		PassphraseCommandArgv: []string{passCredsBin, credFile},
	}
	serviceUID, serviceGID := svc.StoreUID, svc.StoreGID
	if err := unlockconfig.SaveUnlockConfigForService(dataDir, unlockCfg, serviceUID, serviceGID); err != nil {
		return "", fmt.Errorf("saving unlock config: %w", err)
	}

	var warning string
	if state.cleanPassfile {
		if err := removePassphraseFile(identityDir); err != nil {
			warning = fmt.Sprintf("switched to systemd-creds, but failed to remove old passphrase file: %v", err)
		}
	}

	return warning, nil
}

// executeClear removes auto-unlock configuration and associated files.
// isLocal is the data directory's own mode, as for the other actions.
func executeClear(dataDir string, isLocal bool) (string, error) {
	if err := requireSignerStopped(dataDir); err != nil {
		return "", err
	}

	// In systemd mode, require root.
	if !isLocal && os.Getuid() != 0 {
		return "", fmt.Errorf("systemd mode: must be run as root (use sudo)")
	}

	state, err := loadUnlockState(dataDir)
	if err != nil {
		return "", err
	}

	if state.method == unlockconfig.MethodNone {
		return "", nil // nothing to clear
	}

	// Remove the product store's unlock config.
	if err := unlockconfig.ClearUnlockConfig(dataDir); err != nil {
		return "", fmt.Errorf("clearing unlock config: %w", err)
	}

	// Method-specific cleanup. Every failure is reported: a plaintext passphrase
	// left on disk must never be hidden behind another warning.
	identityDir := storepaths.NewPaths(dataDir).ProductDir()
	var warnings []string
	if state.cleanPassfile {
		if err := removePassphraseFile(identityDir); err != nil {
			warnings = append(warnings, fmt.Sprintf("failed to remove old passphrase file: %v", err))
		}
	}
	if state.cleanSystemdCreds {
		if err := cleanupSystemdCreds(dataDir, isLocal); err != nil {
			warnings = append(warnings, fmt.Sprintf("failed to remove old systemd-creds state: %v", err))
		}
	}
	if len(warnings) == 0 {
		return "", nil
	}
	return "switched to prompt mode, but " + strings.Join(warnings, "; "), nil
}

// methodUnreadable is an unlock.yaml that does not parse. The actions still
// replace or clear it, so appass can repair it.
const methodUnreadable = "unreadable"

// methodReadError is an unlock.yaml that exists but cannot be read, for
// example for permissions. The actions refuse it, so appass offers none.
const methodReadError = "read-error"

// currentAutoUnlockMethod reports the configured auto-unlock method. An
// unlock.yaml that does not parse is methodUnreadable, with the reason. Any
// other read failure returns no method, and the actions stop.
func currentAutoUnlockMethod(dataDir string) (string, error) {
	unlockCfg, err := unlockconfig.LoadUnlockConfig(dataDir)
	if errors.Is(err, unlockconfig.ErrMalformed) {
		return methodUnreadable, err
	}
	if err != nil {
		return "", err
	}
	return unlockCfg.Method(), nil
}

// unlockState is the auto-unlock method on disk and which method's files a
// change must clean up. Either method may have left files behind an
// unreadable unlock.yaml, so both are cleaned.
type unlockState struct {
	method            string
	cleanPassfile     bool
	cleanSystemdCreds bool
}

func loadUnlockState(dataDir string) (unlockState, error) {
	method, err := currentAutoUnlockMethod(dataDir)
	if err != nil && method != methodUnreadable {
		return unlockState{}, err
	}
	return unlockState{
		method:            method,
		cleanPassfile:     method == unlockconfig.MethodPassfile || method == methodUnreadable,
		cleanSystemdCreds: method == unlockconfig.MethodSystemdCreds || method == methodUnreadable,
	}, nil
}

// removePassphraseFile removes the passfile method's plaintext passphrase.
func removePassphraseFile(identityDir string) error {
	err := os.Remove(filepath.Join(identityDir, "passphrase"))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// cleanupSystemdCreds removes the systemd-creds method's credential file and,
// for a systemd-managed data directory, its line in the apsigner unit. A local
// data directory has no unit of its own, so a unit on the host belongs to
// another store and is left alone.
func cleanupSystemdCreds(dataDir string, isLocal bool) error {
	if !isLocal {
		if err := removeLoadCredentialFromService(); err != nil {
			return err
		}
	}

	credFile := filepath.Join(storepaths.NewPaths(dataDir).ProductDir(), "passphrase.cred")
	if _, err := os.Stat(credFile); err == nil {
		if err := os.Remove(credFile); err != nil {
			return fmt.Errorf("removing credential file: %w", err)
		}
	}
	return nil
}

func lookupUserGroupIDs(username, groupname string) (int, int, error) {
	u, err := user.Lookup(username)
	if err != nil {
		return 0, 0, fmt.Errorf("looking up user %q: %w", username, err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, fmt.Errorf("parsing uid: %w", err)
	}

	g, err := user.LookupGroup(groupname)
	if err != nil {
		return 0, 0, fmt.Errorf("looking up group %q: %w", groupname, err)
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return 0, 0, fmt.Errorf("parsing gid: %w", err)
	}
	return uid, gid, nil
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

	if err := daemonReload(); err != nil {
		return err
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

	if err := daemonReload(); err != nil {
		return err
	}

	return nil
}
