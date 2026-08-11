// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aplane-algo/aplane/internal/adminipc"
	"gopkg.in/yaml.v3"
)

const consoleProfileName = "apconsole.yaml"

type consoleMode string

const (
	consoleModeLocal  consoleMode = "local"
	consoleModeRemote consoleMode = "remote"
)

type consoleProfile struct {
	Mode       consoleMode `yaml:"mode"`
	ClientData string      `yaml:"client_data"`
	SignerData string      `yaml:"signer_data"`
}

type consoleStartupConfig struct {
	Mode        consoleMode
	ClientData  string
	SignerData  string
	ProfilePath string
	Notices     []string

	modeSource       consoleValueSource
	clientDataSource consoleValueSource
	signerDataSource consoleValueSource
}

type consoleStartupFlags struct {
	ConfigPath       string
	RemoteSet        bool
	Remote           bool
	SignerDataSet    bool
	SignerData       string
	ClientDataSet    bool
	ClientData       string
	CurrentDir       string
	ExecutablePath   string
	ClientDataEnv    string
	SignerDataEnv    string
	ConsoleConfigEnv string
}

type consoleValueSource struct {
	label                   string
	explicit                bool
	overridesIPCEnvironment bool
}

func resolveConsoleStartup(flags consoleStartupFlags) (consoleStartupConfig, error) {
	profile, profilePath, profileSource, err := loadDiscoveredConsoleProfile(flags)
	if err != nil {
		return consoleStartupConfig{}, err
	}

	cfg := consoleStartupConfig{
		Mode:             consoleModeLocal,
		ProfilePath:      profilePath,
		modeSource:       consoleValueSource{label: "default mode"},
		clientDataSource: consoleValueSource{},
		signerDataSource: consoleValueSource{},
	}
	if profile != nil {
		if err := applyConsoleMode(&cfg, profile.Mode, profileSource); err != nil {
			return consoleStartupConfig{}, err
		}
		if err := applyConsolePath(&cfg.ClientData, &cfg.clientDataSource, profile.ClientData, profileSource, "client_data", &cfg.Notices); err != nil {
			return consoleStartupConfig{}, err
		}
		if err := applyConsolePath(&cfg.SignerData, &cfg.signerDataSource, profile.SignerData, profileSource, "signer_data", &cfg.Notices); err != nil {
			return consoleStartupConfig{}, err
		}
	}

	if flags.ClientDataEnv != "" {
		if err := applyConsolePath(&cfg.ClientData, &cfg.clientDataSource, flags.ClientDataEnv, consoleValueSource{
			label:    "environment APCLIENT_DATA",
			explicit: true,
		}, "client_data", &cfg.Notices); err != nil {
			return consoleStartupConfig{}, err
		}
	}
	if flags.SignerDataEnv != "" {
		if err := applyConsolePath(&cfg.SignerData, &cfg.signerDataSource, flags.SignerDataEnv, consoleValueSource{
			label:    "environment APSIGNER_DATA",
			explicit: true,
		}, "signer_data", &cfg.Notices); err != nil {
			return consoleStartupConfig{}, err
		}
	}

	if flags.RemoteSet {
		mode := consoleModeLocal
		if flags.Remote {
			mode = consoleModeRemote
		}
		if err := applyConsoleMode(&cfg, mode, consoleValueSource{
			label:    "flag -remote",
			explicit: true,
		}); err != nil {
			return consoleStartupConfig{}, err
		}
	}
	if flags.ClientDataSet {
		if err := applyConsolePath(&cfg.ClientData, &cfg.clientDataSource, flags.ClientData, consoleValueSource{
			label:    "flag -client-data",
			explicit: true,
		}, "client_data", &cfg.Notices); err != nil {
			return consoleStartupConfig{}, err
		}
	}
	if flags.SignerDataSet {
		if err := applyConsolePath(&cfg.SignerData, &cfg.signerDataSource, flags.SignerData, consoleValueSource{
			label:                   "flag -d",
			explicit:                true,
			overridesIPCEnvironment: true,
		}, "signer_data", &cfg.Notices); err != nil {
			return consoleStartupConfig{}, err
		}
	}

	return cfg, nil
}

func applyConsoleMode(cfg *consoleStartupConfig, mode consoleMode, source consoleValueSource) error {
	if mode == "" {
		return nil
	}
	if err := applyConsoleValue((*string)(&cfg.Mode), &cfg.modeSource, string(mode), source, "mode", &cfg.Notices); err != nil {
		return err
	}
	cfg.Mode = consoleMode(cfg.Mode)
	return nil
}

func applyConsolePath(current *string, currentSource *consoleValueSource, incoming string, incomingSource consoleValueSource, field string, notices *[]string) error {
	return applyConsoleValue(current, currentSource, incoming, incomingSource, field, notices)
}

func applyConsoleValue(current *string, currentSource *consoleValueSource, incoming string, incomingSource consoleValueSource, field string, notices *[]string) error {
	if incoming == "" {
		return nil
	}
	if *current != "" && *current != incoming && currentSource.explicit && incomingSource.explicit {
		return fmt.Errorf("conflicting %s values: %q from %s and %q from %s; remove one input or make them match", field, *current, currentSource.label, incoming, incomingSource.label)
	}
	if *current != "" && *current != incoming && currentSource.label != "" {
		*notices = append(*notices, fmt.Sprintf("using %s %q from %s; ignoring conflicting %q from %s", field, incoming, incomingSource.label, *current, currentSource.label))
	}
	*current = incoming
	*currentSource = incomingSource
	return nil
}

func loadDiscoveredConsoleProfile(flags consoleStartupFlags) (*consoleProfile, string, consoleValueSource, error) {
	if flags.ConfigPath != "" {
		profile, err := loadConsoleProfile(flags.ConfigPath)
		if err != nil {
			return nil, "", consoleValueSource{}, err
		}
		return profile, flags.ConfigPath, consoleValueSource{
			label:                   fmt.Sprintf("profile %s selected by -config", flags.ConfigPath),
			explicit:                true,
			overridesIPCEnvironment: true,
		}, nil
	}
	if flags.ConsoleConfigEnv != "" {
		profile, err := loadConsoleProfile(flags.ConsoleConfigEnv)
		if err != nil {
			return nil, "", consoleValueSource{}, err
		}
		return profile, flags.ConsoleConfigEnv, consoleValueSource{
			label:                   fmt.Sprintf("profile %s selected by APCONSOLE_CONFIG", flags.ConsoleConfigEnv),
			explicit:                true,
			overridesIPCEnvironment: true,
		}, nil
	}

	for _, path := range consoleProfileCandidates(flags) {
		if _, err := os.Stat(path); err == nil {
			profile, err := loadConsoleProfile(path)
			if err != nil {
				return nil, "", consoleValueSource{}, err
			}
			return profile, path, consoleValueSource{
				label:    fmt.Sprintf("auto-discovered profile %s", path),
				explicit: false,
			}, nil
		} else if !os.IsNotExist(err) {
			return nil, "", consoleValueSource{}, fmt.Errorf("failed to inspect apconsole profile %s: %w", path, err)
		}
	}
	return nil, "", consoleValueSource{}, nil
}

func resolveConsoleIPCPath(dataDir, ipcPath string, source consoleValueSource) (string, error) {
	return adminipc.ResolveClientPath(adminipc.ClientPathRequest{
		DataDir: dataDir, IPCPath: ipcPath, DataDirExplicit: source.overridesIPCEnvironment,
	})
}

func loadConsoleProfile(path string) (*consoleProfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read apconsole profile %s: %w", path, err)
	}

	var profile consoleProfile
	if err := yaml.Unmarshal(data, &profile); err != nil {
		return nil, fmt.Errorf("failed to parse apconsole profile %s: %w", path, err)
	}
	if profile.Mode == "" {
		profile.Mode = consoleModeLocal
	}
	switch profile.Mode {
	case consoleModeLocal:
		if profile.SignerData == "" {
			return nil, fmt.Errorf("invalid apconsole profile %s: signer_data is required for local mode", path)
		}
	case consoleModeRemote:
	default:
		return nil, fmt.Errorf("invalid apconsole profile %s: mode must be local or remote", path)
	}
	if profile.ClientData == "" {
		return nil, fmt.Errorf("invalid apconsole profile %s: client_data is required", path)
	}

	baseDir := filepath.Dir(path)
	profile.ClientData = resolveProfilePath(baseDir, profile.ClientData)
	profile.SignerData = resolveProfilePath(baseDir, profile.SignerData)
	return &profile, nil
}

func consoleProfileCandidates(flags consoleStartupFlags) []string {
	var candidates []string
	addRoot := func(root string) {
		if root == "" {
			return
		}
		candidates = append(candidates, filepath.Join(root, consoleProfileName))
	}

	addRoot(flags.CurrentDir)
	addRoot(profileRootFromRolePath(flags.CurrentDir))
	addRoot(profileRootFromRolePath(flags.ClientDataEnv))
	addRoot(profileRootFromRolePath(flags.SignerDataEnv))
	addRoot(profileRootFromExecutable(flags.ExecutablePath))

	return uniqueStrings(candidates)
}

func profileRootFromRolePath(path string) string {
	if path == "" {
		return ""
	}
	clean := filepath.Clean(path)
	base := filepath.Base(clean)
	if base == "apclient" || base == "apsigner" {
		return filepath.Dir(clean)
	}
	if base == "bin" {
		parent := filepath.Dir(clean)
		parentBase := filepath.Base(parent)
		if parentBase == "apclient" || parentBase == "apsigner" {
			return filepath.Dir(parent)
		}
	}
	return ""
}

func profileRootFromExecutable(path string) string {
	if path == "" {
		return ""
	}
	return profileRootFromRolePath(filepath.Dir(path))
}

func resolveProfilePath(baseDir, path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Clean(filepath.Join(baseDir, path))
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	var out []string
	for _, value := range values {
		if value == "" {
			continue
		}
		clean := filepath.Clean(value)
		key := clean
		if !filepath.IsAbs(key) {
			if abs, err := filepath.Abs(key); err == nil {
				key = abs
			}
		}
		key = strings.TrimRight(key, string(filepath.Separator))
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, clean)
	}
	return out
}
