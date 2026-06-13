// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package aplocalnet configures APlane for a local AlgoKit LocalNet.
package aplocalnet

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/plugin/discovery"
	"gopkg.in/yaml.v3"
)

const (
	NetworkID           = "localnet"
	PluginName          = "algokit-localnet"
	DefaultAlgodURL     = "http://localhost:4001"
	DefaultAlgodToken   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	DefaultApplyTimeout = 15 * time.Second
)

// Options controls LocalNet setup.
type Options struct {
	ClientDataDir string
	SignerDataDir string
	AlgodURL      string
	AlgodToken    string
	KMDURL        string
}

// LocalNetInfo describes the reachable LocalNet.
type LocalNetInfo struct {
	AlgodURL    string
	GenesisID   string
	GenesisHash string
	LastRound   uint64
}

// ApplyResult describes mutations made by Apply.
type ApplyResult struct {
	LocalNet                LocalNetInfo
	SignerConfigPath        string
	SignerConfigChanged     bool
	ClientConfigPath        string
	ClientConfigChanged     bool
	PluginConfigPath        string
	PluginActivationChanged bool
	PluginAvailable         bool
	EnvConfigPath           string
	EnvConfigChanged        bool
	Warnings                []string
}

// NormalizeOptions fills in LocalNet endpoint defaults.
func NormalizeOptions(opts Options) Options {
	opts.ClientDataDir = strings.TrimSpace(opts.ClientDataDir)
	opts.SignerDataDir = strings.TrimSpace(opts.SignerDataDir)
	opts.AlgodURL = NormalizeEndpointURL(firstNonEmpty(
		opts.AlgodURL,
		os.Getenv("APLANE_LOCALNET_ALGOD_URL"),
		DefaultAlgodURL,
	))
	opts.KMDURL = NormalizeEndpointURL(firstNonEmpty(
		opts.KMDURL,
		os.Getenv("APLANE_LOCALNET_KMD_URL"),
	))
	opts.AlgodToken = firstNonEmpty(
		opts.AlgodToken,
		os.Getenv("APLANE_LOCALNET_TOKEN"),
		DefaultAlgodToken,
	)
	return opts
}

// NormalizeEndpointURL trims user-supplied endpoint text while preserving the
// scheme, host, port, and path.
func NormalizeEndpointURL(raw string) string {
	raw = strings.TrimSpace(raw)
	return strings.TrimRight(raw, "/")
}

// CheckReachable confirms algod is reachable and returns its genesis metadata.
func CheckReachable(ctx context.Context, opts Options) (LocalNetInfo, error) {
	opts = NormalizeOptions(opts)
	if opts.AlgodURL == "" {
		return LocalNetInfo{}, fmt.Errorf("algod URL is required")
	}

	client, err := algod.MakeClient(opts.AlgodURL, opts.AlgodToken)
	if err != nil {
		return LocalNetInfo{}, fmt.Errorf("create algod client: %w", err)
	}

	status, err := client.Status().Do(ctx)
	if err != nil {
		return LocalNetInfo{}, fmt.Errorf("read algod status from %s: %w", opts.AlgodURL, err)
	}
	version, err := client.Versions().Do(ctx)
	if err != nil {
		return LocalNetInfo{}, fmt.Errorf("read algod versions from %s: %w", opts.AlgodURL, err)
	}

	genesisHash, err := apconfig.CanonicalGenesisHash(base64.StdEncoding.EncodeToString(version.GenesisHash))
	if err != nil {
		return LocalNetInfo{}, fmt.Errorf("localnet genesis hash from algod is invalid: %w", err)
	}

	return LocalNetInfo{
		AlgodURL:    opts.AlgodURL,
		GenesisID:   version.GenesisID,
		GenesisHash: genesisHash,
		LastRound:   status.LastRound,
	}, nil
}

// Apply checks LocalNet reachability and updates the explicitly supplied target
// data roots. A non-empty SignerDataDir updates apsigner config.yaml; a
// non-empty ClientDataDir updates apclient config/plugin/env state.
func Apply(ctx context.Context, opts Options) (ApplyResult, error) {
	opts = NormalizeOptions(opts)
	if opts.SignerDataDir == "" && opts.ClientDataDir == "" {
		return ApplyResult{}, fmt.Errorf("at least one of signer data directory or client data directory is required")
	}

	info, err := CheckReachable(ctx, opts)
	if err != nil {
		return ApplyResult{}, err
	}

	result := ApplyResult{
		LocalNet: info,
	}
	if opts.SignerDataDir != "" {
		signerChanged, signerPath, err := EnsureSignerLocalnetConfig(opts.SignerDataDir, info, opts.AlgodToken)
		if err != nil {
			return ApplyResult{}, err
		}
		result.SignerConfigPath = signerPath
		result.SignerConfigChanged = signerChanged
	}
	if opts.ClientDataDir != "" {
		clientChanged, clientPath, err := EnsureClientLocalnetConfig(opts.ClientDataDir, info, opts.AlgodToken)
		if err != nil {
			return ApplyResult{}, err
		}
		pluginChanged, pluginPath, err := EnsurePluginActivated(opts.ClientDataDir)
		if err != nil {
			return ApplyResult{}, err
		}
		envChanged, envPath, envWarnings, err := EnsureLocalnetEnvConfig(opts.ClientDataDir, opts.KMDURL)
		if err != nil {
			return ApplyResult{}, err
		}
		result.ClientConfigPath = clientPath
		result.ClientConfigChanged = clientChanged
		result.PluginConfigPath = pluginPath
		result.PluginActivationChanged = pluginChanged
		result.PluginAvailable = PluginAvailable(opts.ClientDataDir)
		result.EnvConfigPath = envPath
		result.EnvConfigChanged = envChanged
		if !result.PluginAvailable {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("%s is enabled but not installed under %s",
					PluginName,
					filepath.Join(opts.ClientDataDir, discovery.AvailableDirName, PluginName),
				),
			)
		}
		result.Warnings = append(result.Warnings, envWarnings...)
		result.Warnings = append(result.Warnings, clientConfigWarnings(opts.ClientDataDir)...)
	}
	return result, nil
}

// EnsureSignerLocalnetConfig writes networks.localnet algod and genesis_hash
// settings to apsigner config.yaml.
func EnsureSignerLocalnetConfig(dataDir string, info LocalNetInfo, algodToken string) (bool, string, error) {
	if dataDir == "" {
		return false, "", fmt.Errorf("signer data directory is required")
	}
	if err := requireDir(dataDir, "signer data directory"); err != nil {
		return false, "", err
	}
	canonicalGenesisHash, err := apconfig.CanonicalGenesisHash(info.GenesisHash)
	if err != nil {
		return false, "", fmt.Errorf("invalid localnet genesis hash: %w", err)
	}
	info.GenesisHash = canonicalGenesisHash

	path := filepath.Join(dataDir, "config.yaml")
	doc, err := loadYAMLDocument(path)
	if err != nil {
		return false, path, err
	}

	root, err := documentMapping(doc)
	if err != nil {
		return false, path, err
	}

	changed := false
	networks, didChange, err := ensureMappingValue(root, "networks")
	if err != nil {
		return false, path, err
	}
	changed = changed || didChange
	localnet, didChange, err := ensureMappingValue(networks, NetworkID)
	if err != nil {
		return false, path, err
	}
	changed = changed || didChange
	algodCfg, didChange, err := ensureMappingValue(localnet, "algod")
	if err != nil {
		return false, path, err
	}
	changed = changed || didChange

	changed = setScalarValue(algodCfg, "server", info.AlgodURL, 0) || changed
	changed = setScalarValue(algodCfg, "token", algodToken, yaml.DoubleQuotedStyle) || changed
	changed = setScalarValue(localnet, "genesis_hash", info.GenesisHash, yaml.DoubleQuotedStyle) || changed

	if !changed {
		return false, path, nil
	}
	if err := writeYAMLDocumentAtomic(path, doc, 0o640); err != nil {
		return false, path, fmt.Errorf("write signer config %s: %w", path, err)
	}
	return true, path, nil
}

// EnsureClientLocalnetConfig makes localnet the default apshell network and
// ensures its algod settings are present. Existing non-empty networks_allowed
// lists are extended so the new default remains valid.
func EnsureClientLocalnetConfig(clientDataDir string, info LocalNetInfo, algodToken string) (bool, string, error) {
	if clientDataDir == "" {
		return false, "", fmt.Errorf("client data directory is required")
	}
	if err := os.MkdirAll(clientDataDir, 0o755); err != nil {
		return false, "", fmt.Errorf("create client data directory %s: %w", clientDataDir, err)
	}

	path := apconfig.GetConfigPath(clientDataDir)
	doc, err := loadYAMLDocument(path)
	if err != nil {
		return false, path, err
	}
	root, err := documentMapping(doc)
	if err != nil {
		return false, path, err
	}

	changed := setScalarValue(root, "network", NetworkID, 0)
	if allowed := mappingValue(root, "networks_allowed"); allowed != nil {
		if allowed.Kind != yaml.SequenceNode {
			return false, path, fmt.Errorf("networks_allowed must be a sequence")
		}
		if len(allowed.Content) > 0 && !sequenceContainsScalar(allowed, NetworkID) {
			allowed.Content = append(allowed.Content, stringNode(NetworkID, 0))
			changed = true
		}
	}

	networks, didChange, err := ensureMappingValue(root, "networks")
	if err != nil {
		return false, path, err
	}
	changed = changed || didChange
	localnet, didChange, err := ensureMappingValue(networks, NetworkID)
	if err != nil {
		return false, path, err
	}
	changed = changed || didChange
	algodCfg, didChange, err := ensureMappingValue(localnet, "algod")
	if err != nil {
		return false, path, err
	}
	changed = changed || didChange

	changed = setScalarValue(algodCfg, "server", info.AlgodURL, 0) || changed
	changed = setScalarValue(algodCfg, "token", algodToken, yaml.DoubleQuotedStyle) || changed

	if !changed {
		return false, path, nil
	}
	if err := writeYAMLDocumentAtomic(path, doc, 0o644); err != nil {
		return false, path, fmt.Errorf("write client config %s: %w", path, err)
	}
	return true, path, nil
}

// EnsurePluginActivated adds algokit-localnet to APCLIENT_DATA/plugins.yaml.
func EnsurePluginActivated(clientDataDir string) (bool, string, error) {
	if clientDataDir == "" {
		return false, "", fmt.Errorf("client data directory is required")
	}
	if err := os.MkdirAll(clientDataDir, 0o755); err != nil {
		return false, "", fmt.Errorf("create client data directory %s: %w", clientDataDir, err)
	}

	path := filepath.Join(clientDataDir, discovery.ActivationConfigName)
	doc, err := loadYAMLDocument(path)
	if err != nil {
		return false, path, err
	}
	root, err := documentMapping(doc)
	if err != nil {
		return false, path, err
	}

	seq, changed, err := ensureSequenceValue(root, "enabled_plugins")
	if err != nil {
		return false, path, err
	}
	if err := validatePluginDirName(PluginName); err != nil {
		return false, path, err
	}

	for _, item := range seq.Content {
		if item.Kind != yaml.ScalarNode || item.Tag != "!!str" {
			return false, path, fmt.Errorf("enabled_plugins contains a non-string value")
		}
		if err := validatePluginDirName(item.Value); err != nil {
			return false, path, fmt.Errorf("invalid enabled plugin name %q: %w", item.Value, err)
		}
		if item.Value == PluginName {
			if !changed {
				return false, path, nil
			}
			break
		}
	}
	if !sequenceContainsScalar(seq, PluginName) {
		seq.Content = append(seq.Content, stringNode(PluginName, 0))
		changed = true
	}

	if !changed {
		return false, path, nil
	}
	if err := writeYAMLDocumentAtomic(path, doc, 0o644); err != nil {
		return false, path, fmt.Errorf("write plugin activation config %s: %w", path, err)
	}
	return true, path, nil
}

// EnsureLocalnetEnvConfig persists plugin-only LocalNet endpoint overrides in
// the install environment script so apconsole passes them to plugin processes
// after restart. Empty kmdURL means no plugin env override is required.
func EnsureLocalnetEnvConfig(clientDataDir string, kmdURL string) (bool, string, []string, error) {
	kmdURL = NormalizeEndpointURL(kmdURL)
	if kmdURL == "" {
		return false, "", nil, nil
	}
	envPath, ok := findEnvScript(clientDataDir)
	if !ok {
		return false, "", []string{
			fmt.Sprintf("KMD URL override was not persisted; export APLANE_LOCALNET_KMD_URL=%s before starting apconsole", kmdURL),
		}, nil
	}

	data, err := os.ReadFile(envPath)
	if err != nil {
		return false, envPath, nil, fmt.Errorf("read env config %s: %w", envPath, err)
	}

	line := fmt.Sprintf("export APLANE_LOCALNET_KMD_URL=%s", shellQuote(kmdURL))
	updated, changed := setShellExportLine(string(data), "APLANE_LOCALNET_KMD_URL", line)
	if !changed {
		return false, envPath, nil, nil
	}
	if err := writeFileAtomic(envPath, []byte(updated), 0o644); err != nil {
		return false, envPath, nil, fmt.Errorf("write env config %s: %w", envPath, err)
	}
	return true, envPath, nil, nil
}

// PluginAvailable reports whether the LocalNet plugin payload is installed in
// the client plugin catalog.
func PluginAvailable(clientDataDir string) bool {
	if clientDataDir == "" {
		return false
	}
	info, err := os.Stat(filepath.Join(clientDataDir, discovery.AvailableDirName, PluginName))
	return err == nil && info.IsDir()
}

func findEnvScript(clientDataDir string) (string, bool) {
	clientDataDir = strings.TrimSpace(clientDataDir)
	if clientDataDir == "" {
		return "", false
	}
	candidates := []string{
		filepath.Join(filepath.Dir(clientDataDir), "apenv.sh"),
		filepath.Join(clientDataDir, "apenv.sh"),
	}
	for _, path := range candidates {
		info, err := os.Stat(path)
		if err == nil && !info.IsDir() {
			return path, true
		}
	}
	return "", false
}

func setShellExportLine(text string, name string, line string) (string, bool) {
	lines := strings.SplitAfter(text, "\n")
	prefix := "export " + name + "="
	changed := false
	replaced := false
	for i, existing := range lines {
		trimmed := strings.TrimSpace(existing)
		if strings.HasPrefix(trimmed, prefix) {
			replaced = true
			newLine := line + "\n"
			if existing == newLine {
				continue
			}
			lines[i] = newLine
			changed = true
		}
	}
	if !replaced {
		if len(lines) == 0 {
			lines = append(lines, line+"\n")
		} else {
			if text != "" && !strings.HasSuffix(text, "\n") {
				lines = append(lines, "\n")
			}
			lines = append(lines, line+"\n")
		}
		changed = true
	}
	return strings.Join(lines, ""), changed
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func clientConfigWarnings(clientDataDir string) []string {
	if clientDataDir == "" {
		return nil
	}
	cfg, err := apconfig.LoadConfig(clientDataDir)
	if err != nil {
		return []string{fmt.Sprintf("could not inspect apclient config.yaml: %v", err)}
	}
	if len(cfg.NetworksAllowed) > 0 && !cfg.IsNetworkAllowed(NetworkID) {
		return []string{
			fmt.Sprintf("%s is not listed in %s networks_allowed; apshell cannot switch to localnet until it is added",
				NetworkID,
				apconfig.GetConfigPath(clientDataDir),
			),
		}
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func requireDir(path, label string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%s %s is not accessible: %w", label, path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s %s is not a directory", label, path)
	}
	return nil
}

func loadYAMLDocument(path string) (*yaml.Node, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return emptyYAMLDocument(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("read YAML file %s: %w", path, err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return emptyYAMLDocument(), nil
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse YAML file %s: %w", path, err)
	}
	return &doc, nil
}

func emptyYAMLDocument() *yaml.Node {
	return &yaml.Node{
		Kind: yaml.DocumentNode,
		Content: []*yaml.Node{{
			Kind: yaml.MappingNode,
			Tag:  "!!map",
		}},
	}
}

func documentMapping(doc *yaml.Node) (*yaml.Node, error) {
	if doc.Kind == 0 {
		*doc = *emptyYAMLDocument()
	}
	if doc.Kind != yaml.DocumentNode {
		return nil, fmt.Errorf("YAML root must be a document")
	}
	if len(doc.Content) == 0 {
		doc.Content = append(doc.Content, &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"})
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("YAML root must be a mapping")
	}
	return root, nil
}

func ensureMappingValue(parent *yaml.Node, key string) (*yaml.Node, bool, error) {
	value := mappingValue(parent, key)
	if value == nil {
		node := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		parent.Content = append(parent.Content, stringNode(key, 0), node)
		return node, true, nil
	}
	if value.Kind != yaml.MappingNode {
		return nil, false, fmt.Errorf("%s must be a mapping", key)
	}
	return value, false, nil
}

func ensureSequenceValue(parent *yaml.Node, key string) (*yaml.Node, bool, error) {
	value := mappingValue(parent, key)
	if value == nil {
		node := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		parent.Content = append(parent.Content, stringNode(key, 0), node)
		return node, true, nil
	}
	if value.Kind != yaml.SequenceNode {
		return nil, false, fmt.Errorf("%s must be a sequence", key)
	}
	return value, false, nil
}

func mappingValue(parent *yaml.Node, key string) *yaml.Node {
	if parent == nil || parent.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(parent.Content); i += 2 {
		if parent.Content[i].Value == key {
			return parent.Content[i+1]
		}
	}
	return nil
}

func setScalarValue(parent *yaml.Node, key, value string, style yaml.Style) bool {
	existing := mappingValue(parent, key)
	if existing == nil {
		parent.Content = append(parent.Content, stringNode(key, 0), stringNode(value, style))
		return true
	}
	if existing.Kind != yaml.ScalarNode || existing.Value != value || existing.Tag != "!!str" {
		*existing = *stringNode(value, style)
		return true
	}
	if style != 0 && existing.Style != style {
		existing.Style = style
		return true
	}
	return false
}

func stringNode(value string, style yaml.Style) *yaml.Node {
	return &yaml.Node{
		Kind:  yaml.ScalarNode,
		Tag:   "!!str",
		Value: value,
		Style: style,
	}
}

func sequenceContainsScalar(seq *yaml.Node, value string) bool {
	for _, item := range seq.Content {
		if item.Kind == yaml.ScalarNode && item.Value == value {
			return true
		}
	}
	return false
}

func validatePluginDirName(name string) error {
	if name == "" {
		return fmt.Errorf("name is empty")
	}
	if name == "." || name == ".." || filepath.Clean(name) != name {
		return fmt.Errorf("name must be a single directory name")
	}
	if strings.ContainsAny(name, `/\`) {
		return fmt.Errorf("name must not contain path separators")
	}
	return nil
}

func writeYAMLDocumentAtomic(path string, doc *yaml.Node, mode os.FileMode) error {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		_ = enc.Close()
		return fmt.Errorf("marshal YAML: %w", err)
	}
	if err := enc.Close(); err != nil {
		return fmt.Errorf("marshal YAML: %w", err)
	}
	return writeFileAtomic(path, buf.Bytes(), mode)
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		_ = tmp.Close()
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	targetMode := mode
	var targetUID, targetGID int
	hasOwnership := false
	if info, err := os.Stat(path); err == nil {
		targetMode = info.Mode().Perm()
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			targetUID = int(stat.Uid)
			targetGID = int(stat.Gid)
			hasOwnership = true
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Chmod(targetMode); err != nil {
		return err
	}
	// Only root can chown to another user; a non-root process rewriting a
	// group-writable file owned by someone else should not abort the write
	// over an EPERM it can never avoid.
	if hasOwnership && os.Getuid() == 0 && (os.Getuid() != targetUID || os.Getgid() != targetGID) {
		if err := tmp.Chown(targetUID, targetGID); err != nil {
			return err
		}
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}
