// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package storeperm owns the signer-store filesystem trust policy.
package storeperm

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aplane-algo/aplane/internal/fsutil"
)

// profile selects one complete signer-store permission contract.
type profile uint8

const (
	// legacySharedProfile audits the transitional 2770/0660 group-shared
	// layout. It exists only to validate inputs before migration.
	legacySharedProfile profile = iota
	// privateServiceProfile audits the service-user-only 0700/0600 layout.
	privateServiceProfile
)

// AuditOptions is an opaque, complete read-only store policy. Callers obtain
// one from an operation-specific constructor so socket and ancestor
// exceptions cannot be assembled piecemeal.
type AuditOptions struct{ policy options }

// MigrationOptions is an opaque stopped-store migration policy. It is a
// distinct type because a removable legacy socket is not an audit exception.
type MigrationOptions struct{ policy options }

type options struct {
	root             string
	expectedUID      int
	expectedGID      int
	profile          profile
	socketPath       string
	ancestorBoundary string
}

// ProductionAuditOptions rejects every in-store socket and inspects ancestors
// through the filesystem root.
func ProductionAuditOptions(root string, expectedUID, expectedGID int) AuditOptions {
	return AuditOptions{policy: options{
		root: root, expectedUID: expectedUID, expectedGID: expectedGID,
		profile: privateServiceProfile,
	}}
}

// SameUIDAuditOptions recognizes one exact live socket while retaining the
// full ancestor walk. The socket may be inspected but is never removed.
func SameUIDAuditOptions(root string, expectedUID, expectedGID int, socketPath string) AuditOptions {
	return AuditOptions{policy: options{
		root: root, expectedUID: expectedUID, expectedGID: expectedGID,
		profile: privateServiceProfile, socketPath: socketPath,
	}}
}

// TrustedBoundaryAuditOptions is the explicit embedder/test policy for a root
// below a separately validated ancestor. Normal product callers do not use it.
func TrustedBoundaryAuditOptions(root string, expectedUID, expectedGID int, socketPath, boundary string) AuditOptions {
	return AuditOptions{policy: options{
		root: root, expectedUID: expectedUID, expectedGID: expectedGID,
		profile: privateServiceProfile, socketPath: socketPath, ancestorBoundary: boundary,
	}}
}

// LegacyMigrationOptions recognizes one exact stale in-store socket that a
// stopped migration may remove after complete inventory validation.
func LegacyMigrationOptions(root string, expectedUID, expectedGID int, socketPath string) MigrationOptions {
	return MigrationOptions{policy: options{
		root: root, expectedUID: expectedUID, expectedGID: expectedGID,
		profile: legacySharedProfile, socketPath: socketPath,
	}}
}

// TrustedBoundaryMigrationOptions is the explicit embedder/test migration
// policy below a separately validated ancestor. Product migrations use
// LegacyMigrationOptions and inspect ancestors through the filesystem root.
func TrustedBoundaryMigrationOptions(root string, expectedUID, expectedGID int, socketPath, boundary string) MigrationOptions {
	opts := LegacyMigrationOptions(root, expectedUID, expectedGID, socketPath)
	opts.policy.ancestorBoundary = boundary
	return opts
}

// Finding is one independently actionable filesystem-policy violation.
type Finding struct {
	Path   string
	Code   string
	Detail string
}

func (f Finding) Error() string {
	return fmt.Sprintf("%s: %s (%s)", f.Path, f.Detail, f.Code)
}

type profilePolicy struct {
	dirMode        os.FileMode
	fileMode       os.FileMode
	allowDirSetgid bool
}

type artifactExpectation struct {
	uid            int
	gid            int
	mode           os.FileMode
	allowDirSetgid bool
	wantDir        bool
	wantRegular    bool
}

func policyForProfile(profile profile) (profilePolicy, error) {
	switch profile {
	case legacySharedProfile:
		return profilePolicy{dirMode: 0o770, fileMode: 0o660, allowDirSetgid: true}, nil
	case privateServiceProfile:
		return profilePolicy{dirMode: 0o700, fileMode: 0o600}, nil
	default:
		return profilePolicy{}, fmt.Errorf("unknown store permission profile %d", profile)
	}
}

// Audit performs a read-only, no-symlink-traversal inspection. Findings are
// returned in path/code order. A non-nil error means the inventory could not
// be completed and its result must not authorize migration or startup.
func Audit(opts AuditOptions) ([]Finding, error) {
	return audit(opts.policy)
}

func audit(opts options) ([]Finding, error) {
	policy, err := policyForProfile(opts.profile)
	if err != nil {
		return nil, err
	}
	if opts.root == "" {
		return nil, fmt.Errorf("store root is required")
	}
	root, err := filepath.Abs(filepath.Clean(opts.root))
	if err != nil {
		return nil, fmt.Errorf("resolve store root: %w", err)
	}
	if opts.expectedUID < 0 || opts.expectedGID < 0 {
		return nil, fmt.Errorf("invalid expected store ownership %d:%d", opts.expectedUID, opts.expectedGID)
	}

	var findings []Finding
	ancestorFindings, err := auditAncestors(root, opts.ancestorBoundary)
	if err != nil {
		return nil, err
	}
	findings = append(findings, ancestorFindings...)

	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("inspect %s: %w", path, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			findings = append(findings, Finding{Path: path, Code: "symlink", Detail: "symlink is not allowed in signer store"})
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		uid, gid, ok := fsutil.FileOwnership(info)
		if !ok {
			return fmt.Errorf("ownership metadata unavailable for %s", path)
		}
		expect := expectedArtifact(root, path, info, opts, policy)
		if uid != expect.uid || gid != expect.gid {
			findings = append(findings, Finding{
				Path: path, Code: "owner",
				Detail: fmt.Sprintf("owner is %d:%d, expected %d:%d", uid, gid, expect.uid, expect.gid),
			})
		}
		if (expect.wantDir && !info.IsDir()) || (expect.wantRegular && !info.Mode().IsRegular()) {
			findings = append(findings, Finding{Path: path, Code: "type", Detail: "artifact has an unexpected filesystem type"})
		}

		switch {
		case info.IsDir():
			auditMode(path, info.Mode(), expect.mode, expect.allowDirSetgid, &findings)
		case info.Mode().IsRegular():
			auditMode(path, info.Mode(), expect.mode, false, &findings)
			if links, ok := regularFileLinkCount(info); ok && links != 1 {
				findings = append(findings, Finding{
					Path: path, Code: "hardlink",
					Detail: fmt.Sprintf("regular file has %d links, expected 1", links),
				})
			}
		case info.Mode()&os.ModeSocket != 0 && sameCleanPath(path, opts.socketPath):
			auditMode(path, info.Mode(), 0o660, false, &findings)
		default:
			findings = append(findings, Finding{Path: path, Code: "type", Detail: "unexpected filesystem object type"})
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("audit signer store: %w", err)
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Path == findings[j].Path {
			return findings[i].Code < findings[j].Code
		}
		return findings[i].Path < findings[j].Path
	})
	return findings, nil
}

func expectedArtifact(root, path string, info os.FileInfo, opts options, policy profilePolicy) artifactExpectation {
	expect := artifactExpectation{uid: opts.expectedUID, gid: opts.expectedGID}
	if info.IsDir() {
		expect.mode = policy.dirMode
		expect.allowDirSetgid = policy.allowDirSetgid
	} else {
		expect.mode = policy.fileMode
	}
	if isRootCredential(root, path) {
		expect.uid, expect.gid = 0, 0
		expect.mode = 0o600
		expect.wantRegular = true
		return expect
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return expect
	}
	switch filepath.ToSlash(rel) {
	case "install":
		expect.uid, expect.gid = 0, opts.expectedGID
		expect.mode = 0o750
		expect.allowDirSetgid = opts.profile == legacySharedProfile
		expect.wantDir = true
	case "install/uninstall.sh":
		expect.uid, expect.gid = 0, opts.expectedGID
		expect.mode = 0o750
		expect.wantRegular = true
	case "install/release.json", "install/operator-root":
		expect.uid, expect.gid = 0, opts.expectedGID
		expect.mode = 0o640
		expect.wantRegular = true
	}
	return expect
}

func auditAncestors(root, boundary string) ([]Finding, error) {
	var boundaryAbs string
	if boundary != "" {
		var err error
		boundaryAbs, err = filepath.Abs(filepath.Clean(boundary))
		if err != nil {
			return nil, fmt.Errorf("resolve ancestor boundary: %w", err)
		}
		rel, err := filepath.Rel(boundaryAbs, root)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("ancestor boundary %s does not contain store root %s", boundaryAbs, root)
		}
	}
	var paths []string
	for current := root; ; current = filepath.Dir(current) {
		paths = append(paths, current)
		if boundaryAbs != "" && current == boundaryAbs {
			break
		}
		next := filepath.Dir(current)
		if next == current {
			break
		}
	}
	var findings []Finding
	for i := len(paths) - 1; i >= 0; i-- {
		path := paths[i]
		info, err := os.Lstat(path)
		if err != nil {
			return nil, fmt.Errorf("inspect store path component %s: %w", path, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			findings = append(findings, Finding{Path: path, Code: "ancestor-type", Detail: "store path component is not a real directory"})
			continue
		}
		// The root itself is checked against its selected profile during the
		// tree walk. Ancestors must not be mutable by group or other users.
		if path != root && path != boundaryAbs && info.Mode().Perm()&0o022 != 0 {
			findings = append(findings, Finding{Path: path, Code: "ancestor-write", Detail: "store ancestor is group/other writable"})
		}
	}
	return findings, nil
}

func auditMode(path string, actual, ceiling os.FileMode, allowSetgid bool, findings *[]Finding) {
	if actual.Perm()&^ceiling != 0 {
		*findings = append(*findings, Finding{
			Path: path, Code: "mode",
			Detail: fmt.Sprintf("mode %04o exceeds permission ceiling %04o", actual.Perm(), ceiling),
		})
	}
	allowedSpecial := os.FileMode(0)
	if allowSetgid {
		allowedSpecial = os.ModeSetgid
	}
	if actual&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky)&^allowedSpecial != 0 {
		*findings = append(*findings, Finding{Path: path, Code: "special-mode", Detail: "unexpected special permission bits"})
	}
}

func isRootCredential(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	return len(parts) == 3 && parts[0] == "identities" && parts[2] == "passphrase.cred"
}

func sameCleanPath(left, right string) bool {
	if right == "" {
		return false
	}
	leftAbs, leftErr := filepath.Abs(filepath.Clean(left))
	rightAbs, rightErr := filepath.Abs(filepath.Clean(right))
	return leftErr == nil && rightErr == nil && leftAbs == rightAbs
}
