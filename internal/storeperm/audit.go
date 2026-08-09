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

// Profile selects one complete signer-store permission contract.
type Profile uint8

const (
	// LegacySharedProfile audits the transitional 2770/0660 group-shared
	// layout. It exists only to validate inputs before migration.
	LegacySharedProfile Profile = iota
	// PrivateServiceProfile audits the service-user-only 0700/0600 layout.
	PrivateServiceProfile
)

// Options describes the expected store owner and narrowly recognized
// exceptions. ExpectedUID and ExpectedGID apply to the root and all ordinary
// descendants. SocketPath may name the legacy in-store IPC socket. Empty means
// sockets are never accepted in the store inventory.
type Options struct {
	Root        string
	ExpectedUID int
	ExpectedGID int
	Profile     Profile
	SocketPath  string
	// AncestorBoundary, when non-empty, is an already-validated parent at
	// which ancestor inspection stops. Production callers leave it empty;
	// tests and embedding applications may supply a separately trusted root.
	AncestorBoundary string
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

func policyForProfile(profile Profile) (profilePolicy, error) {
	switch profile {
	case LegacySharedProfile:
		return profilePolicy{dirMode: 0o770, fileMode: 0o660, allowDirSetgid: true}, nil
	case PrivateServiceProfile:
		return profilePolicy{dirMode: 0o700, fileMode: 0o600}, nil
	default:
		return profilePolicy{}, fmt.Errorf("unknown store permission profile %d", profile)
	}
}

// Audit performs a read-only, no-symlink-traversal inspection. Findings are
// returned in path/code order. A non-nil error means the inventory could not
// be completed and its result must not authorize migration or startup.
func Audit(opts Options) ([]Finding, error) {
	policy, err := policyForProfile(opts.Profile)
	if err != nil {
		return nil, err
	}
	if opts.Root == "" {
		return nil, fmt.Errorf("store root is required")
	}
	root, err := filepath.Abs(filepath.Clean(opts.Root))
	if err != nil {
		return nil, fmt.Errorf("resolve store root: %w", err)
	}
	if opts.ExpectedUID < 0 || opts.ExpectedGID < 0 {
		return nil, fmt.Errorf("invalid expected store ownership %d:%d", opts.ExpectedUID, opts.ExpectedGID)
	}

	var findings []Finding
	ancestorFindings, err := auditAncestors(root, opts.AncestorBoundary)
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
		case info.Mode()&os.ModeSocket != 0 && sameCleanPath(path, opts.SocketPath):
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

func expectedArtifact(root, path string, info os.FileInfo, opts Options, policy profilePolicy) artifactExpectation {
	expect := artifactExpectation{uid: opts.ExpectedUID, gid: opts.ExpectedGID}
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
		expect.uid, expect.gid = 0, opts.ExpectedGID
		expect.mode = 0o750
		expect.allowDirSetgid = opts.Profile == LegacySharedProfile
		expect.wantDir = true
	case "install/uninstall.sh":
		expect.uid, expect.gid = 0, opts.ExpectedGID
		expect.mode = 0o750
		expect.wantRegular = true
	case "install/release.json", "install/operator-root":
		expect.uid, expect.gid = 0, opts.ExpectedGID
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
