# Changelog

All notable changes to aPlane will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Version information embedded in all binaries via `--version` flag
- `internal/version` package for build-time version injection
- CHANGELOG.md following Keep a Changelog format

### Changed
- Makefile now injects VERSION, GIT_COMMIT, and BUILD_TIME into binaries

## [0.38.0] - 2026-01-15

### Added
- TUI decomposition: split view.go and update.go into domain-specific files
- Plugin contract tests for JSON-RPC protocol and manifest validation
- JS API runtime tests for argument validation and helper functions
- Fee helper consolidation in engine.go

### Changed
- Improved transaction summary formatting with alias support
- Standardized keyType naming across codebase

### Fixed
- Various code quality improvements from static analysis

---

## Release Notes Format

When preparing a release:

1. Move items from `[Unreleased]` to a new version section
2. Add the release date in YYYY-MM-DD format
3. Categorize changes:
   - **Added** for new features
   - **Changed** for changes in existing functionality
   - **Deprecated** for soon-to-be removed features
   - **Removed** for now removed features
   - **Fixed** for any bug fixes
   - **Security** for vulnerability fixes
