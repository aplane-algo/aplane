// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"fmt"
	"os"
)

func apstoreUsage() {
	fmt.Fprintf(os.Stderr, "apstore - Signer keystore management\n\n")
	fmt.Fprintf(os.Stderr, "Usage:\n")
	fmt.Fprintf(os.Stderr, "  apstore [-d path] initialize [--role signer|sentry]\n")
	fmt.Fprintf(os.Stderr, "  apstore [-d path] permissions <preflight|audit|migrate|prepare-managed-root --uid UID --gid GID|convert-managed --uid UID --gid GID>\n")
	fmt.Fprintf(os.Stderr, "  apstore [-d path] rebuild <archive-path> [--role signer|sentry] [--address ADDRESS ...]\n")
	fmt.Fprintf(os.Stderr, "  apstore [-d path] verify <backup-dir|archive-path>\n")
	fmt.Fprintf(os.Stderr, "  apstore [-d path] generations prune [--all-priors]\n")
	fmt.Fprintf(os.Stderr, "  apstore [-d path] policy check\n")
	fmt.Fprintf(os.Stderr, "  apstore [-d path] policy verify\n")
	fmt.Fprintf(os.Stderr, "  apstore [-d path] policy sign\n")
	fmt.Fprintf(os.Stderr, "  apstore [-d path] keys list\n")
	fmt.Fprintf(os.Stderr, "\nOptions:\n")
	fmt.Fprintf(os.Stderr, "  -d path              Data directory (or set APSIGNER_DATA env var)\n")
	fmt.Fprintf(os.Stderr, "\nExamples:\n")
	fmt.Fprintf(os.Stderr, "  apstore initialize\n")
	fmt.Fprintf(os.Stderr, "  apstore initialize --role sentry\n")
	fmt.Fprintf(os.Stderr, "  apstore rebuild /mnt/usb/aplane-backup.tar.gz\n")
	fmt.Fprintf(os.Stderr, "  apstore rebuild /mnt/usb/aplane-sentry-backup.tar.gz --role sentry\n")
	fmt.Fprintf(os.Stderr, "  apstore verify /mnt/usb/backup/aplane-backup-20260423-010203.tar.gz\n")
	fmt.Fprintf(os.Stderr, "  apstore policy check\n")
	fmt.Fprintf(os.Stderr, "  apstore policy sign\n")
	fmt.Fprintf(os.Stderr, "  apstore keys list\n")
}
