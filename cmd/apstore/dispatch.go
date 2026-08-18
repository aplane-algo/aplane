// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"flag"
	"fmt"
	"os"
)

func dispatchApstoreCommand(args []string) {
	command := args[0]
	if err := enforceApstoreExecutionMode(dataDirectory, args); err != nil {
		exitWithError(err)
	}

	releaseOfflineMutationLock, err := acquireOfflineMutationLockForArgs(args, dataDirectory)
	if err != nil {
		exitWithError(err)
	}
	defer releaseOfflineMutationLock()

	switch command {
	case "initialize":
		if err := runStoreMutatingCommand(command, func() error { return cmdInitialize(args[1:]) }); err != nil {
			exitWithError(err)
		}

	case "permissions":
		if err := cmdPermissions(args[1:]); err != nil {
			exitWithError(err)
		}

	case "generations":
		if err := runStoreMutatingCommand(command, func() error {
			return cmdGenerations(args[1:])
		}); err != nil {
			exitWithError(err)
		}

	case "backup":
		if isManagedBackupCommand(args) {
			if err := cmdBackupManaged(args[1:]); err != nil {
				exitWithError(err)
			}
			return
		}
		logErrorf("usage: apstore backup <create|import|list|export|delete>")
		os.Exit(apstoreExitUsage)

	case "restore":
		if isManagedRestoreCommand(args) {
			if err := cmdRestoreManaged(args[1:]); err != nil {
				exitWithError(err)
			}
			return
		}
		logErrorf("usage: apstore restore <preview|apply|rollback|reconcile>")
		logErrorf("use apstore rebuild <archive-path> [--role signer|sentry] [--address ADDRESS ...] only for replacement-keystore recovery")
		os.Exit(apstoreExitUsage)

	case "rebuild":
		if err := runStoreMutatingCommand(command, func() error {
			return cmdRebuild(args[1:])
		}); err != nil {
			exitWithError(err)
		}

	case "verify":
		backupPath, err := verifyBackupPathFromArgs(args)
		if err != nil {
			logErrorf("%v", err)
			os.Exit(apstoreExitUsage)
		}
		if err := cmdVerify(backupPath); err != nil {
			exitWithError(err)
		}

	case "changepass":
		if err := cmdChangepass(); err != nil {
			exitWithError(err)
		}

	case "policy":
		run := func() error {
			return cmdPolicy(args[1:])
		}
		if len(args) > 1 && args[1] == "sign" {
			if err := runStoreMutatingCommand(command, run); err != nil {
				exitWithError(err)
			}
		} else if err := run(); err != nil {
			exitWithError(err)
		}

	case "keys":
		if err := cmdKeys(args[1:]); err != nil {
			exitWithError(err)
		}

	default:
		logErrorf("unknown command: %s", command)
		flag.Usage()
		os.Exit(apstoreExitUsage)
	}
}

func verifyBackupPathFromArgs(args []string) (string, error) {
	if len(args) < 2 {
		return "", fmt.Errorf("usage: apstore verify <backup-dir|archive-path>")
	}
	if len(args) > 2 {
		return "", fmt.Errorf("unknown verify option: %s", args[2])
	}
	return args[1], nil
}
