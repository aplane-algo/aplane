//go:build !testmode

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"flag"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"os"
)

var testFlag *bool

const testBuildTagHint = "test mode is only available for testing builds"

func isTestMode() bool {
	return testFlag != nil && *testFlag
}

func initTestFlag() {
	testFlag = flag.Bool("test", false, "Run in test mode (testing builds only)")
}

func runTestMode(_ serverconfig.ServerConfig, _ []string) {
	logErrorf(testBuildTagHint)
	os.Exit(2)
}

func runRemoteTestMode(_ *remoteAdminConfig, _ []string) {
	logErrorf(testBuildTagHint)
	os.Exit(2)
}
