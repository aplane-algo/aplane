// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// native-funding performs narrowly scoped integration-fixture operations with
// the protocol-native Falcon-1024 account in TEST_FUNDING_MNEMONIC.
package main

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/aplane-algo/aplane/test/integration/harness"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}

	network, err := harness.NewTestnetConfig()
	if err != nil {
		fatalf("load integration network: %v", err)
	}
	funder, err := harness.NewFundTestAccount(network.Client)
	if err != nil {
		fatalf("load native Falcon funding account: %v", err)
	}

	switch os.Args[1] {
	case "address":
		if len(os.Args) != 2 {
			usage()
		}
		fmt.Println(funder.GetAddress())
	case "fund":
		if len(os.Args) != 4 {
			usage()
		}
		amount, err := strconv.ParseUint(os.Args[3], 10, 64)
		if err != nil || amount == 0 {
			fatalf("fund amount must be a positive integer number of microAlgos")
		}
		if err := funder.FundMicroAlgosAndWait(os.Args[2], amount); err != nil {
			fatalf("fund %s: %v", os.Args[2], err)
		}
		fmt.Printf("funded %s with %d microAlgos\n", os.Args[2], amount)
	case "balance":
		if len(os.Args) != 3 {
			usage()
		}
		info, err := network.Client.AccountInformation(os.Args[2]).Do(context.Background())
		if err != nil {
			fatalf("read account %s: %v", os.Args[2], err)
		}
		fmt.Println(info.Amount)
	default:
		usage()
	}
}

func usage() {
	_, _ = fmt.Fprintln(os.Stderr, "usage: native-funding address | fund <address> <microalgos> | balance <address>")
	os.Exit(2)
}

func fatalf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, "native-funding: "+format+"\n", args...)
	os.Exit(1)
}
