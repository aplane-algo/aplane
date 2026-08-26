// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	apkeys "github.com/aplane-algo/aplane/internal/keys"
)

func cmdKeys(args []string) error {
	if len(args) != 1 || args[0] != "list" {
		return fmt.Errorf("usage: apstore keys list")
	}
	return cmdKeysList()
}

func cmdKeysList() error {
	active, kr, err := readStore()
	if err != nil {
		return err
	}
	defer kr.Zero()

	report, err := apkeys.ScanKeysDirectoryWithKeyringReportActive(active, kr)
	if err != nil {
		return err
	}
	for _, warning := range report.Warnings {
		logWarnf("%s", warning.Message())
	}

	addresses := make([]string, 0, len(report.Keys))
	for address := range report.Keys {
		addresses = append(addresses, address)
	}
	sort.Strings(addresses)
	if len(addresses) == 0 {
		logInfof("no keys found")
		return nil
	}

	logInfof("found %d key(s)", len(addresses))
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "ADDRESS/SELECTOR\tKEY TYPE\tCATEGORY\tCREATED\tFILE"); err != nil {
		return err
	}
	for _, address := range addresses {
		info := report.Keys[address]
		if _, err := fmt.Fprintf(
			w,
			"%s\t%s\t%s\t%s\t%s\n",
			address,
			displayKeyType(info.KeyType),
			displayValue(info.Category),
			displayValue(info.CreatedAt),
			displayKeyFile(info.KeyFile),
		); err != nil {
			return err
		}
	}
	return w.Flush()
}

func displayValue(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

func displayKeyFile(path string) string {
	if strings.TrimSpace(path) == "" {
		return "-"
	}
	return filepath.Base(path)
}
