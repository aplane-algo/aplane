// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

// Package main implements a static analyzer that checks for proper zeroing of key material.
//
// This analyzer scans for functions that handle private key bytes and verifies
// they call ZeroBytes or ZeroKey before returning.
package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Patterns that indicate key material is being handled
var keyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)privatekey`),
	regexp.MustCompile(`(?i)privkey`),
	regexp.MustCompile(`(?i)secretkey`),
	regexp.MustCompile(`(?i)\.PrivateKey`),
}

// Patterns that indicate proper zeroing
var zeroPatterns = []*regexp.Regexp{
	regexp.MustCompile(`ZeroBytes`),
	regexp.MustCompile(`ZeroKey`),
	regexp.MustCompile(`util\.Zero`),
}

// Directories to scan (relative to repo root)
var targetDirs = []string{
	"internal/signing",
	"internal/crypto",
	"lsig",
}

// Files/patterns to skip
var skipPatterns = []string{
	"_test.go",
	"testdata",
}

// Functions that are exempt from zeroing requirements.
// These follow ownership patterns where the caller is responsible for zeroing:
// - SignMessage: receives key material as parameter, caller calls ZeroKey when done
// - GenerateKeypair/GenerateKey: returns key material to caller, caller must zero
// - PrivateKeySize/etc: size constants, not actual key material
// - Sign (wrapper): delegates to implementation that handles zeroing
var exemptFunctions = map[string]string{
	"SignMessage":     "key passed as parameter - caller owns lifecycle via ZeroKey()",
	"GenerateKeypair": "returns keys to caller - caller responsible for zeroing",
	"GenerateKey":     "returns keys to caller - caller responsible for zeroing",
	"SignWithRawKey":  "key passed as parameter - caller owns lifecycle",
	"PrivateKeySize":  "returns size constant, not actual key material",
	"Sign":            "wrapper delegates to implementation with proper zeroing",
}

type finding struct {
	file     string
	line     int
	content  string
	funcName string
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: keyzero <repo-root>")
		os.Exit(1)
	}

	root := os.Args[1]
	var findings []finding
	var filesChecked int

	for _, dir := range targetDirs {
		dirPath := filepath.Join(root, dir)
		if _, err := os.Stat(dirPath); os.IsNotExist(err) {
			continue
		}

		err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if info.IsDir() {
				return nil
			}

			if !strings.HasSuffix(path, ".go") {
				return nil
			}

			for _, skip := range skipPatterns {
				if strings.Contains(path, skip) {
					return nil
				}
			}

			filesChecked++
			fileFindings := checkFile(path)
			findings = append(findings, fileFindings...)
			return nil
		})

		if err != nil {
			fmt.Fprintf(os.Stderr, "Error walking %s: %v\n", dir, err)
		}
	}

	// Report results
	fmt.Printf("Key Zeroing Analysis\n")
	fmt.Printf("====================\n")
	fmt.Printf("Files checked: %d\n\n", filesChecked)

	if len(findings) == 0 {
		fmt.Println("No issues found.")
		os.Exit(0)
	}

	fmt.Printf("Potential issues: %d\n\n", len(findings))
	for _, f := range findings {
		fmt.Printf("%s:%d\n", f.file, f.line)
		fmt.Printf("  Function: %s\n", f.funcName)
		fmt.Printf("  Line: %s\n", strings.TrimSpace(f.content))
		fmt.Printf("  Issue: Key material referenced but no ZeroBytes/ZeroKey in function\n\n")
	}

	os.Exit(1)
}

func checkFile(path string) []finding {
	var findings []finding

	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = file.Close() }()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	// Find functions that reference key material
	inFunc := false
	funcStart := 0
	funcName := ""
	braceCount := 0
	hasKeyRef := false
	hasZero := false
	keyRefLine := 0
	keyRefContent := ""

	funcPattern := regexp.MustCompile(`^func\s+(\([^)]+\)\s+)?(\w+)`)

	for i, line := range lines {
		lineNum := i + 1

		// Track function boundaries
		if match := funcPattern.FindStringSubmatch(line); match != nil {
			// If we were in a function, check it
			if inFunc && hasKeyRef && !hasZero {
				// Check if function is exempt (ownership passed to caller)
				if _, exempt := exemptFunctions[funcName]; !exempt {
					findings = append(findings, finding{
						file:     path,
						line:     keyRefLine,
						content:  keyRefContent,
						funcName: funcName,
					})
				}
			}

			// Start new function
			inFunc = true
			funcStart = lineNum
			funcName = match[2]
			braceCount = 0
			hasKeyRef = false
			hasZero = false
		}

		if inFunc {
			braceCount += strings.Count(line, "{") - strings.Count(line, "}")

			// Check for key material references
			for _, pat := range keyPatterns {
				if pat.MatchString(line) {
					// Skip type declarations and struct definitions
					if !strings.Contains(line, "type ") && !strings.Contains(line, "//") {
						hasKeyRef = true
						keyRefLine = lineNum
						keyRefContent = line
					}
					break
				}
			}

			// Check for zeroing calls
			for _, pat := range zeroPatterns {
				if pat.MatchString(line) {
					hasZero = true
					break
				}
			}

			// Function ended
			if braceCount == 0 && funcStart != lineNum {
				if hasKeyRef && !hasZero {
					// Check if function is exempt (ownership passed to caller)
					if _, exempt := exemptFunctions[funcName]; !exempt {
						findings = append(findings, finding{
							file:     path,
							line:     keyRefLine,
							content:  keyRefContent,
							funcName: funcName,
						})
					}
				}
				inFunc = false
			}
		}
	}

	return findings
}
