// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

// Scripting, AI, and plugin execution commands

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/command"
	"github.com/aplane-algo/aplane/internal/docassets"

	"github.com/chzyer/readline"
)

// cmdJS executes JavaScript code in the REPL.
// Supports:
//   - js -help: print the JavaScript API reference
//   - js <file.js>, js { code }, js <inline>, and multi-line mode
func (r *REPLState) cmdJS(args []string, ctx *command.Context) (command.Result, error) {
	return newTerminalCommandResult(nil), r.runJS(args, rawCommandArgs(ctx))
}

// rawCommandArgs returns a command's arguments as typed, with the quotes
// ParseCommand strips.
func rawCommandArgs(ctx *command.Context) string {
	if ctx != nil {
		return ctx.RawArgs
	}
	return ""
}

func (r *REPLState) runJS(args []string, rawArgs string) error {
	if len(args) > 0 && args[0] == "-help" {
		r.println(strings.TrimRight(docassets.UserJSAPI, "\n"))
		return nil
	}

	code, ok, err := r.jsCode(args, rawArgs)
	if err != nil || !ok {
		return err
	}

	r.ensureJSRunner()

	// Run the code
	result, err := r.Scripts.Runner.RunWithContext(r.commandContext(), code)
	if err != nil {
		return err
	}

	r.Scripts.LastCode = code

	// Print result if not empty
	if !result.IsEmpty {
		r.println(result.Value)
	}

	return nil
}

// jsCode returns the code a js command names, from whichever of its four
// forms was used. ok is false when there is nothing to run: the input was
// cancelled or empty.
func (r *REPLState) jsCode(args []string, rawArgs string) (code string, ok bool, err error) {
	switch {
	case len(args) == 0:
		return r.jsCodeFromLines()
	case strings.HasPrefix(rawArgs, "{"):
		return r.jsCodeFromBraces(rawArgs)
	case strings.HasSuffix(args[0], ".js"):
		return r.jsCodeFromFile(args[0])
	}
	// Inline mode: js <code>
	// Use rawArgs to preserve quotes
	if rawArgs != "" {
		return rawArgs, true, nil
	}
	return strings.Join(args, " "), true, nil
}

// jsCodeFromLines is multi-line mode: lines until a blank one.
func (r *REPLState) jsCodeFromLines() (string, bool, error) {
	r.println("Enter JavaScript code (blank line to execute, Ctrl+C to cancel):")

	lines, cancelled, err := r.readJSLines(nil, func(line string) bool { return line == "" })
	if err != nil || cancelled || len(lines) == 0 {
		return "", false, err
	}
	return strings.Join(lines, "\n"), true, nil
}

// jsCodeFromBraces is brace-delimited mode: js { code here }. It uses rawArgs
// to preserve quotes inside the braces. Without a closing brace on the line,
// it reads more lines until one that holds only the closing brace.
func (r *REPLState) jsCodeFromBraces(rawArgs string) (string, bool, error) {
	inner := strings.TrimPrefix(rawArgs, "{")
	inner = strings.TrimSpace(inner)

	if strings.HasSuffix(inner, "}") {
		code := strings.TrimSuffix(inner, "}")
		return strings.TrimSpace(code), true, nil
	}

	lines, cancelled, err := r.readJSLines([]string{inner}, func(line string) bool { return strings.TrimSpace(line) == "}" })
	if err != nil || cancelled {
		return "", false, err
	}
	return strings.Join(lines, "\n"), true, nil
}

// jsCodeFromFile is file mode: js script.js. Absolute paths are used as-is;
// bare filenames resolve to the scripts directory.
func (r *REPLState) jsCodeFromFile(scriptPath string) (string, bool, error) {
	if !filepath.IsAbs(scriptPath) {
		scriptPath = filepath.Join(r.DataDir, "scripts", scriptPath)
	}
	content, err := os.ReadFile(scriptPath)
	if err != nil {
		return "", false, fmt.Errorf("failed to read script: %w", err)
	}
	return string(content), true, nil
}

// readJSLines appends lines to lines until isEnd accepts one, reading from
// the interactive line reader when there is one and from standard input
// otherwise. An interrupt at the line reader cancels the command.
func (r *REPLState) readJSLines(lines []string, isEnd func(line string) bool) (_ []string, cancelled bool, _ error) {
	if !r.hasInteractiveLineReader() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := scanner.Text()
			if isEnd(line) {
				break
			}
			lines = append(lines, line)
		}
		if err := scanner.Err(); err != nil {
			return nil, false, err
		}
		return lines, false, nil
	}

	r.clearInputPrompt()
	for {
		line, err := r.readInteractiveLine()
		if err != nil {
			if errors.Is(err, readline.ErrInterrupt) {
				r.println("\nCancelled.")
				return nil, true, nil
			}
			return nil, false, err
		}
		if isEnd(line) {
			return lines, false, nil
		}
		lines = append(lines, line)
	}
}

// cmdJSSave saves JavaScript code to a file in the data directory's scripts/ folder.
// Usage: jssave [-f] <path> [-last | <javascript code>]
func (r *REPLState) cmdJSSave(_ []string, ctx *command.Context) (command.Result, error) {
	return newTerminalCommandResult(nil), r.runJSSave(rawCommandArgs(ctx))
}

func (r *REPLState) runJSSave(rawArgs string) error {
	raw := strings.TrimSpace(rawArgs)
	if raw == "" {
		return fmt.Errorf("usage: jssave [-f] <path> [-last | <javascript code>]")
	}

	overwrite := false
	if strings.HasPrefix(raw, "-f ") {
		overwrite = true
		raw = strings.TrimSpace(raw[3:])
	}

	parts := strings.SplitN(raw, " ", 2)
	if len(parts) < 2 || strings.TrimSpace(parts[1]) == "" {
		return fmt.Errorf("usage: jssave [-f] <path> [-last | <javascript code>]")
	}

	scriptPath := parts[0]
	code := parts[1]

	if strings.TrimSpace(code) == "-last" {
		if r.Scripts.LastCode == "" {
			return fmt.Errorf("no previously executed JavaScript code")
		}
		code = r.Scripts.LastCode
	}

	dest, err := saveJSScript(r.DataDir, scriptPath, code, overwrite)
	if err != nil {
		return err
	}

	r.printf("Saved to %s\n", dest)
	return nil
}

// cmdJSList lists saved JavaScript scripts in the data directory's scripts/ folder.
func (r *REPLState) cmdJSList(_ []string, _ *command.Context) (command.Result, error) {
	return newTerminalCommandResult(nil), r.runJSList()
}

func (r *REPLState) runJSList() error {
	entries, err := listJSScripts(r.DataDir)
	if err != nil {
		return err
	}

	dir, err := jsScriptsDir(r.DataDir)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		r.printf("No saved scripts in %s\n", dir)
		return nil
	}
	r.printf("Scripts in %s:\n", dir)
	for _, e := range entries {
		r.printf("  %s  %6d B  %s\n", e.Name, e.Size, time.Unix(e.MTime, 0).Format("2006-01-02 15:04"))
	}
	return nil
}

// jsScriptEntry describes a saved script file surfaced by jslist.
type jsScriptEntry struct {
	Name  string `json:"name"`
	Size  int64  `json:"size"`
	MTime int64  `json:"mtime"`
}

func jsScriptsDir(dataDir string) (string, error) {
	return filepath.Abs(filepath.Join(dataDir, "scripts"))
}

func normalizeJSScriptPath(dataDir, scriptPath string) (string, error) {
	scriptsDir, err := jsScriptsDir(dataDir)
	if err != nil {
		return "", err
	}

	scriptPath = strings.TrimSpace(scriptPath)
	if scriptPath == "" {
		return "", fmt.Errorf("path is required")
	}

	var dest string
	if strings.Contains(scriptPath, "/") {
		if !strings.HasPrefix(scriptPath, "/") {
			return "", fmt.Errorf("path with '/' must be absolute (must start with '/')")
		}
		dest = filepath.Clean(scriptPath)
	} else {
		dest = filepath.Join(scriptsDir, scriptPath)
	}
	if !strings.HasSuffix(dest, ".js") {
		dest += ".js"
	}
	return dest, nil
}

// saveJSScript writes code to the path normalizeJSScriptPath resolves: a
// bare name under dataDir/scripts/, or an absolute path as given. Returns the
// absolute path written.
func saveJSScript(dataDir, scriptPath, code string, overwrite bool) (string, error) {
	dest, err := normalizeJSScriptPath(dataDir, scriptPath)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return "", fmt.Errorf("failed to create scripts directory: %w", err)
	}
	if !overwrite {
		if _, err := os.Stat(dest); err == nil {
			return "", fmt.Errorf("%s already exists (use -f to overwrite)", dest)
		}
	}
	if err := os.WriteFile(dest, []byte(code+"\n"), 0644); err != nil {
		return "", fmt.Errorf("failed to write %s: %w", dest, err)
	}
	return dest, nil
}

// listJSScripts returns saved scripts in dataDir/scripts/ sorted by path.
func listJSScripts(dataDir string) ([]jsScriptEntry, error) {
	dir, err := jsScriptsDir(dataDir)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []jsScriptEntry
	for _, e := range raw {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".js") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, jsScriptEntry{
			Name:  e.Name(),
			Size:  info.Size(),
			MTime: info.ModTime().Unix(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// shellCommandWaitDelay is how long a `!` command's output is still read
// once its shell has exited or been killed: a process it started can keep
// the output open after it.
const shellCommandWaitDelay = 500 * time.Millisecond

// runShellCommand executes a shell command (used by ! prefix). It runs on
// the command's context, so cancelling the command, as an embedded host's
// Ctrl-C or its session's shutdown does, kills it.
//
// When its output is captured (an embedded host's pane), the command has no
// terminal of its own: it runs in its own process group, which a cancel kills
// whole, so the processes a compound command started end with the shell. At
// the interactive REPL it writes to the shell's own output and stays in the
// terminal's foreground group, where the terminal's Ctrl-C reaches every
// process of it and a program such as vim can read the terminal.
func (r *REPLState) runShellCommand(cmdStr string) error {
	if cmdStr == "" {
		return nil
	}

	// Execute via sh -c to support pipes, redirects, etc.
	ctx := r.commandContext()
	cmd := exec.CommandContext(ctx, "sh", "-c", cmdStr)
	cmd.Stdout = r.Out
	cmd.Stderr = r.Out
	cmd.Stdin = os.Stdin
	cmd.WaitDelay = shellCommandWaitDelay
	if _, direct := r.Out.(*os.File); !direct {
		runInOwnProcessGroup(cmd)
	}

	err := cmd.Run()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("shell command stopped: %w", ctxErr)
	}
	if errors.Is(err, exec.ErrWaitDelay) {
		// The shell exited; what it left running writes nowhere now.
		return nil
	}
	if err != nil {
		// Don't treat non-zero exit as error, just show it happened
		if exitErr, ok := err.(*exec.ExitError); ok {
			r.printf("(exit %d)\n", exitErr.ExitCode())
			return nil
		}
		return fmt.Errorf("failed to execute command: %w", err)
	}

	return nil
}
