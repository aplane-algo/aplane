// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { parse as parseYaml } from "yaml";
import type { ClientConfig } from "./types.js";
import { SignerError } from "./errors.js";

/** Default ports (match apshell/apsignerd defaults) */
export const DEFAULT_SSH_PORT = 1127;
export const DEFAULT_SIGNER_PORT = 11270;

/** Default data directory (like ~/.aws, ~/.docker, ~/.kube) */
export const DEFAULT_DATA_DIR = "~/.apclient";

/**
 * Expand ~ in paths to the user's home directory.
 */
export function expandPath(filePath: string): string {
  if (filePath.startsWith("~")) {
    return path.join(os.homedir(), filePath.slice(1));
  }
  return filePath;
}

/**
 * Load client configuration from data_dir/config.yaml.
 *
 * @param dataDir - Path to data directory
 * @returns ClientConfig with values from file, defaults for missing fields
 */
export function loadConfig(dataDir: string): ClientConfig {
  const config: ClientConfig = {
    signerPort: DEFAULT_SIGNER_PORT,
  };

  const configPath = path.join(dataDir, "config.yaml");

  if (!fs.existsSync(configPath)) {
    return config;
  }

  try {
    const content = fs.readFileSync(configPath, "utf-8");
    const data = parseYaml(content) || {};

    if (data.signer_port !== undefined) {
      config.signerPort = data.signer_port;
    }

    // Parse SSH config if present
    if (data.ssh && data.ssh.host) {
      config.ssh = {
        host: data.ssh.host,
        port: data.ssh.port ?? DEFAULT_SSH_PORT,
        identityFile: data.ssh.identity_file ?? ".ssh/id_ed25519",
        knownHostsPath: data.ssh.known_hosts_path ?? ".ssh/known_hosts",
      };
    }
  } catch {
    // Return defaults on parse error
  }

  return config;
}

/**
 * Load authentication token from file.
 *
 * @param tokenPath - Path to aplane.token file
 * @returns Token string
 * @throws SignerError if file doesn't exist
 */
export function loadToken(tokenPath: string): string {
  const expandedPath = expandPath(tokenPath);

  if (!fs.existsSync(expandedPath)) {
    throw new SignerError(`No token found at ${expandedPath}`);
  }

  return fs.readFileSync(expandedPath, "utf-8").trim();
}

/**
 * Load token from the default location in a data directory.
 *
 * @param dataDir - Data directory path (will be expanded)
 * @returns Token string
 * @throws SignerError if token file doesn't exist
 */
export function loadTokenFromDir(dataDir: string): string {
  const expandedDir = expandPath(dataDir);
  const tokenPath = path.join(expandedDir, "aplane.token");
  return loadToken(tokenPath);
}

/**
 * Resolve data directory from: parameter > env var > default.
 *
 * @param dataDir - Optional override
 * @returns Resolved and expanded path
 */
export function resolveDataDir(dataDir?: string): string {
  const dir =
    dataDir || process.env.APCLIENT_DATA || DEFAULT_DATA_DIR;
  return expandPath(dir);
}
