// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

/**
 * Runtime argument specification for a generic LogicSig.
 * Position in the array corresponds to the TEAL arg index.
 */
export interface RuntimeArg {
  /** Internal name for the argument (e.g., "preimage") */
  name: string;
  /** Argument type: "bytes", "string", or "uint64" */
  type: string;
  /** Help text describing the argument */
  description: string;
  /** Human-readable label for UI display */
  label?: string;
  /** If true, must be provided at signing time */
  required?: boolean;
  /** Expected byte length (0 = variable) */
  byteLength?: number;
}

/**
 * Information about a signing key from the signer.
 */
export interface KeyInfo {
  /** Algorand address */
  address: string;
  /** Public key in hex format */
  publicKeyHex: string;
  /** Key type (e.g., "ed25519", "falcon1024-v1", "timelock-v1") */
  keyType: string;
  /** Total LogicSig size for budget calculation (bytecode + crypto sig) */
  lsigSize: number;
  /** True if this is a generic LogicSig (no cryptographic signature needed) */
  isGenericLsig: boolean;
  /** Runtime arguments for generic LogicSigs */
  runtimeArgs?: RuntimeArg[];
}

/**
 * SSH tunnel configuration.
 */
export interface SSHConfig {
  /** Remote host to SSH to */
  host: string;
  /** SSH port (default: 1127) */
  port: number;
  /** Path to SSH private key, relative to data directory */
  identityFile: string;
  /** Path to known_hosts file, relative to data directory */
  knownHostsPath: string;
}

/**
 * Client configuration for connecting to apsignerd.
 */
export interface ClientConfig {
  /** Signer REST port (default: 11270) */
  signerPort: number;
  /** SSH configuration (if present, use SSH tunnel) */
  ssh?: SSHConfig;
}

/**
 * Options for SignerClient.connectSsh()
 */
export interface ConnectSshOptions {
  /** SSH port on remote (default: 1127) */
  sshPort?: number;
  /** Signer REST port on remote (default: 11270) */
  signerPort?: number;
  /** Request timeout in milliseconds (default: 90000) */
  timeout?: number;
}

/**
 * Options for SignerClient.fromEnv()
 */
export interface FromEnvOptions {
  /** Override default data directory */
  dataDir?: string;
  /** Request timeout in milliseconds (default: 90000) */
  timeout?: number;
}

/**
 * Options for SignerClient.connectLocal()
 */
export interface ConnectLocalOptions {
  /** Signer host (default: localhost) */
  host?: string;
  /** Signer port (default: 11270) */
  port?: number;
  /** Request timeout in milliseconds (default: 90000) */
  timeout?: number;
}

/**
 * LogicSig runtime arguments for a single address.
 * Maps argument name to its value as Uint8Array.
 */
export type LsigArgs = Record<string, Uint8Array>;

/**
 * LogicSig runtime arguments for multiple addresses.
 * Maps address to its argument map.
 */
export type LsigArgsMap = Record<string, LsigArgs>;

/**
 * Internal sign request structure sent to the server.
 */
export interface SignRequest {
  /** Auth address (which key to use for signing) */
  auth_address: string;
  /** Actual transaction sender address */
  txn_sender: string;
  /** Transaction bytes (TX + msgpack) as hex */
  txn_bytes_hex: string;
  /** Runtime args for generic LogicSigs (name -> hex value) */
  lsig_args?: Record<string, string>;
}

/**
 * Describes modifications made by the server during signing.
 */
export interface MutationReport {
  /** Number of dummy transactions added for LSig budget */
  dummiesAdded?: number;
  /** True if group ID was computed/recomputed */
  groupIdChanged?: boolean;
  /** Indices of transactions with modified fees (0-based) */
  feesModified?: number[];
  /** Total fee increase in microAlgos (for dummy fees) */
  totalFeesDelta?: number;
  /** Number of transactions in original request */
  originalCount?: number;
  /** Number of transactions in signed response */
  finalCount?: number;
  /** Number of pre-signed transactions included as-is */
  passthroughCount?: number;
  /** Human-readable reason (e.g., "lsig_budget") */
  reason?: string;
}

/**
 * Response from the /sign endpoint.
 */
export interface GroupSignResponse {
  /** Array of signed transactions (hex-encoded msgpack) */
  signed?: string[];
  /** Modifications made by server (undefined if none) */
  mutations?: MutationReport;
  /** Error message if signing failed */
  error?: string;
}

/**
 * Response from the /keys endpoint.
 */
export interface KeysResponse {
  /** Number of keys */
  count: number;
  /** Array of key information */
  keys: KeyInfo[];
}
