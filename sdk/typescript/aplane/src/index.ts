// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

/**
 * aPlane TypeScript SDK - Transaction signing via apsignerd
 *
 * Data directory (default: ~/.aplane):
 *     ~/.aplane/
 *     ├── aplane.token         # API token
 *     └── config.yaml          # Connection settings
 *
 * Example config.yaml:
 *     signer_port: 11270
 *
 * Usage:
 *     import { SignerClient, sendRawTransaction } from "@aplane/signer";
 *
 *     const client = await SignerClient.fromEnv();
 *     const signed = await client.signTransaction(txn);
 *     const txid = await sendRawTransaction(algodClient, signed);
 *
 * @packageDocumentation
 */

// Main client
export { SignerClient } from "./client.js";

// Utilities
export {
  sendRawTransaction,
  loadToken,
  loadConfig,
  resolveDataDir,
  expandPath,
} from "./utils.js";

// Encoding utilities
export {
  encodeTransaction,
  encodeLsigArgs,
  concatenateSignedTxns,
  bytesToHex,
  hexToBytes,
} from "./encoding.js";

// Errors
export {
  SignerError,
  AuthenticationError,
  SigningRejectedError,
  SignerUnavailableError,
  KeyNotFoundError,
  TransactionRejectedError,
  LogicSigRejectedError,
  InsufficientFundsError,
  InvalidTransactionError,
} from "./errors.js";

// Types
export type {
  KeyInfo,
  RuntimeArg,
  ClientConfig,
  SSHConfig,
  FromEnvOptions,
  ConnectLocalOptions,
  ConnectSshOptions,
  LsigArgs,
  LsigArgsMap,
  SignRequest,
  MutationReport,
  GroupSignResponse,
  KeysResponse,
} from "./types.js";

// Constants
export { DEFAULT_SIGNER_PORT, DEFAULT_SSH_PORT, DEFAULT_DATA_DIR } from "./config.js";
