// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

import type { Algodv2 } from "algosdk";
import {
  TransactionRejectedError,
  LogicSigRejectedError,
  InsufficientFundsError,
  InvalidTransactionError,
} from "./errors.js";

// Re-export config utilities
export { loadToken, loadConfig, resolveDataDir, expandPath } from "./config.js";

/**
 * Submit a signed transaction to the network with clean error handling.
 *
 * @param algodClient - algosdk Algodv2 client instance
 * @param signedTxn - Base64-encoded string from signTransaction()
 * @returns Transaction ID
 *
 * @throws LogicSigRejectedError - If a LogicSig program returned false
 * @throws InsufficientFundsError - If account has insufficient funds
 * @throws InvalidTransactionError - If transaction is malformed
 * @throws TransactionRejectedError - For other rejection reasons
 *
 * @example
 * ```typescript
 * const signed = await client.signTransaction(txn);
 * const txid = await sendRawTransaction(algodClient, signed);
 * console.log(`Submitted: ${txid}`);
 * ```
 *
 * Note: You can also use algodClient.sendRawTransaction() directly
 * if you don't need the clean error types.
 */
export async function sendRawTransaction(
  algodClient: Algodv2,
  signedTxn: string
): Promise<string> {
  try {
    const txnBytes = Buffer.from(signedTxn, "base64");
    const response = await algodClient.sendRawTransaction(txnBytes).do();
    return response.txid;
  } catch (error) {
    throw parseAlgodError(error);
  }
}

/**
 * Parse algod HTTP error into a clean aplane exception.
 */
function parseAlgodError(error: unknown): Error {
  const msg = String(error);

  // Try to extract transaction ID
  let txid = "unknown";
  const txidMatch = msg.match(/transaction ([A-Z0-9]{52}):/);
  if (txidMatch) {
    txid = txidMatch[1];
  }

  // LogicSig rejection
  if (msg.toLowerCase().includes("rejected by logic")) {
    return new LogicSigRejectedError(txid);
  }

  // Insufficient funds / overspend
  if (
    msg.toLowerCase().includes("overspend") ||
    msg.toLowerCase().includes("insufficient funds")
  ) {
    const balanceMatch = msg.match(/tried to spend \{(\d+)\}/);
    if (balanceMatch) {
      return new InsufficientFundsError(
        txid,
        `insufficient funds (tried to spend ${balanceMatch[1]} microAlgos)`
      );
    }
    return new InsufficientFundsError(txid);
  }

  // LogicSig pool budget exceeded
  if (
    msg.toLowerCase().includes("logicsigs") &&
    msg.toLowerCase().includes("pool")
  ) {
    const poolMatch = msg.match(/had (\d+) bytes.*pool of (\d+) bytes/);
    if (poolMatch) {
      return new InvalidTransactionError(
        txid,
        `LogicSig too large (${poolMatch[1]} bytes exceeds ${poolMatch[2]} byte pool). ` +
          "Fee pooling should be automatic - ensure you're using signTransaction() or signTransactions()."
      );
    }
    return new InvalidTransactionError(
      txid,
      "LogicSig exceeds pool budget - fee pooling should be automatic via signTransaction()"
    );
  }

  // Invalid group ID
  if (
    msg.toLowerCase().includes("group") &&
    (msg.toLowerCase().includes("invalid") ||
      msg.toLowerCase().includes("mismatch"))
  ) {
    return new InvalidTransactionError(txid, "invalid or mismatched group ID");
  }

  // Fee too low
  if (
    msg.toLowerCase().includes("fee") &&
    (msg.toLowerCase().includes("too small") ||
      msg.toLowerCase().includes("below"))
  ) {
    return new InvalidTransactionError(txid, "transaction fee too low");
  }

  // Round range errors
  if (
    msg.toLowerCase().includes("round") &&
    (msg.toLowerCase().includes("past") ||
      msg.toLowerCase().includes("future") ||
      msg.toLowerCase().includes("invalid"))
  ) {
    return new InvalidTransactionError(
      txid,
      "transaction round range invalid (expired or too far in future)"
    );
  }

  // Generic rejection - extract a cleaner message if possible
  const reasonMatch = msg.match(/\}: (.+?)(?:\s*$|\s*\{)/);
  if (reasonMatch && reasonMatch[1].trim()) {
    return new TransactionRejectedError(txid, reasonMatch[1].trim());
  }

  // Fallback: return generic error with truncated message
  const truncated = msg.length > 200 ? msg.slice(0, 200) + "..." : msg;
  return new TransactionRejectedError(txid, truncated);
}
