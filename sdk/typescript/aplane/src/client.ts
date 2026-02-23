// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

import * as fs from "fs";
import * as path from "path";
import * as net from "net";
import type { Transaction } from "algosdk";
import type { Client as SSHClient, ClientChannel } from "ssh2";
import type {
  KeyInfo,
  ConnectLocalOptions,
  ConnectSshOptions,
  FromEnvOptions,
  LsigArgs,
  LsigArgsMap,
  SignRequest,
  GroupSignResponse,
  KeysResponse,
  RuntimeArg,
} from "./types.js";
import {
  SignerError,
  AuthenticationError,
  SigningRejectedError,
  SignerUnavailableError,
  KeyNotFoundError,
} from "./errors.js";
import {
  encodeTransaction,
  encodeLsigArgs,
  concatenateSignedTxns,
} from "./encoding.js";
import {
  loadConfig,
  loadTokenFromDir,
  resolveDataDir,
  expandPath,
  DEFAULT_SIGNER_PORT,
  DEFAULT_SSH_PORT,
} from "./config.js";

/** Default request timeout in milliseconds (90s for operator approval wait) */
const DEFAULT_TIMEOUT = 90000;

/**
 * Find an available local port.
 */
async function findFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (addr && typeof addr === "object") {
        const port = addr.port;
        server.close(() => resolve(port));
      } else {
        reject(new Error("Could not get server address"));
      }
    });
  });
}

/**
 * SSH tunnel wrapper that forwards a local port to a remote port.
 */
class SSHTunnel {
  private sshClient: SSHClient | null = null;
  private server: net.Server | null = null;
  localPort: number = 0;

  async connect(options: {
    host: string;
    sshPort: number;
    username: string;
    privateKeyPath: string;
    remoteHost: string;
    remotePort: number;
  }): Promise<void> {
    // Dynamically import ssh2
    const { Client } = await import("ssh2");

    const privateKey = fs.readFileSync(options.privateKeyPath, "utf-8");
    this.localPort = await findFreePort();

    return new Promise((resolve, reject) => {
      this.sshClient = new Client();

      this.sshClient.on("ready", () => {
        // Create local server that forwards to remote via SSH
        this.server = net.createServer((localSocket) => {
          this.sshClient!.forwardOut(
            "127.0.0.1",
            this.localPort,
            options.remoteHost,
            options.remotePort,
            (err: Error | undefined, channel: ClientChannel) => {
              if (err) {
                localSocket.destroy();
                return;
              }
              localSocket.pipe(channel).pipe(localSocket);
            }
          );
        });

        this.server.listen(this.localPort, "127.0.0.1", () => {
          resolve();
        });

        this.server.on("error", (err) => {
          reject(new SignerUnavailableError(`SSH tunnel server error: ${err.message}`));
        });
      });

      this.sshClient.on("error", (err: Error) => {
        reject(new SignerUnavailableError(`SSH connection failed: ${err.message}`));
      });

      this.sshClient.connect({
        host: options.host,
        port: options.sshPort,
        username: options.username,
        privateKey: privateKey,
      });
    });
  }

  close(): void {
    if (this.server) {
      this.server.close();
      this.server = null;
    }
    if (this.sshClient) {
      this.sshClient.end();
      this.sshClient = null;
    }
  }
}

/**
 * Client for apsignerd signing service.
 *
 * Use static methods to create instances:
 * ```typescript
 * // Local connection
 * const client = SignerClient.connectLocal("your-token");
 *
 * // SSH tunnel connection
 * const client = await SignerClient.connectSsh(
 *   "signer.example.com",
 *   "your-token",
 *   "~/.ssh/id_ed25519"
 * );
 *
 * // From environment/config
 * const client = await SignerClient.fromEnv();
 *
 * // Sign transactions
 * const signed = await client.signTransaction(txn);
 *
 * // Close when done (important for SSH)
 * client.close();
 * ```
 */
export class SignerClient {
  private baseUrl: string;
  private token: string;
  private timeout: number;
  private keyCache: Map<string, KeyInfo> = new Map();
  private tunnel: SSHTunnel | null = null;

  /**
   * Create a SignerClient instance (use static methods instead).
   */
  private constructor(
    baseUrl: string,
    token: string,
    timeout: number,
    tunnel: SSHTunnel | null = null
  ) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.token = token;
    this.timeout = timeout;
    this.tunnel = tunnel;
  }

  /**
   * Connect to a local apsignerd instance.
   *
   * @param token - Authentication token
   * @param options - Connection options
   * @returns SignerClient instance
   *
   * @example
   * ```typescript
   * const client = SignerClient.connectLocal("your-token");
   * const client = SignerClient.connectLocal("your-token", { port: 11270, timeout: 90000 });
   * ```
   */
  static connectLocal(
    token: string,
    options: ConnectLocalOptions = {}
  ): SignerClient {
    const host = options.host ?? "localhost";
    const port = options.port ?? DEFAULT_SIGNER_PORT;
    const timeout = options.timeout ?? DEFAULT_TIMEOUT;

    const baseUrl = `http://${host}:${port}`;
    return new SignerClient(baseUrl, token, timeout);
  }

  /**
   * Connect to remote apsignerd via SSH tunnel.
   *
   * Establishes an SSH tunnel to the remote host and forwards
   * the signer port to a local port. Uses 2FA: token (as SSH username)
   * + public key authentication.
   *
   * @param host - Remote host running apsignerd
   * @param token - Authentication token (used for both SSH and HTTP API)
   * @param sshKeyPath - Path to SSH private key (e.g., ~/.ssh/id_ed25519)
   * @param options - Connection options
   * @returns Promise<SignerClient> instance with active SSH tunnel
   *
   * @example
   * ```typescript
   * const client = await SignerClient.connectSsh(
   *   "signer.example.com",
   *   "your-token",
   *   "~/.ssh/id_ed25519"
   * );
   *
   * // Use the client...
   * const signed = await client.signTransaction(txn);
   *
   * // Close when done
   * client.close();
   * ```
   */
  static async connectSsh(
    host: string,
    token: string,
    sshKeyPath: string,
    options: ConnectSshOptions = {}
  ): Promise<SignerClient> {
    const sshPort = options.sshPort ?? DEFAULT_SSH_PORT;
    const signerPort = options.signerPort ?? DEFAULT_SIGNER_PORT;
    const timeout = options.timeout ?? DEFAULT_TIMEOUT;

    const expandedKeyPath = expandPath(sshKeyPath);

    if (!fs.existsSync(expandedKeyPath)) {
      throw new SignerError(`SSH key not found: ${expandedKeyPath}`);
    }

    const tunnel = new SSHTunnel();

    try {
      // Token is used as SSH username for 2FA (token + public key)
      await tunnel.connect({
        host,
        sshPort,
        username: token,
        privateKeyPath: expandedKeyPath,
        remoteHost: "127.0.0.1",
        remotePort: signerPort,
      });
    } catch (error) {
      tunnel.close();
      if (error instanceof SignerError) {
        throw error;
      }
      throw new SignerUnavailableError(
        `SSH tunnel failed: ${error instanceof Error ? error.message : String(error)}`
      );
    }

    // Connect through tunnel
    const baseUrl = `http://127.0.0.1:${tunnel.localPort}`;
    const client = new SignerClient(baseUrl, token, timeout, tunnel);

    // Verify connection
    const healthy = await client.health();
    if (!healthy) {
      client.close();
      throw new SignerUnavailableError(
        `Connected via SSH but signer not responding on port ${signerPort}`
      );
    }

    return client;
  }

  /**
   * Connect using config file from data directory.
   *
   * Data directory (default: ~/.aplane):
   *   - config.yaml: Connection settings (signer_port, ssh)
   *   - aplane.token: Authentication token
   *   - .ssh/id_ed25519: SSH key (if using SSH tunnel)
   *
   * @param options - Connection options
   * @returns Promise<SignerClient> instance
   *
   * @example
   * ```typescript
   * // Uses ~/.aplane by default
   * const client = await SignerClient.fromEnv();
   *
   * // Or override
   * const client = await SignerClient.fromEnv({ dataDir: "/custom/path" });
   * ```
   */
  static async fromEnv(options: FromEnvOptions = {}): Promise<SignerClient> {
    const dataDir = resolveDataDir(options.dataDir);
    const timeout = options.timeout ?? DEFAULT_TIMEOUT;

    // Load config from data_dir/config.yaml
    const config = loadConfig(dataDir);

    // Load token from data directory
    const token = loadTokenFromDir(dataDir);

    // Check if SSH is configured
    if (config.ssh) {
      // Resolve SSH key path (relative to data_dir)
      const sshKeyPath = path.join(dataDir, config.ssh.identityFile);

      if (!fs.existsSync(sshKeyPath)) {
        throw new SignerError(`SSH configured but key not found at ${sshKeyPath}`);
      }

      return SignerClient.connectSsh(config.ssh.host, token, sshKeyPath, {
        sshPort: config.ssh.port,
        signerPort: config.signerPort,
        timeout,
      });
    }

    // Direct connection to localhost (no SSH tunnel)
    return SignerClient.connectLocal(token, {
      port: config.signerPort,
      timeout,
    });
  }

  /**
   * Close the client and any SSH tunnel.
   */
  close(): void {
    if (this.tunnel) {
      this.tunnel.close();
      this.tunnel = null;
    }
  }

  /**
   * Check if signer is healthy and reachable.
   *
   * @returns true if healthy, false otherwise
   */
  async health(): Promise<boolean> {
    try {
      const response = await this.fetch("/health", {
        method: "GET",
        timeout: 5000, // 5s for health checks
      });
      return response.status === 200;
    } catch {
      return false;
    }
  }

  /**
   * List available signing keys.
   *
   * @param refresh - If true, bypass cache and fetch fresh data
   * @returns List of KeyInfo with address, keyType, etc.
   */
  async listKeys(refresh: boolean = false): Promise<KeyInfo[]> {
    if (!refresh && this.keyCache.size > 0) {
      return Array.from(this.keyCache.values());
    }

    const response = await this.fetch("/keys", { method: "GET", timeout: 10000 });

    if (response.status === 401) {
      throw new AuthenticationError();
    }

    if (response.status !== 200) {
      throw new SignerError(`Failed to list keys: HTTP ${response.status}`);
    }

    const data = (await response.json()) as KeysResponse;
    const keys: KeyInfo[] = [];

    for (const k of data.keys || []) {
      // Parse runtime_args, mapping snake_case API fields to camelCase TypeScript
      let runtimeArgs: RuntimeArg[] | undefined;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const rawArgs = (k as any).runtime_args;
      if (rawArgs) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        runtimeArgs = rawArgs.map((arg: any) => ({
          name: arg.name,
          type: arg.type || "bytes",
          description: arg.description || "",
          label: arg.label,
          required: arg.required,
          byteLength: arg.byte_length,
        }));
      }

      // Map snake_case API fields to camelCase TypeScript interface
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const raw = k as any;
      const keyInfo: KeyInfo = {
        address: k.address,
        publicKeyHex: raw.public_key_hex || "",
        keyType: raw.key_type || "",
        lsigSize: raw.lsig_size || 0,
        isGenericLsig: raw.is_generic_lsig || false,
        runtimeArgs,
      };
      keys.push(keyInfo);
      this.keyCache.set(keyInfo.address, keyInfo);
    }

    return keys;
  }

  /**
   * Get key info for a specific address.
   *
   * @param address - The Algorand address to look up
   * @returns KeyInfo if found, undefined otherwise
   */
  async getKeyInfo(address: string): Promise<KeyInfo | undefined> {
    if (!this.keyCache.has(address)) {
      await this.listKeys(true);
    }
    return this.keyCache.get(address);
  }

  /**
   * Sign a transaction via apsignerd.
   *
   * The server automatically handles:
   * - Dummy transaction creation for large LogicSigs (e.g., Falcon-1024)
   * - Fee pooling (distributes fees across the group)
   * - Group ID computation
   *
   * @param txn - algosdk Transaction object
   * @param authAddress - Key to sign with (defaults to txn.sender)
   * @param lsigArgs - Optional runtime args for generic LogicSigs
   * @returns Base64-encoded signed transaction(s), ready for algodClient.sendRawTransaction()
   *
   * @example
   * ```typescript
   * // Basic signing (uses txn.sender as authAddress)
   * const signed = await client.signTransaction(txn);
   *
   * // Rekeyed account
   * const signed = await client.signTransaction(txn, "SIGNER_KEY_ADDRESS");
   *
   * // Generic LogicSig with runtime args
   * const signed = await client.signTransaction(txn, hashlockAddr, {
   *   preimage: new Uint8Array([...])
   * });
   * ```
   */
  async signTransaction(
    txn: Transaction,
    authAddress?: string,
    lsigArgs?: LsigArgs
  ): Promise<string> {
    const auth = authAddress ?? txn.sender.toString();
    const lsigArgsMap = lsigArgs ? { [auth]: lsigArgs } : undefined;

    const signedList = await this.signRequest([txn], [auth], lsigArgsMap);

    // Concatenate all signed txns and return as single base64 string
    return concatenateSignedTxns(signedList);
  }

  /**
   * Sign multiple transactions as a group.
   *
   * The server automatically handles:
   * - Group ID computation (for 2+ transactions)
   * - Dummy transaction creation for large LogicSigs
   * - Fee pooling across the group
   *
   * Note: Transactions should NOT have group IDs pre-assigned.
   * The server computes the group ID after adding any required dummies.
   *
   * @param txns - List of algosdk Transaction objects
   * @param authAddresses - List of auth addresses (one per txn), defaults to each txn's sender
   * @param lsigArgsMap - Optional mapping of address -> lsigArgs
   * @returns Base64-encoded concatenated signed transactions for the entire group
   *
   * @example
   * ```typescript
   * // Build transactions (do NOT call assignGroupId)
   * const txn1 = algosdk.makePaymentTxnWithSuggestedParams(...);
   * const txn2 = algosdk.makePaymentTxnWithSuggestedParams(...);
   *
   * // Sign group (server handles grouping and dummies)
   * const signed = await client.signTransactions([txn1, txn2]);
   *
   * // Submit directly
   * await algodClient.sendRawTransaction(Buffer.from(signed, "base64")).do();
   * ```
   */
  async signTransactions(
    txns: Transaction[],
    authAddresses?: string[],
    lsigArgsMap?: LsigArgsMap
  ): Promise<string> {
    const authAddrs =
      authAddresses ?? txns.map((txn) => txn.sender.toString());

    if (authAddrs.length !== txns.length) {
      throw new Error("authAddresses length must match txns length");
    }

    const signedList = await this.signRequest(txns, authAddrs, lsigArgsMap);

    // Concatenate all signed txns and return as single base64 string
    return concatenateSignedTxns(signedList);
  }

  /**
   * Sign multiple transactions and return as a list.
   *
   * Like signTransactions() but returns individual base64-encoded signed
   * transactions instead of concatenated. Useful when you need to inspect
   * or handle transactions individually.
   *
   * @param txns - List of algosdk Transaction objects
   * @param authAddresses - List of auth addresses (one per txn)
   * @param lsigArgsMap - Optional mapping of address -> lsigArgs
   * @returns List of base64-encoded signed transactions (includes any dummies)
   */
  async signTransactionsList(
    txns: Transaction[],
    authAddresses?: string[],
    lsigArgsMap?: LsigArgsMap
  ): Promise<string[]> {
    const authAddrs =
      authAddresses ?? txns.map((txn) => txn.sender.toString());

    if (authAddrs.length !== txns.length) {
      throw new Error("authAddresses length must match txns length");
    }

    const signedHexes = await this.signRequest(txns, authAddrs, lsigArgsMap);

    // Convert each hex to base64
    return signedHexes.map((hex) => {
      const bytes = new Uint8Array(hex.length / 2);
      for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
      }
      if (typeof Buffer !== "undefined") {
        return Buffer.from(bytes).toString("base64");
      }
      const binary = String.fromCharCode(...bytes);
      return btoa(binary);
    });
  }

  /**
   * Send signing request to the unified /sign endpoint.
   * Returns hex-encoded signed transactions.
   */
  private async signRequest(
    txns: Transaction[],
    authAddresses: string[],
    lsigArgsMap?: LsigArgsMap
  ): Promise<string[]> {
    // Build request array
    const signRequests: SignRequest[] = [];
    for (let i = 0; i < txns.length; i++) {
      const txn = txns[i];
      const authAddr = authAddresses[i];
      const [txnBytesHex, txnSender] = encodeTransaction(txn);

      const req: SignRequest = {
        txn_bytes_hex: txnBytesHex,
        auth_address: authAddr,
        txn_sender: txnSender,
      };

      // Add LogicSig args if provided
      if (lsigArgsMap && lsigArgsMap[authAddr]) {
        req.lsig_args = encodeLsigArgs(lsigArgsMap[authAddr]);
      }

      signRequests.push(req);
    }

    // Send to /sign endpoint
    const requestBody = { requests: signRequests };

    const response = await this.fetch("/sign", {
      method: "POST",
      body: JSON.stringify(requestBody),
    });

    // Handle errors
    if (response.status === 401) {
      throw new AuthenticationError();
    }

    if (response.status === 400) {
      const data = await this.safeJson(response);
      const error = String(data.error || (await response.text()));
      if (error.toLowerCase().includes("not found")) {
        throw new KeyNotFoundError(error);
      }
      throw new SignerError(`Bad request: ${error}`);
    }

    if (response.status === 403) {
      const data = await this.safeJson(response);
      const error = String(data.error || "Signing request rejected by operator");
      throw new SigningRejectedError(error);
    }

    if (response.status === 503) {
      const data = await this.safeJson(response);
      const error = String(data.error || "Signer unavailable");
      throw new SignerUnavailableError(error);
    }

    if (response.status !== 200) {
      throw new SignerError(`Signing failed: HTTP ${response.status}`);
    }

    // Parse successful response
    let data: GroupSignResponse;
    try {
      data = (await response.json()) as GroupSignResponse;
    } catch {
      throw new SignerError("Server returned invalid JSON");
    }

    if (data.error) {
      throw new SignerError(data.error);
    }

    // Return hex-encoded signed transactions
    const signedHexes = data.signed || [];
    if (signedHexes.length === 0) {
      throw new SignerError("Server returned no signed transactions");
    }

    return signedHexes;
  }

  /**
   * Parse JSON response safely, returning empty object on failure.
   */
  private async safeJson(response: Response): Promise<Record<string, unknown>> {
    try {
      return (await response.json()) as Record<string, unknown>;
    } catch {
      return {};
    }
  }

  /**
   * Make an HTTP request with authentication and timeout.
   */
  private async fetch(
    path: string,
    options: {
      method: string;
      body?: string;
      timeout?: number;
    }
  ): Promise<Response> {
    const url = this.baseUrl + path;
    const timeout = options.timeout ?? this.timeout;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    try {
      const headers: Record<string, string> = {
        Authorization: `aplane ${this.token}`,
      };

      if (options.body) {
        headers["Content-Type"] = "application/json";
      }

      const response = await fetch(url, {
        method: options.method,
        headers,
        body: options.body,
        signal: controller.signal,
      });

      return response;
    } catch (error) {
      if (error instanceof Error && error.name === "AbortError") {
        throw new SignerUnavailableError(`Request timed out after ${timeout}ms`);
      }
      throw new SignerUnavailableError(
        `Failed to connect: ${error instanceof Error ? error.message : String(error)}`
      );
    } finally {
      clearTimeout(timeoutId);
    }
  }
}
