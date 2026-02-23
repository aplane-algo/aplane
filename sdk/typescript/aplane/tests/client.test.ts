// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { SignerClient } from "../src/client.js";
import {
  AuthenticationError,
  SigningRejectedError,
  SignerUnavailableError,
  KeyNotFoundError,
} from "../src/errors.js";
import { bytesToHex, hexToBytes, concatenateSignedTxns } from "../src/encoding.js";

// Mock fetch globally
const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

describe("SignerClient", () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("connectLocal", () => {
    it("creates client with default options", () => {
      const client = SignerClient.connectLocal("test-token");
      expect(client).toBeInstanceOf(SignerClient);
    });

    it("creates client with custom options", () => {
      const client = SignerClient.connectLocal("test-token", {
        host: "custom-host",
        port: 12345,
        timeout: 60000,
      });
      expect(client).toBeInstanceOf(SignerClient);
    });
  });

  describe("health", () => {
    it("returns true when signer is healthy", async () => {
      mockFetch.mockResolvedValueOnce({
        status: 200,
        ok: true,
      });

      const client = SignerClient.connectLocal("test-token");
      const result = await client.health();

      expect(result).toBe(true);
      expect(mockFetch).toHaveBeenCalledWith(
        "http://localhost:11270/health",
        expect.objectContaining({
          method: "GET",
        })
      );
    });

    it("returns false when signer is unavailable", async () => {
      mockFetch.mockResolvedValueOnce({
        status: 503,
        ok: false,
      });

      const client = SignerClient.connectLocal("test-token");
      const result = await client.health();

      expect(result).toBe(false);
    });

    it("returns false on network error", async () => {
      mockFetch.mockRejectedValueOnce(new Error("Network error"));

      const client = SignerClient.connectLocal("test-token");
      const result = await client.health();

      expect(result).toBe(false);
    });
  });

  describe("listKeys", () => {
    it("returns list of keys", async () => {
      const mockKeys = {
        count: 2,
        keys: [
          {
            address: "ADDR1",
            publicKeyHex: "abc123",
            keyType: "ed25519",
            lsigSize: 0,
            isGenericLsig: false,
          },
          {
            address: "ADDR2",
            publicKeyHex: "def456",
            keyType: "falcon1024-v1",
            lsigSize: 3035,
            isGenericLsig: false,
          },
        ],
      };

      mockFetch.mockResolvedValueOnce({
        status: 200,
        ok: true,
        json: async () => mockKeys,
      });

      const client = SignerClient.connectLocal("test-token");
      const keys = await client.listKeys();

      expect(keys).toHaveLength(2);
      expect(keys[0].address).toBe("ADDR1");
      expect(keys[0].keyType).toBe("ed25519");
      expect(keys[1].address).toBe("ADDR2");
      expect(keys[1].lsigSize).toBe(3035);
    });

    it("throws AuthenticationError on 401", async () => {
      mockFetch.mockResolvedValueOnce({
        status: 401,
        ok: false,
      });

      const client = SignerClient.connectLocal("test-token");
      await expect(client.listKeys()).rejects.toThrow(AuthenticationError);
    });

    it("uses cache on subsequent calls", async () => {
      const mockKeys = {
        count: 1,
        keys: [{ address: "ADDR1", keyType: "ed25519" }],
      };

      // Set up mock for both calls (first and refresh)
      mockFetch
        .mockResolvedValueOnce({
          status: 200,
          ok: true,
          json: async () => mockKeys,
        })
        .mockResolvedValueOnce({
          status: 200,
          ok: true,
          json: async () => mockKeys,
        });

      const client = SignerClient.connectLocal("test-token");

      // First call fetches from server
      await client.listKeys();
      expect(mockFetch).toHaveBeenCalledTimes(1);

      // Second call uses cache
      await client.listKeys();
      expect(mockFetch).toHaveBeenCalledTimes(1);

      // Third call with refresh fetches again
      await client.listKeys(true);
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });
  });

  describe("signing errors", () => {
    // Create a mock transaction-like object for testing
    const createMockTxn = () => ({
      sender: {
        toString: () => "SENDER_ADDRESS",
      },
      toByte: () => new Uint8Array([1, 2, 3, 4]),
    });

    it("throws AuthenticationError on 401", async () => {
      mockFetch.mockResolvedValueOnce({
        status: 401,
        ok: false,
      });

      const client = SignerClient.connectLocal("test-token");
      // Cast to bypass type checking for mock transaction
      const mockTxn = createMockTxn() as Parameters<typeof client.signTransaction>[0];

      await expect(client.signTransaction(mockTxn)).rejects.toThrow(
        AuthenticationError
      );
    });

    it("throws SigningRejectedError on 403", async () => {
      mockFetch.mockResolvedValueOnce({
        status: 403,
        ok: false,
        json: async () => ({ error: "Operator rejected" }),
      });

      const client = SignerClient.connectLocal("test-token");
      const mockTxn = createMockTxn() as Parameters<typeof client.signTransaction>[0];

      await expect(client.signTransaction(mockTxn)).rejects.toThrow(
        SigningRejectedError
      );
    });

    it("throws SignerUnavailableError on 503", async () => {
      mockFetch.mockResolvedValueOnce({
        status: 503,
        ok: false,
        json: async () => ({ error: "Signer locked" }),
      });

      const client = SignerClient.connectLocal("test-token");
      const mockTxn = createMockTxn() as Parameters<typeof client.signTransaction>[0];

      await expect(client.signTransaction(mockTxn)).rejects.toThrow(
        SignerUnavailableError
      );
    });

    it("throws KeyNotFoundError on 400 with 'not found'", async () => {
      mockFetch.mockResolvedValueOnce({
        status: 400,
        ok: false,
        json: async () => ({ error: "Key not found: INVALID_ADDRESS" }),
        text: async () => "Key not found: INVALID_ADDRESS",
      });

      const client = SignerClient.connectLocal("test-token");
      const mockTxn = createMockTxn() as Parameters<typeof client.signTransaction>[0];

      await expect(client.signTransaction(mockTxn)).rejects.toThrow(
        KeyNotFoundError
      );
    });

    it("throws SignerUnavailableError on timeout", async () => {
      const abortError = new Error("Abort");
      abortError.name = "AbortError";
      mockFetch.mockRejectedValueOnce(abortError);

      const client = SignerClient.connectLocal("test-token", { timeout: 100 });
      const mockTxn = createMockTxn() as Parameters<typeof client.signTransaction>[0];

      await expect(client.signTransaction(mockTxn)).rejects.toThrow(
        SignerUnavailableError
      );
    });
  });
});

describe("encoding utilities", () => {
  describe("bytesToHex", () => {
    it("converts Uint8Array to hex string", () => {
      const bytes = new Uint8Array([0, 1, 255, 16, 171]);
      expect(bytesToHex(bytes)).toBe("0001ff10ab");
    });

    it("handles empty array", () => {
      expect(bytesToHex(new Uint8Array([]))).toBe("");
    });
  });

  describe("hexToBytes", () => {
    it("converts hex string to Uint8Array", () => {
      const hex = "0001ff10ab";
      const bytes = hexToBytes(hex);
      expect(bytes).toEqual(new Uint8Array([0, 1, 255, 16, 171]));
    });

    it("handles empty string", () => {
      expect(hexToBytes("")).toEqual(new Uint8Array([]));
    });
  });

  describe("concatenateSignedTxns", () => {
    it("concatenates hex strings to base64", () => {
      const hexes = ["0102", "0304"];
      const result = concatenateSignedTxns(hexes);
      // Should be base64 of [1, 2, 3, 4]
      expect(result).toBe("AQIDBA==");
    });

    it("handles single transaction", () => {
      const hexes = ["deadbeef"];
      const result = concatenateSignedTxns(hexes);
      // Should be base64 of [0xde, 0xad, 0xbe, 0xef]
      expect(result).toBe("3q2+7w==");
    });
  });
});
