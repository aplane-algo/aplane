/**
 * Atomic swap example - exchange ALGO between two accounts in a single group.
 *
 * This demonstrates signing a transaction group where both parties must sign.
 * Works with any combination of key types (Ed25519, Falcon, etc.).
 *
 * Setup:
 *   1. Create data directory: mkdir -p ~/.apclient/.ssh
 *   2. Copy token: cp /path/to/aplane.token ~/.apclient/
 *   3. Copy SSH key: cp ~/.ssh/your_key ~/.apclient/.ssh/id_ed25519
 *   4. Create config.yaml (see below)
 *   5. Set env: export APCLIENT_DATA=~/.apclient
 *
 * Example config.yaml (SSH tunnel):
 *   signer_port: 11270
 *   ssh:
 *     host: 192.168.86.73
 *     port: 1127
 *     identity_file: .ssh/id_ed25519
 *
 * Example config.yaml (direct local connection):
 *   signer_port: 11270
 *
 * Important:
 *   - Do NOT pre-assign group IDs with assignGroupID()
 *   - The server computes the group ID after adding any required dummy transactions
 *   - The return value can be passed directly to sendRawTransaction()
 */

import algosdk from "algosdk";
import { SignerClient } from "@aplane/signer";

// Swap parameters (replace with your actual addresses)
const ALICE = "ALICEED255EXAMPLE777777777777777777777777777777777777777777"; // Ed25519 account
const BOB = "BOBFALCONEXAMPLE7777777777777777777777777777777777777777777"; // Falcon account
const SWAP_AMOUNT = 100000; // 0.1 ALGO in microAlgos

async function main() {
  // Connect using config from $APCLIENT_DATA
  const signer = await SignerClient.fromEnv();

  try {
    const algodClient = new algosdk.Algodv2("", "https://testnet-api.4160.nodely.dev", "");
    const params = await algodClient.getTransactionParams().do();

    // Build transactions (do NOT call assignGroupID)
    const txnAliceToBob = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
      sender: ALICE,
      receiver: BOB,
      amount: SWAP_AMOUNT,
      suggestedParams: params,
    });

    const txnBobToAlice = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
      sender: BOB,
      receiver: ALICE,
      amount: SWAP_AMOUNT,
      suggestedParams: params,
    });

    // Resolve auth addresses (handles rekeyed accounts)
    const aliceInfo = await algodClient.accountInformation(ALICE).do();
    const bobInfo = await algodClient.accountInformation(BOB).do();
    const authAddresses = [
      aliceInfo["auth-addr"] || ALICE,
      bobInfo["auth-addr"] || BOB,
    ];

    // Sign the group (server handles grouping and dummies for Falcon)
    console.log(`Signing atomic swap: ${ALICE.slice(0, 8)}... <-> ${BOB.slice(0, 8)}...`);
    const signed = await signer.signTransactions(
      [txnAliceToBob, txnBobToAlice],
      authAddresses
    );

    // Submit using standard algosdk (signed is base64)
    const response = await algodClient.sendRawTransaction(Buffer.from(signed, "base64")).do();
    const txid = response.txid;
    console.log(`Submitted: ${txid}`);

    // Wait for confirmation
    const result = await algosdk.waitForConfirmation(algodClient, txid, 4);
    console.log(`Confirmed in round ${result["confirmed-round"]}`);
    console.log("Atomic swap complete!");
  } finally {
    signer.close();
  }
}

main().catch(console.error);
