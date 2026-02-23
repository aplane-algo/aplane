/**
 * Hashlock claim example - demonstrates generic LogicSig with runtime arguments.
 *
 * This example shows how to claim funds from a hashlock LogicSig by providing
 * the preimage that hashes to the stored hash.
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
 * Prerequisites:
 *   - A hashlock key must exist in the signer's keystore
 *   - The hashlock address must have funds to claim
 *   - You must know the preimage that hashes to the stored hash
 */

import algosdk from "algosdk";
import { SignerClient } from "@aplane/signer";

// The hashlock address (must exist in apsignerd keystore)
const HASHLOCK_ADDRESS = "HASHLOCKEXAMPLE7777777777777777777777777777777777777777";

// The recipient address (where funds will be sent)
const RECIPIENT = "RECIPIENTEXAMPLE777777777777777777777777777777777777777";

// The secret preimage (must hash to the stored hash)
// For SHA256: crypto.createHash('sha256').update(PREIMAGE).digest() === stored_hash
const PREIMAGE = new Uint8Array(Buffer.from("my_secret_preimage_32_bytes_long"));

async function main() {
  // Connect using config from $APCLIENT_DATA
  const signer = await SignerClient.fromEnv();

  try {
    const algodClient = new algosdk.Algodv2("", "https://testnet-api.4160.nodely.dev", "");

    // Discover required arguments for this LogicSig
    const keyInfo = await signer.getKeyInfo(HASHLOCK_ADDRESS);
    if (keyInfo?.runtimeArgs) {
      console.log("Required arguments for this LogicSig:");
      for (const arg of keyInfo.runtimeArgs) {
        console.log(`  - ${arg.name}: ${arg.type} (${arg.description})`);
      }
    }

    // Build claim transaction (send all funds to recipient)
    const params = await algodClient.getTransactionParams().do();
    const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
      sender: HASHLOCK_ADDRESS,
      receiver: RECIPIENT,
      amount: 0, // Use closeRemainderTo to send all funds
      closeRemainderTo: RECIPIENT,
      suggestedParams: params,
    });

    // Sign with the preimage argument
    console.log("Signing hashlock claim with preimage...");
    const signed = await signer.signTransaction(
      txn,
      HASHLOCK_ADDRESS,
      { preimage: PREIMAGE }
    );

    // Submit using standard algosdk (signed is base64)
    const response = await algodClient.sendRawTransaction(Buffer.from(signed, "base64")).do();
    const txid = response.txid;
    console.log(`Submitted: ${txid}`);

    // Wait for confirmation
    const result = await algosdk.waitForConfirmation(algodClient, txid, 4);
    console.log(`Confirmed in round ${result["confirmed-round"]}`);
    console.log("Hashlock claimed successfully!");
  } finally {
    signer.close();
  }
}

main().catch(console.error);
