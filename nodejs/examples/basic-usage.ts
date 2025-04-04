import {
  Algorithm,
  generateKeyPair,
  sign,
  verify,
  publicKeySize,
  secretKeySize,
  signatureSize,
} from "../src";
import crypto from "crypto";

/**
 * This example demonstrates basic usage of the bitcoinpqc TypeScript bindings.
 *
 * It shows:
 * 1. Getting key and signature sizes
 * 2. Key generation
 * 3. Signing messages
 * 4. Verifying signatures
 * 5. Error handling
 */

// Print key sizes for all algorithms
console.log("===== Key and Signature Sizes =====");
for (const algo of [
  Algorithm.ML_DSA_44,
  Algorithm.SLH_DSA_SHAKE_128S,
  Algorithm.FN_DSA_512,
]) {
  const algoName = Algorithm[algo];
  console.log(`${algoName}:`);
  console.log(`  Public key size: ${publicKeySize(algo)} bytes`);
  console.log(`  Secret key size: ${secretKeySize(algo)} bytes`);
  console.log(`  Signature size: ${signatureSize(algo)} bytes`);
  console.log();
}

// Generate a keypair
function generateKeysAndSign(algorithm: Algorithm, message: string): void {
  console.log(`===== Working with ${Algorithm[algorithm]} =====`);

  // Generate random data for key generation
  console.log("Generating random data...");
  const randomData = crypto.randomBytes(128);

  try {
    // Generate a keypair
    console.log("Generating keypair...");
    const keypair = generateKeyPair(algorithm, randomData);
    console.log(
      `Generated keypair with public key size ${keypair.publicKey.bytes.length} bytes`
    );

    // Create a message to sign
    const messageBytes = Buffer.from(message, "utf-8");
    console.log(`Message to sign: "${message}"`);

    // Sign the message
    console.log("Signing message...");
    const signature = sign(keypair.secretKey, messageBytes);
    console.log(`Created signature of size ${signature.bytes.length} bytes`);

    // Verify the signature
    console.log("Verifying signature...");
    try {
      verify(keypair.publicKey, messageBytes, signature);
      console.log("✅ Signature verified successfully!");
    } catch (error) {
      console.error("❌ Signature verification failed:", error);
    }

    // Try verifying with a different message (should fail with real implementation)
    const badMessage = Buffer.from(message + " (modified)", "utf-8");
    console.log(
      `\nAttempting to verify with modified message: "${message} (modified)"`
    );
    try {
      verify(keypair.publicKey, badMessage, signature);
      console.log("❌ Verification succeeded with modified message!");
    } catch (error) {
      console.log("✅ Verification correctly failed with modified message");
      console.log(`   Error: ${error}`);
    }
  } catch (error) {
    console.error(
      `❌ Error while working with ${Algorithm[algorithm]}:`,
      error
    );
  }

  console.log("\n");
}

// Run examples with working algorithms
generateKeysAndSign(Algorithm.FN_DSA_512, "Hello from FN-DSA-512 (Falcon)!");
generateKeysAndSign(Algorithm.ML_DSA_44, "Hello from ML-DSA-44 (Dilithium)!");
generateKeysAndSign(
  Algorithm.SLH_DSA_SHAKE_128S,
  "Hello from SLH-DSA-SHAKE-128S (SPHINCS+)!"
);
