/**
 * PQC Key Exchange for ATOS agent-to-agent communication.
 *
 * Uses ML-KEM-768 (CRYSTALS-Kyber) for post-quantum key encapsulation,
 * then derives a shared AES-256-GCM session key for message encryption.
 *
 * Flow:
 *   1. Each agent generates an ML-KEM keypair on startup
 *   2. Public keys are broadcast via libp2p and stored in AgentState (IPLD)
 *   3. Sender encapsulates a shared secret using recipient's public key
 *   4. Recipient decapsulates to recover the same shared secret
 *   5. Both sides derive an AES-256 key from the shared secret via HKDF
 *   6. All subsequent messages are encrypted with AES-256-GCM
 */

import { ml_kem768 } from "@noble/post-quantum/ml-kem";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { gcm } from "@noble/ciphers/aes";
import { randomBytes } from "@noble/ciphers/webcrypto";

/**
 * Generate an ML-KEM-768 keypair for an agent.
 * The public key should be stored in AgentState IPLD node for peers to fetch.
 *
 * @returns {{ publicKey: Uint8Array, secretKey: Uint8Array }}
 */
export function generateAgentKeypair() {
  const seed = randomBytes(64);
  return ml_kem768.keygen(seed);
}

/**
 * Sender side: encapsulate a shared secret using the recipient's ML-KEM public key.
 *
 * @param {Uint8Array} recipientPublicKey
 * @returns {{ ciphertext: Uint8Array, sharedSecret: Uint8Array }}
 */
export function encapsulate(recipientPublicKey) {
  const seed = randomBytes(32);
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(
    recipientPublicKey,
    seed
  );
  return { ciphertext: cipherText, sharedSecret };
}

/**
 * Recipient side: decapsulate to recover the shared secret.
 *
 * @param {Uint8Array} ciphertext
 * @param {Uint8Array} secretKey
 * @returns {Uint8Array} sharedSecret
 */
export function decapsulate(ciphertext, secretKey) {
  return ml_kem768.decapsulate(ciphertext, secretKey);
}

/**
 * Derive a 32-byte AES-256 session key from the ML-KEM shared secret using HKDF.
 *
 * @param {Uint8Array} sharedSecret
 * @param {string} info - Context string (e.g. sender + recipient peer IDs)
 * @returns {Uint8Array} 32-byte AES key
 */
export function deriveSessionKey(sharedSecret, info = "atos-agent-channel") {
  return hkdf(sha256, sharedSecret, undefined, info, 32);
}

/**
 * Encrypt a message with AES-256-GCM using a derived session key.
 *
 * @param {Uint8Array} sessionKey
 * @param {string} message
 * @returns {{ nonce: Uint8Array, ciphertext: Uint8Array }}
 */
export function encryptMessage(sessionKey, message) {
  const nonce = randomBytes(24);
  const stream = gcm(sessionKey, nonce);
  const ciphertext = stream.encrypt(new TextEncoder().encode(message));
  return { nonce, ciphertext };
}

/**
 * Decrypt a message with AES-256-GCM.
 *
 * @param {Uint8Array} sessionKey
 * @param {Uint8Array} nonce
 * @param {Uint8Array} ciphertext
 * @returns {string}
 */
export function decryptMessage(sessionKey, nonce, ciphertext) {
  const stream = gcm(sessionKey, nonce);
  return new TextDecoder().decode(stream.decrypt(ciphertext));
}

// ── Demo ────────────────────────────────────────────────────────────────────

// Agent A generates keypair
const agentA = generateAgentKeypair();
// Agent B generates keypair
const agentB = generateAgentKeypair();

// Agent A encapsulates a shared secret using B's public key
const { ciphertext, sharedSecret: secretA } = encapsulate(agentB.publicKey);

// Agent B decapsulates using its secret key
const secretB = decapsulate(ciphertext, agentB.secretKey);

// Both derive the same AES session key
const sessionKeyA = deriveSessionKey(secretA, "agentA->agentB");
const sessionKeyB = deriveSessionKey(secretB, "agentA->agentB");

// Agent A encrypts a task message
const msg = JSON.stringify({ task: "DEPLOY_TOKEN", contractName: "ATOSToken" });
const { nonce, ciphertext: encrypted } = encryptMessage(sessionKeyA, msg);

// Agent B decrypts it
const decrypted = decryptMessage(sessionKeyB, nonce, encrypted);

console.log("Shared secrets match:", secretA.toString() === secretB.toString());
console.log("Decrypted message:", decrypted);
