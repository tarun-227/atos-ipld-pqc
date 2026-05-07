/**
 * CID generation pipeline for ATOS lifecycle events.
 * Uses multiformats + @ipld/dag-cbor to produce content-addressed
 * identifiers for every token and agent event in the system.
 */

import { CID } from "multiformats/cid";
import { encode } from "@ipld/dag-cbor";
import { sha256 } from "multiformats/hashes/sha2";
import * as dagCBOR from "@ipld/dag-cbor";

/**
 * Generate a CID for any ATOS event object.
 * The object must conform to one of the IPLD schemas in /schemas.
 *
 * @param {object} eventData - The event payload (TokenDeployEvent, TransferEvent, etc.)
 * @returns {Promise<{cid: CID, encoded: Uint8Array}>}
 */
export async function generateEventCID(eventData) {
  // Encode to DAG-CBOR bytes
  const encoded = encode(eventData);

  // Hash with SHA-256 and wrap in CIDv1 with dag-cbor codec
  const hash = await sha256.digest(encoded);
  const cid = CID.createV1(dagCBOR.code, hash);

  return { cid, encoded };
}

/**
 * Build a linked DAG chain from an ordered array of events.
 * Each event's prevCID points to the CID of the previous event,
 * forming a verifiable append-only log.
 *
 * @param {object[]} events - Ordered array of event objects
 * @returns {Promise<Array<{event: object, cid: CID}>>}
 */
export async function buildEventChain(events) {
  const chain = [];
  let prevCID = null;

  for (const event of events) {
    const linked = prevCID ? { ...event, prevCID } : { ...event };
    const { cid } = await generateEventCID(linked);
    chain.push({ event: linked, cid });
    prevCID = cid;
  }

  return chain;
}

// ── Demo ────────────────────────────────────────────────────────────────────
// Run: node --experimental-vm-modules src/cid/generate.js

const deployEvent = {
  eventType: "TOKEN_DEPLOY",
  agentId: "12D3KooWExample",
  timestamp: Date.now(),
  contract: {
    name: "ATOSToken",
    symbol: "ATOS",
    decimals: 18,
    totalSupply: "2000000000000000000000000",
    address: "0x480763D755d5A145c4A233873aE899ADCB9124eE",
    bytecodeHash: "0xabc123",
  },
  deployer: "0xDeployer",
  txHash: "0xTxHash",
  network: "sepolia",
};

const transferEvent = {
  eventType: "TOKEN_TRANSFER",
  agentId: "12D3KooWExample",
  timestamp: Date.now(),
  from: "0xDeployer",
  to: "0xRecipient",
  amount: "1000000000000000000",
  txHash: "0xTransferTx",
  blockNumber: 8400000,
  network: "sepolia",
};

const chain = await buildEventChain([deployEvent, transferEvent]);
chain.forEach(({ event, cid }) => {
  console.log(`[${event.eventType}] CID: ${cid.toString()}`);
  if (event.prevCID) console.log(`  └─ prevCID: ${event.prevCID.toString()}`);
});
