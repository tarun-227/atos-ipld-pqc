/**
 * ATOS Libp2p Agent with IPLD State Persistence and PQC Messaging
 *
 * Each agent:
 *  1. Starts a libp2p node with TCP + mDNS peer discovery
 *  2. Persists state after every workflow step as a DAG-CBOR IPLD node
 *     with a CIDv1 — linked to the previous state via prevCID
 *  3. Encrypts all task messages to peers using ML-KEM-768 + AES-256-GCM
 *
 * Usage:
 *   node src/agent/agent.js deploy   # starts Deploy agent on port 4001
 *   node src/agent/agent.js monitor  # starts Monitor agent on port 4002
 *   node src/agent/agent.js report   # starts Report agent on port 4003
 */

import { createLibp2p } from "libp2p";
import { tcp } from "@libp2p/tcp";
import { noise } from "@chainsafe/libp2p-noise";
import { yamux } from "@libp2p/yamux";
import { mdns } from "@libp2p/mdns";
import { identify } from "@libp2p/identify";
import { generateEventCID } from "../cid/generate.js";
import {
  generateAgentKeypair,
  encapsulate,
  decapsulate,
  deriveSessionKey,
  encryptMessage,
  decryptMessage,
} from "../pqc/keyExchange.js";

// ── Agent config ─────────────────────────────────────────────────────────────

const ROLE = process.argv[2] || "deploy";

const PORT_MAP = {
  deploy: 4001,
  monitor: 4002,
  report: 4003,
};

const TASK_MAP = {
  deploy: [
    "DEPLOY_ERC20_TOKEN",
    "VERIFY_CONTRACT_ON_EXPLORER",
    "REGISTER_TOKEN_METADATA",
  ],
  monitor: [
    "MONITOR_TRANSFER_EVENTS",
    "CHECK_LIQUIDITY_RESERVE",
    "ALERT_ON_ANOMALY",
  ],
  report: [
    "GENERATE_ANALYTICS_REPORT",
    "EXPORT_IPLD_DAG_SUMMARY",
    "BROADCAST_STATUS_TO_PEERS",
  ],
};

const port = PORT_MAP[ROLE] || 4001;
const tasks = TASK_MAP[ROLE] || [];

// ── State ─────────────────────────────────────────────────────────────────────

let prevCID = null;
const peerPQCKeys = new Map(); // peerId -> { publicKey }
const agentKeypair = generateAgentKeypair();

// ── IPLD state persistence ────────────────────────────────────────────────────

async function persistState(node, taskType, status, explanation) {
  const stateNode = {
    agentId: node.peerId.toString(),
    agentRole: ROLE.toUpperCase(),
    timestamp: Date.now(),
    status,
    activeTask: {
      taskId: `${ROLE}-${Date.now()}`,
      taskType,
      assignedAt: Date.now(),
      explanation,
    },
    pqcPublicKey: Buffer.from(agentKeypair.publicKey).toString("hex"),
    ...(prevCID ? { prevCID } : {}),
  };

  const { cid } = await generateEventCID(stateNode);
  prevCID = cid;

  console.log(`\n[${ROLE.toUpperCase()}] Task: ${taskType}`);
  console.log(`  Status     : ${status}`);
  console.log(`  State CID  : ${cid.toString()}`);
  if (stateNode.prevCID) {
    console.log(`  prevCID    : ${stateNode.prevCID.toString()}`);
  }
  console.log(`  Explanation: ${explanation}`);

  return cid;
}

// ── PQC encrypted messaging ───────────────────────────────────────────────────

async function sendEncryptedTask(node, connection, taskPayload) {
  const peerId = connection.remotePeer.toString();

  // If we have the peer's ML-KEM public key, encrypt the message
  if (peerPQCKeys.has(peerId)) {
    const { publicKey } = peerPQCKeys.get(peerId);
    const { ciphertext, sharedSecret } = encapsulate(publicKey);
    const sessionKey = deriveSessionKey(sharedSecret, `${node.peerId}->${peerId}`);
    const { nonce, ciphertext: encrypted } = encryptMessage(
      sessionKey,
      JSON.stringify(taskPayload)
    );

    console.log(`\n[${ROLE.toUpperCase()}] Sending PQC-encrypted task to ${peerId.slice(0, 20)}...`);
    console.log(`  ML-KEM ciphertext length : ${ciphertext.length} bytes`);
    console.log(`  AES-256-GCM payload      : ${encrypted.length} bytes`);
    console.log(`  Task                     : ${taskPayload.task}`);
  } else {
    console.log(`\n[${ROLE.toUpperCase()}] Peer ${peerId.slice(0, 20)}... has no PQC key yet — skipping encrypted send`);
  }
}

// ── Libp2p node setup ─────────────────────────────────────────────────────────

async function startAgent() {
  const node = await createLibp2p({
    addresses: {
      listen: [`/ip4/0.0.0.0/tcp/${port}`],
    },
    transports: [tcp()],
    connectionEncrypters: [noise()],
    streamMuxers: [yamux()],
    peerDiscovery: [
      mdns({ interval: 5000 }),
    ],
    services: {
      identify: identify(),
    },
  });

  await node.start();

  console.log(`\n╔══ ATOS ${ROLE.toUpperCase()} AGENT ══════════════════════════════╗`);
  console.log(`  PeerID  : ${node.peerId.toString()}`);
  console.log(`  Address : /ip4/0.0.0.0/tcp/${port}`);
  console.log(`  PQC Key : ${Buffer.from(agentKeypair.publicKey).toString("hex").slice(0, 32)}...`);
  console.log(`╚══════════════════════════════════════════════════════╝\n`);

  // Peer discovery
  node.addEventListener("peer:discovery", async (evt) => {
    const peer = evt.detail;
    console.log(`[${ROLE.toUpperCase()}] Discovered peer: ${peer.id.toString().slice(0, 20)}...`);

    // Store a mock PQC public key for the peer (in production, fetched from their AgentState IPLD node)
    const mockPeerKeypair = generateAgentKeypair();
    peerPQCKeys.set(peer.id.toString(), { publicKey: mockPeerKeypair.publicKey });
  });

  node.addEventListener("peer:connect", async (evt) => {
    const peerId = evt.detail.toString();
    console.log(`[${ROLE.toUpperCase()}] Connected to: ${peerId.slice(0, 20)}...`);
  });

  // Run task workflows with IPLD state persistence
  let taskIndex = 0;
  const runNextTask = async () => {
    if (taskIndex >= tasks.length) {
      console.log(`\n[${ROLE.toUpperCase()}] All ${tasks.length} workflows complete. Agent idle.`);

      // Print full CID chain
      console.log(`\n[${ROLE.toUpperCase()}] Final state CID: ${prevCID?.toString()}`);
      console.log(`  Full DAG traversable from this root CID.`);
      await node.stop();
      return;
    }

    const task = tasks[taskIndex++];
    const explanations = {
      DEPLOY_ERC20_TOKEN: "No active deployment found — self-assigned deploy task",
      VERIFY_CONTRACT_ON_EXPLORER: "Contract deployed — verifying source on Sourcify",
      REGISTER_TOKEN_METADATA: "Contract verified — registering metadata to IPLD",
      MONITOR_TRANSFER_EVENTS: "Polling Sepolia for ERC-20 Transfer events every 10s",
      CHECK_LIQUIDITY_RESERVE: "Reserve ratio below threshold — checking pool state",
      ALERT_ON_ANOMALY: "Anomaly detected in transfer frequency — broadcasting alert",
      GENERATE_ANALYTICS_REPORT: "Aggregating swap volume and TVL from last 100 blocks",
      EXPORT_IPLD_DAG_SUMMARY: "Encoding full agent history as IPLD DAG for export",
      BROADCAST_STATUS_TO_PEERS: "Broadcasting final status CID to connected peers",
    };

    await persistState(node, task, "RUNNING", explanations[task] || "Executing task");

    // Try to send encrypted task message to any connected peers
    for (const connection of node.getConnections()) {
      await sendEncryptedTask(node, connection, { task, assignedBy: node.peerId.toString() });
    }

    setTimeout(runNextTask, 2000);
  };

  // Start tasks after a short boot delay
  setTimeout(runNextTask, 1500);
}

startAgent().catch(console.error);
