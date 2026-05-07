# atos-ipld-pqc

IPLD schemas, multiformats CID pipeline, and post-quantum cryptography layer for the ATOS multi-agent system.

This repo focuses on three infrastructure pillars of the [ParkGHO ATOS project](https://github.com/seetadev/ParkGHO-Family/issues/35):

---

## What's here

### `/schemas` — IPLD Schemas
DAG-CBOR schemas for every ERC-20 lifecycle event and agent state:
- `token-deploy.ipldsch` — token deployment event
- `token-transfer.ipldsch` — on-chain transfer event
- `liquidity-event.ipldsch` — add/remove liquidity and swap events
- `agent-state.ipldsch` — per-agent state with task refs and PQC public key

Each schema node links to the previous event via `prevCID`, forming a verifiable append-only DAG across the token's lifecycle.

### `/src/cid` — Multiformats CID Pipeline
`generate.js` — Encodes any ATOS event object to DAG-CBOR and produces a CIDv1 using SHA-256. Also includes `buildEventChain()` which chains events with `prevCID` links automatically.

### `/src/pqc` — Post-Quantum Key Exchange
`keyExchange.js` — Full ML-KEM-768 (CRYSTALS-Kyber) key encapsulation + AES-256-GCM message encryption pipeline for secure agent-to-agent communication.

Flow:
1. Each agent generates an ML-KEM keypair on startup
2. Public key is stored in `AgentState` IPLD node for peers to fetch
3. Sender encapsulates a shared secret using recipient's public key
4. Recipient decapsulates to recover the shared secret
5. Both derive an AES-256 key via HKDF-SHA256
6. Messages encrypted with AES-256-GCM + random nonce

---

## Run demos

```bash
npm install
npm run cid-demo    # generates CID chain for a deploy + transfer event
npm run pqc-demo    # runs full ML-KEM key exchange + encrypt/decrypt round-trip
```

---

## Roadmap

- [ ] Wire CID pipeline into agent state persistence
- [ ] Integrate PQC layer into libp2p message handler
- [ ] Push verified event CIDs to IPFS/Filecoin via Storacha
- [ ] Runtime schema validation against `.ipldsch` definitions
- [ ] Kademlia DHT integration for scalable agent public key discovery
