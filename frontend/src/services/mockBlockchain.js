import { INITIAL_NODES } from "../data/presets";

// Initial verified on-chain threats
const INITIAL_THREATS = [
  {
    apkHash: "0x8f3c428a1d99e021bbfae4468f707cfb792138402c3b69018e19e7a83d739811",
    url: "http://fake-cj-delivery-check.com/track.apk",
    threatType: "CJ Parcel Smishing (Trojan.Dropper)",
    threatScore: 96,
    detectedPermissions: [
      "android.permission.READ_SMS",
      "android.permission.RECEIVE_SMS",
      "android.permission.CALL_PHONE",
      "android.permission.RECORD_AUDIO",
      "android.permission.SYSTEM_ALERT_WINDOW"
    ],
    proposer: INITIAL_NODES[0].address,
    proposedAt: Math.floor(Date.now() / 1000) - 3600,
    confirmedAt: Math.floor(Date.now() / 1000) - 3590,
    isConfirmed: true,
    isRevoked: false,
    approvalCount: 3,
    endorsers: [
      { address: INITIAL_NODES[0].address, name: INITIAL_NODES[0].name, signedAt: Math.floor(Date.now() / 1000) - 3600 },
      { address: INITIAL_NODES[1].address, name: INITIAL_NODES[1].name, signedAt: Math.floor(Date.now() / 1000) - 3595 },
      { address: INITIAL_NODES[2].address, name: INITIAL_NODES[2].name, signedAt: Math.floor(Date.now() / 1000) - 3590 }
    ],
    txHash: "0x3a79d8ef1b2c4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f",
    blockNumber: 4281820
  }
];

export class LocalBlockchainState {
  constructor() {
    this.threats = [...INITIAL_THREATS];
    this.blockHeight = 4281940;
    this.contractAddress = "0x5FbDB2315678afecb367f032d93F642f64180aa3";
    this.requiredSignatures = 2;
    this.listeners = [];
  }

  subscribe(callback) {
    this.listeners.push(callback);
    return () => {
      this.listeners = this.listeners.filter(l => l !== callback);
    };
  }

  notify(event, data) {
    this.listeners.forEach(cb => {
      try {
        cb({ event, data, timestamp: Math.floor(Date.now() / 1000) });
      } catch (e) {
        console.error("Listener error", e);
      }
    });
  }

  getThreats(filter = "all") {
    if (filter === "confirmed") {
      return this.threats.filter(t => t.isConfirmed);
    } else if (filter === "pending") {
      return this.threats.filter(t => !t.isConfirmed && !t.isRevoked);
    }
    return [...this.threats].sort((a, b) => b.proposedAt - a.proposedAt);
  }

  getThreat(apkHash) {
    return this.threats.find(t => t.apkHash.toLowerCase() === apkHash.toLowerCase());
  }

  isMalwareConfirmed(apkHash) {
    const threat = this.getThreat(apkHash);
    return Boolean(threat && threat.isConfirmed && !threat.isRevoked);
  }

  proposeThreat({ apkHash, url, threatType, threatScore, permissions, proposerAddress }) {
    const existing = this.getThreat(apkHash);
    if (existing) {
      return existing;
    }

    this.blockHeight += 1;
    const proposer = proposerAddress || INITIAL_NODES[0].address;
    const proposerNode = INITIAL_NODES.find(n => n.address.toLowerCase() === proposer.toLowerCase()) || INITIAL_NODES[0];
    const now = Math.floor(Date.now() / 1000);
    const txHash = "0x" + Array.from({length: 64}, () => Math.floor(Math.random()*16).toString(16)).join('');

    const newThreat = {
      apkHash,
      url,
      threatType,
      threatScore,
      detectedPermissions: permissions,
      proposer,
      proposedAt: now,
      confirmedAt: 0,
      isConfirmed: false,
      isRevoked: false,
      approvalCount: 1,
      endorsers: [
        {
          address: proposer,
          name: proposerNode.name,
          signedAt: now
        }
      ],
      txHash,
      blockNumber: this.blockHeight
    };

    this.threats.unshift(newThreat);
    this.notify("ThreatProposed", newThreat);
    return newThreat;
  }

  endorseThreat(apkHash, oracleAddress) {
    const threat = this.getThreat(apkHash);
    if (!threat) return null;

    const alreadySigned = threat.endorsers.some(e => e.address.toLowerCase() === oracleAddress.toLowerCase());
    if (alreadySigned) return threat;

    const node = INITIAL_NODES.find(n => n.address.toLowerCase() === oracleAddress.toLowerCase());
    const nodeName = node ? node.name : "Authorized Node";
    const now = Math.floor(Date.now() / 1000);

    this.blockHeight += 1;
    threat.approvalCount += 1;
    threat.endorsers.push({
      address: oracleAddress,
      name: nodeName,
      signedAt: now
    });

    this.notify("ThreatEndorsed", {
      apkHash,
      oracleAddress,
      oracleName: nodeName,
      approvalCount: threat.approvalCount
    });

    // Check consensus threshold
    if (!threat.isConfirmed && threat.approvalCount >= this.requiredSignatures) {
      threat.isConfirmed = true;
      threat.confirmedAt = now;
      threat.confirmTxHash = "0x" + Array.from({length: 64}, () => Math.floor(Math.random()*16).toString(16)).join('');

      this.notify("MalwareConfirmed", {
        ...threat,
        broadcastScope: "GLOBAL_INSTANT_BLOCK"
      });
    }

    return { ...threat };
  }
}

export const localBlockchain = new LocalBlockchainState();
