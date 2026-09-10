import asyncio
import time
import secrets
from typing import Dict, List, Any, Optional

ORACLE_NODES = [
    {
        "id": "node-kisa",
        "name": "KISA (Korea Internet & Security Agency)",
        "address": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
        "type": "National CERT",
        "status": "ONLINE",
        "reputation": 99.8,
        "avatar": "🛡️"
    },
    {
        "id": "node-ahnlab",
        "name": "AhnLab Cyber Threat Intelligence",
        "address": "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
        "type": "Commercial Anti-Virus",
        "status": "ONLINE",
        "reputation": 99.4,
        "avatar": "🔬"
    },
    {
        "id": "node-police",
        "name": "National Police Agency Cyber Bureau",
        "address": "0x90F79bf6EB2c4f870365E785982E1f101E93b906",
        "type": "Law Enforcement",
        "status": "ONLINE",
        "reputation": 98.9,
        "avatar": "🚨"
    },
    {
        "id": "node-fss",
        "name": "FSS Financial Anti-Phishing Center",
        "address": "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65",
        "type": "Financial Regulator",
        "status": "ONLINE",
        "reputation": 99.1,
        "avatar": "🏦"
    }
]

class BlockchainManager:
    def __init__(self, required_signatures: int = 2):
        self.required_signatures = required_signatures
        self.threats: Dict[str, Dict[str, Any]] = {}
        self.subscribers: List[asyncio.Queue] = []
        self.block_height = 4281940
        self.contract_address = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
        self._seed_initial_threats()

    def _seed_initial_threats(self):
        """Seeds initial verified on-chain threat reports"""
        initial_hash = "0x8f3c428a1d99e021bbfae4468f707cfb792138402c3b69018e19e7a83d739811"
        self.threats[initial_hash] = {
            "apkHash": initial_hash,
            "url": "http://fake-cj-delivery-check.com/track.apk",
            "threatType": "CJ Parcel Smishing (Trojan.Dropper)",
            "threatScore": 96,
            "detectedPermissions": [
                "android.permission.READ_SMS",
                "android.permission.RECEIVE_SMS",
                "android.permission.CALL_PHONE",
                "android.permission.RECORD_AUDIO",
                "android.permission.SYSTEM_ALERT_WINDOW"
            ],
            "proposer": ORACLE_NODES[0]["address"],
            "proposedAt": int(time.time()) - 3600,
            "confirmedAt": int(time.time()) - 3590,
            "isConfirmed": True,
            "isRevoked": False,
            "approvalCount": 3,
            "endorsers": [
                {"address": ORACLE_NODES[0]["address"], "name": ORACLE_NODES[0]["name"], "signedAt": int(time.time()) - 3600},
                {"address": ORACLE_NODES[1]["address"], "name": ORACLE_NODES[1]["name"], "signedAt": int(time.time()) - 3595},
                {"address": ORACLE_NODES[2]["address"], "name": ORACLE_NODES[2]["name"], "signedAt": int(time.time()) - 3590}
            ],
            "txHash": f"0x{secrets.token_hex(32)}",
            "blockNumber": self.block_height - 120
        }

    async def subscribe(self) -> asyncio.Queue:
        q = asyncio.Queue()
        self.subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue):
        if q in self.subscribers:
            self.subscribers.remove(q)

    async def broadcast_event(self, event_type: str, payload: Dict[str, Any]):
        """Dispatches event to all active WebSocket connections"""
        message = {
            "type": event_type,
            "timestamp": int(time.time()),
            "data": payload
        }
        for q in list(self.subscribers):
            try:
                await q.put(message)
            except Exception:
                pass

    def get_all_threats(self) -> List[Dict[str, Any]]:
        return list(self.threats.values())

    def get_threat(self, apk_hash: str) -> Optional[Dict[str, Any]]:
        return self.threats.get(apk_hash)

    def is_confirmed(self, apk_hash: str) -> bool:
        threat = self.threats.get(apk_hash)
        return threat is not None and threat.get("isConfirmed", False) and not threat.get("isRevoked", False)

    async def propose_threat(
        self,
        apk_hash: str,
        url: str,
        threat_type: str,
        threat_score: int,
        permissions: List[str],
        proposer_address: Optional[str] = None
    ) -> Dict[str, Any]:
        proposer = proposer_address or ORACLE_NODES[0]["address"]
        proposer_node = next((n for n in ORACLE_NODES if n["address"].lower() == proposer.lower()), ORACLE_NODES[0])

        self.block_height += 1
        tx_hash = f"0x{secrets.token_hex(32)}"
        now = int(time.time())

        threat_entry = {
            "apkHash": apk_hash,
            "url": url,
            "threatType": threat_type,
            "threatScore": threat_score,
            "detectedPermissions": permissions,
            "proposer": proposer,
            "proposedAt": now,
            "confirmedAt": 0,
            "isConfirmed": False,
            "isRevoked": False,
            "approvalCount": 1,
            "endorsers": [
                {
                    "address": proposer,
                    "name": proposer_node["name"],
                    "signedAt": now
                }
            ],
            "txHash": tx_hash,
            "blockNumber": self.block_height
        }

        self.threats[apk_hash] = threat_entry

        # Broadcast ThreatProposed Event
        await self.broadcast_event("ThreatProposed", {
            "apkHash": apk_hash,
            "url": url,
            "threatType": threat_type,
            "threatScore": threat_score,
            "proposer": proposer,
            "proposerName": proposer_node["name"],
            "txHash": tx_hash,
            "blockNumber": self.block_height,
            "approvalCount": 1,
            "requiredSignatures": self.required_signatures
        })

        return threat_entry

    async def endorse_threat(self, apk_hash: str, oracle_address: str) -> Dict[str, Any]:
        if apk_hash not in self.threats:
            raise ValueError("Threat report not found for given hash")

        threat = self.threats[apk_hash]
        if threat["isRevoked"]:
            raise ValueError("Threat report has been revoked")

        # Check if node already endorsed
        existing_addrs = [e["address"].lower() for e in threat["endorsers"]]
        if oracle_address.lower() in existing_addrs:
            return threat

        node = next((n for n in ORACLE_NODES if n["address"].lower() == oracle_address.lower()), None)
        node_name = node["name"] if node else "Authorized Oracle Node"

        self.block_height += 1
        now = int(time.time())

        threat["approvalCount"] += 1
        threat["endorsers"].append({
            "address": oracle_address,
            "name": node_name,
            "signedAt": now
        })

        # Broadcast ThreatEndorsed Event
        await self.broadcast_event("ThreatEndorsed", {
            "apkHash": apk_hash,
            "oracleAddress": oracle_address,
            "oracleName": node_name,
            "approvalCount": threat["approvalCount"],
            "requiredSignatures": self.required_signatures
        })

        # Check for consensus threshold
        if not threat["isConfirmed"] and threat["approvalCount"] >= self.required_signatures:
            threat["isConfirmed"] = True
            threat["confirmedAt"] = now
            confirm_tx = f"0x{secrets.token_hex(32)}"
            threat["confirmTxHash"] = confirm_tx

            # Emit Global Broadcast: MalwareConfirmed!
            await self.broadcast_event("MalwareConfirmed", {
                "apkHash": apk_hash,
                "url": threat["url"],
                "threatType": threat["threatType"],
                "threatScore": threat["threatScore"],
                "detectedPermissions": threat["detectedPermissions"],
                "endorsers": threat["endorsers"],
                "confirmedAt": now,
                "confirmTxHash": confirm_tx,
                "blockNumber": self.block_height,
                "broadcastScope": "GLOBAL_INSTANT_BLOCK"
            })

        return threat

    async def auto_multi_sig_pipeline(
        self,
        apk_hash: str,
        delay_seconds: float = 1.0
    ):
        """Simulates decentralized consensus from independent oracle nodes with real-time steps"""
        # Node 1 already proposed. Node 2 (AhnLab) signs after validation
        await asyncio.sleep(delay_seconds)
        if apk_hash in self.threats and not self.threats[apk_hash]["isConfirmed"]:
            await self.endorse_threat(apk_hash, ORACLE_NODES[1]["address"])

        # Node 3 (Cyber Police) signs for additional quorum
        await asyncio.sleep(delay_seconds * 0.8)
        if apk_hash in self.threats:
            await self.endorse_threat(apk_hash, ORACLE_NODES[2]["address"])


blockchain_manager = BlockchainManager(required_signatures=2)
