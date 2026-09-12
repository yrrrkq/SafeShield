// ThreatConfirmed 이벤트 감지
import { ethers } from "ethers";
import fs from "fs";

const RPC_URL = "http://127.0.0.1:8545";

const CONTRACT_ADDRESS =
  "0x5FbDB2315678afecb367f032d93F642f64180aa3";

const artifact = JSON.parse(
  fs.readFileSync(
    "./artifacts/contracts/ThreatRegistry.sol/ThreatRegistry.json",
    "utf8"
  )
);

// 실시간 이벤트 수신을 위해 WebSocket 사용
const provider = new ethers.JsonRpcProvider(RPC_URL);

const contract = new ethers.Contract(
  CONTRACT_ADDRESS,
  artifact.abi,
  provider
);

console.log("=================================");
console.log("ThreatConfirmed Event Listener");
console.log("=================================");
console.log("Contract:", CONTRACT_ADDRESS);
console.log("Waiting for confirmed threats...\n");

// ThreatRegistry에서 ThreatConfirmed가 발생하면 자동 실행
contract.on(
  "ThreatConfirmed",
  (threatId, urlHash, apkHash) => {
    console.log("\n🚨 THREAT CONFIRMED");
    console.log("---------------------------------");
    console.log("Threat ID:", threatId);
    console.log("URL Hash:", urlHash);
    console.log("APK Hash:", apkHash);
    console.log("---------------------------------");
    console.log("→ Threat added to blacklist");
    console.log("→ Ready to broadcast to clients");
    console.log("\nWaiting for next threat...");
  }
);
