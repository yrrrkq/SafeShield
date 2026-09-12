import { ethers } from "ethers";
import fs from "fs";

const RPC_URL = "http://127.0.0.1:8545";

const CONTRACT_ADDRESS =
  "0x5FbDB2315678afecb367f032d93F642f64180aa3";

// 방금 등록한 Threat ID
const THREAT_ID = process.argv[2];
if (!THREAT_ID) {
  console.error("Threat ID를 입력해주세요.");
  console.error("예: node scripts/approveThreat.js 0x...");
  process.exit(1);
}

const artifact = JSON.parse(
  fs.readFileSync(
    "./artifacts/contracts/ThreatRegistry.sol/ThreatRegistry.json",
    "utf8"
  )
);

const provider = new ethers.JsonRpcProvider(RPC_URL);

async function main() {
  // Hardhat Account #1 = KISA
  // Hardhat Account #2 = Police
  const kisa = await provider.getSigner(1);
  const police = await provider.getSigner(2);

  console.log("=== Validator Approval Demo ===");
  console.log("KISA:", await kisa.getAddress());
  console.log("Police:", await police.getAddress());

  // KISA 권한으로 Contract 연결
  const contractAsKisa = new ethers.Contract(
    CONTRACT_ADDRESS,
    artifact.abi,
    kisa
  );

  // 경찰청 권한으로 Contract 연결
  const contractAsPolice = new ethers.Contract(
    CONTRACT_ADDRESS,
    artifact.abi,
    police
  );

  // 1. KISA 승인
  console.log("\n[1] KISA approves threat...");

  const kisaTx = await contractAsKisa.approveThreat(THREAT_ID);
  await kisaTx.wait();

  let threat = await contractAsKisa.threats(THREAT_ID);

  console.log("KISA approval complete");
  console.log("Approve Count:", threat.approveCount.toString());
  console.log("Status:", threat.status.toString());

  // 2. Police 승인
  console.log("\n[2] Police approves threat...");

  const policeTx = await contractAsPolice.approveThreat(THREAT_ID);
  await policeTx.wait();

  threat = await contractAsPolice.threats(THREAT_ID);

  console.log("Police approval complete");
  console.log("Approve Count:", threat.approveCount.toString());
  console.log("Status:", threat.status.toString());

  // 3. 최종 blacklist 확인
  const blacklisted =
    await contractAsPolice.isBlacklisted(THREAT_ID);

  console.log("\n=== Final Result ===");
  console.log("Approve Count:", threat.approveCount.toString());
  console.log("Status:", threat.status.toString());
  console.log("Blacklisted:", blacklisted);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});