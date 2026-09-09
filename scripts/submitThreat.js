import { ethers } from "ethers";
import {
  threatRegistry,
  submitThreatToContract,
} from "../backend/blockchain.js";

// AI Sandbox가 반환했다고 가정한 분석 결과
const aiResult = {
  url: process.argv[2] || "http://malicious-example.com/test",
  apkHash: ethers.ZeroHash,
  evidence: "Phishing login page detected",
  c2: "192.168.10.50",
  riskScore: 92,
};

async function main() {
  // 원본 데이터를 그대로 온체인에 저장하지 않고 hash로 변환
  const threatReport = {
    urlHash: ethers.keccak256(ethers.toUtf8Bytes(aiResult.url)),
    apkHash: aiResult.apkHash,
    evidenceHash: ethers.keccak256(
      ethers.toUtf8Bytes(aiResult.evidence)
    ),
    c2: aiResult.c2,
    riskScore: aiResult.riskScore,
  };

  console.log("=== AI Threat Report ===");
  console.log(threatReport);

  const receipt = await submitThreatToContract(
    threatRegistry,
    threatReport
  );

  console.log("\nThreat submitted!");
  console.log("Transaction hash:", receipt.hash);

  // submitThreat와 동일한 방식으로 threatId 계산
  const threatId = ethers.keccak256(
    ethers.solidityPacked(
      ["bytes32", "bytes32", "bytes32"],
      [
        threatReport.urlHash,
        threatReport.apkHash,
        threatReport.evidenceHash,
      ]
    )
  );

  const threat = await threatRegistry.threats(threatId);

  console.log("\n=== Blockchain Result ===");
  console.log("Threat ID:", threatId);
  console.log("Risk Score:", threat.riskScore.toString());
  console.log("Approve Count:", threat.approveCount.toString());
  console.log("Reject Count:", threat.rejectCount.toString());
  console.log("Status:", threat.status.toString());
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});