import { ethers } from "ethers";
import fs from "fs";
import readline from "readline";

const RPC_URL = "http://127.0.0.1:8545";

const deployment = JSON.parse(
  fs.readFileSync("./deployment.json", "utf8")
);
const CONTRACT_ADDRESS = deployment.contractAddress;

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

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

function question(query) {
  return new Promise((resolve) => rl.question(query, resolve));
}

function getStatusName(status) {
  const statusNames = [
    "NONE",
    "PENDING",
    "CONFIRMED",
    "REJECTED",
  ];

  return statusNames[Number(status)] ?? "UNKNOWN";
}

async function main() {
  const signers = [];

  // Hardhat 기본 Account 목록 가져오기
  for (let i = 0; i < 20; i++) {
    try {
      const signer = await provider.getSigner(i);
      signers.push(signer);
    } catch {
      break;
    }
  }

  const readContract = new ethers.Contract(
    CONTRACT_ADDRESS,
    artifact.abi,
    provider
  );

  console.log("\n=================================");
  console.log("Threat Validator");
  console.log("=================================");

  console.log("\nThreat ID:", THREAT_ID);

  let threat = await readContract.threats(THREAT_ID);

  console.log("Current Status:", getStatusName(threat.status));
  console.log("Approve Count:", threat.approveCount.toString());
  console.log("Reject Count:", threat.rejectCount.toString());

  const validatorCount = await readContract.validatorCount();
  const threshold = await readContract.threshold();

  console.log("Validator Count:", validatorCount.toString());
  console.log("Majority Threshold:", threshold.toString());

  console.log("\n=== Accounts ===");

  // 실제 Validator인지 함께 표시
  for (let i = 1; i < signers.length; i++) {
    const address = await signers[i].getAddress();
    const isValidator = await readContract.validators(address);

    console.log(
      `Account #${i} : ${address} ${
        isValidator ? "[VALIDATOR]" : ""
      }`
    );
  }

  const accountInput = await question(
    "\n투표할 Validator Account 번호를 입력하세요: "
  );
  const accountNumber = Number(accountInput.trim());

  if (
    !Number.isInteger(accountNumber) ||
    accountNumber <= 0 ||
    accountNumber >= signers.length
  ) {
    throw new Error("잘못된 Account 번호입니다.");
  }

  const signer = signers[accountNumber];
  const signerAddress = await signer.getAddress();
  const isValidator =
    await readContract.validators(signerAddress);

  if (!isValidator) {
    throw new Error(
      `Account #${accountNumber}는 등록된 Validator가 아닙니다.`
    );
  }

  const alreadyVoted =
    await readContract.voted(THREAT_ID, signerAddress);

  if (alreadyVoted) {
    throw new Error(
      `Account #${accountNumber}는 이미 투표했습니다.`
    );
  }

  console.log("\n선택된 Validator:");
  console.log(`Account #${accountNumber}`);
  console.log(signerAddress);

  const voteInput = await question(
    "\n[1] APPROVE (악성)\n[2] REJECT (정상)\n선택: "
  );

  const contract = new ethers.Contract(
    CONTRACT_ADDRESS,
    artifact.abi,
    signer
  );
  let tx;

  if (voteInput.trim() === "1") {
    console.log("\nAPPROVE 트랜잭션 전송 중...");
    tx = await contract.approveThreat(THREAT_ID);
  } else if (voteInput.trim() === "2") {
    console.log("\nREJECT 트랜잭션 전송 중...");
    tx = await contract.rejectThreat(THREAT_ID);
  } else {
    throw new Error("1 또는 2를 입력해주세요.");
  }

  await tx.wait();

  console.log("투표 완료!");
  console.log("Transaction Hash:", tx.hash);
  console.log("Signer:", signerAddress);

  // 투표 후 상태 다시 조회
  threat = await readContract.threats(THREAT_ID);

  const blacklisted =
    await readContract.isBlacklisted(THREAT_ID);

  console.log("\n=================================");
  console.log("Current Result");
  console.log("=================================");

  console.log(
    "Approve Count:",
    threat.approveCount.toString()
  );
  console.log(
    "Reject Count:",
    threat.rejectCount.toString()
  );
  console.log(
    "Status:",
    getStatusName(threat.status)
  );
  console.log("Blacklisted:", blacklisted);


  if (getStatusName(threat.status) === "PENDING") {
    console.log(
      `→ 아직 과반수(${threshold})에 도달하지 않았습니다.`
    );
  }
  rl.close();
}

main().catch((error) => {
  console.error("\nError:", error.message);
  rl.close();
  process.exitCode = 1;
});