// AI 결과를 submitThreat()로 전달
import { ethers } from "ethers";
import fs from "fs";

const RPC_URL = "http://127.0.0.1:8545";

const deployment = JSON.parse(
  fs.readFileSync("./deployment.json", "utf8")
);
const CONTRACT_ADDRESS = deployment.contractAddress;

// ThreatRegistry ABI 불러오기
const artifact = JSON.parse(
  fs.readFileSync(
    "./artifacts/contracts/ThreatRegistry.sol/ThreatRegistry.json",
    "utf8"
  )
);

export const provider = new ethers.JsonRpcProvider(RPC_URL);

// 배포자(Account #0)
// AI 분석 결과를 블록체인에 등록할 때 사용
export const backendSigner = await provider.getSigner(0);

// 실제 배포된 ThreatRegistry 연결
export const threatRegistry = new ethers.Contract(
  CONTRACT_ADDRESS,
  artifact.abi,
  backendSigner
);

// AI 분석 결과를 ThreatRegistry에 등록
export async function submitThreatToContract(
  contract,
  {
    urlHash,
    apkHash,
    evidenceHash,
    c2,
    riskScore,
  }
) {
  const tx = await contract.submitThreat(
    urlHash,
    apkHash,
    evidenceHash,
    c2,
    riskScore
  );

  const receipt = await tx.wait();

  return receipt;
}

// 연결 확인
async function checkConnection() {
  console.log("Connecting to ThreatRegistry...");

  const code = await provider.getCode(CONTRACT_ADDRESS);

  if (code === "0x") {
    console.log("Contract not found.");
    return;
  }

  console.log("Connected!");
  console.log("Contract address:", CONTRACT_ADDRESS);
}

checkConnection().catch(console.error);
