// 블록체인 ThreatRegistry 배포
// Hardhat Local Network에 ThreatRegistry 배포

import hre from "hardhat";
import readline from "readline";
import fs from "fs";

const { ethers } = await hre.network.connect("localhost");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

function question(query) {
  return new Promise((resolve) => rl.question(query, resolve));
}

async function main() {
  const signers = await ethers.getSigners();

  console.log("\n==========================================");
  console.log("Deploying SafeShield ThreatRegistry");
  console.log("==========================================\n");

  // Account #0은 Deployer / AI Backend용
  const deployer = signers[0];
  console.log(`Account #0 : ${deployer.address} [Deployer / AI Backend]`);

  console.log("\n사용 가능한 Validator Account:");

  for (let i = 1; i < signers.length; i++) {
    console.log(`Account #${i} : ${signers[i].address}`);
  }

  const input = await question(
    "\nValidator로 사용할 Account 번호를 입력하세요 (예: 1,2,3): "
  );

  const accountNumbers = input
    .split(",")
    .map((num) => Number(num.trim()));

  // 입력값 검증
  if (
    accountNumbers.length === 0 ||
    accountNumbers.some(
      (num) =>
        !Number.isInteger(num) ||
        num <= 0 ||
        num >= signers.length
    )
  ) {
    throw new Error("잘못된 Account 번호입니다.");
  }

  // 중복 Account 방지
  const uniqueAccountNumbers = [...new Set(accountNumbers)];

  if (uniqueAccountNumbers.length !== accountNumbers.length) {
    throw new Error("중복된 Validator Account가 있습니다.");
  }

  const validatorAddresses = uniqueAccountNumbers.map(
    (num) => signers[num].address
  );

  console.log("\n선택된 Validators:");

  uniqueAccountNumbers.forEach((num) => {
    console.log(`Account #${num} : ${signers[num].address}`);
  });

  // 선택한 Validator 주소들을 Constructor에 전달
  const ThreatRegistry = await ethers.getContractFactory(
    "ThreatRegistry",
    deployer
  );

  const threatRegistry = await ThreatRegistry.deploy(
    validatorAddresses
  );

  await threatRegistry.waitForDeployment();

  const contractAddress = await threatRegistry.getAddress();
  const threshold = await threatRegistry.threshold();

  console.log("\n==========================================");
  console.log("ThreatRegistry Deployment Complete");
  console.log("==========================================");

  console.log("Contract Address :", contractAddress);
  console.log("Validator Count  :", validatorAddresses.length);
  console.log("Threshold        :", threshold.toString());

  // 배포 정보를 deployment.json에 자동 저장
  const deploymentInfo = {
    contractAddress,
    validatorCount: validatorAddresses.length,
    threshold: Number(threshold),
    validators: uniqueAccountNumbers.map((num) => ({
      accountNumber: num,
      address: signers[num].address,
    })),
  };

  fs.writeFileSync(
    "./deployment.json",
    JSON.stringify(deploymentInfo, null, 2)
  );

  console.log("\n배포 정보가 deployment.json에 저장되었습니다.");

  rl.close();
}

main().catch((error) => {
  console.error(error);
  rl.close();
  process.exitCode = 1;
});