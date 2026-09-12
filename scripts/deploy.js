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

  console.log("\n=================================");
  console.log("Validator Account 설정");
  console.log("=================================\n");

  // Account #0은 Deployer / AI Backend용
  console.log(`Account #0 : ${signers[0].address} [Deployer / AI Backend]`);

  // Validator로 선택 가능한 Account 출력
  for (let i = 1; i < signers.length; i++) {
    console.log(`Account #${i} : ${signers[i].address}`);
  }

  console.log();

  const input = await question(
    "Validator로 사용할 Account 번호를 입력하세요 (예: 1,2,3): "
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
    throw new Error("중복된 Account가 있습니다.");
  }

  const validatorAddresses = uniqueAccountNumbers.map(
    (num) => signers[num].address
  );

  console.log("\n선택된 Validator:");

  uniqueAccountNumbers.forEach((num) => {
    console.log(`Account #${num} : ${signers[num].address}`);
  });

  // Account #0을 Deployer로 사용
  const deployer = signers[0];

  const ThreatRegistry = await ethers.getContractFactory(
    "ThreatRegistry",
    deployer
  );

  // 선택한 Validator 주소들을 Constructor에 전달
  const threatRegistry = await ThreatRegistry.deploy(
    validatorAddresses
  );

  await threatRegistry.waitForDeployment();

  const contractAddress = await threatRegistry.getAddress();

  // 과반수 임계값 확인
  const threshold = await threatRegistry.threshold();

  // 배포 정보를 deployment.json에 자동 저장
  const deploymentInfo = {
    contractAddress: contractAddress,
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

  console.log("\n=================================");
  console.log("ThreatRegistry deployed!");
  console.log("=================================");

  console.log("Contract address:", contractAddress);
  console.log("Validator count:", validatorAddresses.length);
  console.log("Majority threshold:", threshold.toString());

  console.log("\n배포 정보가 deployment.json에 저장되었습니다.");

  rl.close();
}

main().catch((error) => {
  console.error(error);
  rl.close();
  process.exitCode = 1;
});