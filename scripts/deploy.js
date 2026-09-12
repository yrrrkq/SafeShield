import hre from "hardhat";
import readline from "readline";
import fs from "fs";

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

function question(query) {
  return new Promise((resolve) => rl.question(query, resolve));
}

async function main() {
  const { ethers } = hre;
  const signers = await ethers.getSigners();

  console.log("==================================================");
  console.log("🛡️  Deploying SafeShield Multi-Sig Threat Oracle...");
  console.log("==================================================\n");

  // Account #0: Deployer / AI Backend용
  const deployer = signers[0];
  console.log(`Account #0 : ${deployer.address} [Deployer / AI Backend]`);

  // 기본 보안 기관 지정 이름 목록
  const defaultAgencyNames = [
    "KISA (Korea Internet & Security Agency)",
    "AhnLab Cyber Threat Defense",
    "National Police Agency Cyber Bureau",
    "FSS Financial Anti-Phishing Center",
  ];

  console.log("\n사용 가능한 Validator Account 목록:");
  for (let i = 1; i < Math.min(signers.length, 5); i++) {
    const agencyName = defaultAgencyNames[i - 1] || `Validator Node #${i}`;
    console.log(`Account #${i} : ${signers[i].address} (${agencyName})`);
  }
  console.log();

  const input = await question(
    "Validator로 사용할 Account 번호를 입력하세요 (예: 1,2,3,4 / 엔터 시 기본값 사용): "
  );

  let selectedIndices = [1, 2, 3, 4].filter((i) => i < signers.length);
  if (input.trim() !== "") {
    const parsed = input
      .split(",")
      .map((num) => Number(num.trim()));

    if (
      parsed.length === 0 ||
      parsed.some(
        (num) =>
          !Number.isInteger(num) ||
          num <= 0 ||
          num >= signers.length
      )
    ) {
      throw new Error("잘못된 Account 번호입니다.");
    }
    selectedIndices = [...new Set(parsed)];
  }

  const nodes = selectedIndices.map((idx, i) => ({
    accountNumber: idx,
    address: signers[idx].address,
    name: defaultAgencyNames[i] || `Validator Node #${idx}`,
    signer: signers[idx],
  }));

  console.log("\n선택된 Validator Nodes:");
  nodes.forEach((node) => {
    console.log(`Account #${node.accountNumber} : ${node.address} - ${node.name}`);
  });

  // 서명 임계값 설정 (기본값: 과반수 또는 2개 이상)
  const threshold = Math.max(2, Math.floor(nodes.length / 2) + 1);

  // SafeShieldOracle 컨트랙트 배포
  const SafeShieldOracle = await ethers.getContractFactory("SafeShieldOracle", deployer);
  const oracle = await SafeShieldOracle.deploy(threshold);
  await oracle.waitForDeployment();

  const contractAddress = await oracle.getAddress();
  console.log(`\n✅ SafeShieldOracle deployed to: ${contractAddress}`);
  console.log(`Required Signatures Threshold: ${threshold}\n`);

  // 1. 보안 기관 검증 노드(Oracle Node) 등록
  console.log("Registering Authorized Cybersecurity Nodes...");
  for (const node of nodes) {
    const tx = await oracle.addOracleNode(node.address, node.name);
    await tx.wait();
    console.log(`  ➕ Added Node: ${node.name} (${node.address})`);
  }

  // 2. 검증된 악성 스미싱 샘플 데이터 Pre-seeding
  console.log("\nPre-seeding Verified Zero-Day Smishing Hash on-chain...");
  const sampleHash = ethers.keccak256(ethers.toUtf8Bytes("MALICIOUS_VOICE_PHISHING_APK_CJ_EXPRESS_v2.4"));
  const sampleUrl = "http://fake-cj-delivery-check.com/track.apk";
  const sampleType = "CJ Parcel Smishing (Trojan.Dropper)";
  const sampleScore = 96;
  const samplePermissions = [
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.CALL_PHONE",
    "android.permission.RECORD_AUDIO",
    "android.permission.SYSTEM_ALERT_WINDOW"
  ];

  // Deployer 노드에서 위협 제안 (Propose)
  let tx = await oracle.proposeThreat(
    sampleHash,
    sampleUrl,
    sampleType,
    sampleScore,
    samplePermissions
  );
  await tx.wait();
  console.log(`  🚨 Proposed Threat: ${sampleHash.substring(0, 18)}...`);

  // 첫 번째 Validator 노드(예: AhnLab)에서 서명 승인 (Endorse)하여 컨센서스 달성
  if (nodes.length > 0) {
    tx = await oracle.connect(nodes[0].signer).endorseThreat(sampleHash);
    await tx.wait();
    console.log(`  ✍️  Endorsed by ${nodes[0].name}. Multi-Sig Consensus Achieved!`);
  }

  // 3. 배포 정보 deployment.json 파일 저장
  const deploymentInfo = {
    contractAddress: contractAddress,
    validatorCount: nodes.length,
    threshold: threshold,
    validators: nodes.map((n) => ({
      accountNumber: n.accountNumber,
      address: n.address,
      name: n.name,
    })),
    preseededThreatHash: sampleHash,
  };

  fs.writeFileSync(
    "./deployment.json",
    JSON.stringify(deploymentInfo, null, 2)
  );

  console.log("\n=================================");
  console.log("🎉 Deployment & Pre-seeding completed!");
  console.log("=================================");
  console.log("Contract Address:", contractAddress);
  console.log("Validator Count:", nodes.length);
  console.log("Majority Threshold:", threshold);
  console.log("배포 파일 저장 위치: ./deployment.json");

  rl.close();
}

main().catch((error) => {
  console.error(error);
  rl.close();
  process.exitCode = 1;
});