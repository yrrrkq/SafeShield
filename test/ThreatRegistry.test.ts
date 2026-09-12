// 2-of-3 등이 제대로 작동하는지 테스트 (자동 테스트)
import { expect } from "chai";
import { network } from "hardhat";

describe("ThreatRegistry", function () {
  async function deployThreatRegistry() {
    // Hardhat 로컬 네트워크 연결
    const { ethers } = await network.connect();

    // 테스트용 계정 가져오기
    const [deployer, kisa, police, ahnlab, outsider] =
      await ethers.getSigners();

    // Validator 3명
    const validators = [
      await kisa.getAddress(),
      await police.getAddress(),
      await ahnlab.getAddress(),
    ];

    // ThreatRegistry 배포
    const ThreatRegistry =
      await ethers.getContractFactory("ThreatRegistry");

    const threatRegistry =
      await ThreatRegistry.deploy(validators);

    await threatRegistry.waitForDeployment();

    return {
      threatRegistry,
      deployer,
      kisa,
      police,
      ahnlab,
      outsider,
    };
  }

  // 테스트에서 사용할 가짜 위협 데이터
  const urlHash =
    "0x1111111111111111111111111111111111111111111111111111111111111111";

  const apkHash =
    "0x2222222222222222222222222222222222222222222222222222222222222222";

  const evidenceHash =
    "0x3333333333333333333333333333333333333333333333333333333333333333";

  const c2 = "185.123.10.20";

  const riskScore = 94;

  // TEST 1. Validator 등록 확인
  it("1. KISA, Police, AhnLab should be registered as validators", async function () {
    const { threatRegistry, kisa, police, ahnlab } =
      await deployThreatRegistry();

    expect(
      await threatRegistry.validators(await kisa.getAddress())
    ).to.equal(true);

    expect(
      await threatRegistry.validators(await police.getAddress())
    ).to.equal(true);

    expect(
      await threatRegistry.validators(await ahnlab.getAddress())
    ).to.equal(true);
  });

  // TEST 2. 위협 등록 → PENDING
  it("2. New threat should be PENDING", async function () {
    const { threatRegistry } = await deployThreatRegistry();

    await threatRegistry.submitThreat(
      urlHash,
      apkHash,
      evidenceHash,
      c2,
      riskScore
    );

    const threatId = ethersId(urlHash, apkHash, evidenceHash);

    const threat = await threatRegistry.threats(threatId);

    // NONE = 0
    // PENDING = 1
    // CONFIRMED = 2
    // REJECTED = 3
    expect(threat.status).to.equal(1n);
  });

  // TEST 3. 한 기관만 승인 → 아직 PENDING
  it("3. Threat should remain PENDING after one approval", async function () {
    const { threatRegistry, kisa } =
      await deployThreatRegistry();

    await threatRegistry.submitThreat(
      urlHash,
      apkHash,
      evidenceHash,
      c2,
      riskScore
    );

    const threatId = ethersId(urlHash, apkHash, evidenceHash);

    await threatRegistry
      .connect(kisa)
      .approveThreat(threatId);

    const threat = await threatRegistry.threats(threatId);

    expect(threat.approveCount).to.equal(1n);
    expect(threat.status).to.equal(1n);
  });

  // TEST 4. 두 기관 승인 → CONFIRMED
  it("4. Threat should become CONFIRMED after two approvals", async function () {
    const { threatRegistry, kisa, police } =
      await deployThreatRegistry();

    await threatRegistry.submitThreat(
      urlHash,
      apkHash,
      evidenceHash,
      c2,
      riskScore
    );

    const threatId = ethersId(urlHash, apkHash, evidenceHash);

    // KISA 승인
    await threatRegistry
      .connect(kisa)
      .approveThreat(threatId);

    // 경찰청 승인
    await threatRegistry
      .connect(police)
      .approveThreat(threatId);

    const threat = await threatRegistry.threats(threatId);

    expect(threat.approveCount).to.equal(2n);
    expect(threat.status).to.equal(2n);
  });

  // TEST 5. CONFIRMED → Blacklist true
  it("5. Confirmed threat should be blacklisted", async function () {
    const { threatRegistry, kisa, police } =
      await deployThreatRegistry();

    await threatRegistry.submitThreat(
      urlHash,
      apkHash,
      evidenceHash,
      c2,
      riskScore
    );

    const threatId = ethersId(urlHash, apkHash, evidenceHash);

    await threatRegistry
      .connect(kisa)
      .approveThreat(threatId);

    await threatRegistry
      .connect(police)
      .approveThreat(threatId);

    expect(
      await threatRegistry.isBlacklisted(threatId)
    ).to.equal(true);
  });


  // TEST 6. 두 기관 Reject → REJECTED
  it("6. Threat should become REJECTED after two rejections", async function () {
    const { threatRegistry, kisa, police } =
      await deployThreatRegistry();

    await threatRegistry.submitThreat(
      urlHash,
      apkHash,
      evidenceHash,
      c2,
      riskScore
    );

    const threatId = ethersId(urlHash, apkHash, evidenceHash);

    await threatRegistry
      .connect(kisa)
      .rejectThreat(threatId);

    await threatRegistry
      .connect(police)
      .rejectThreat(threatId);

    const threat = await threatRegistry.threats(threatId);

    expect(threat.rejectCount).to.equal(2n);
    expect(threat.status).to.equal(3n);

    expect(
      await threatRegistry.isBlacklisted(threatId)
    ).to.equal(false);
  });

  // --------------------------------------------------
  // TEST 7. 동일 Validator 중복 투표 방지
  // --------------------------------------------------

  it("7. Same validator should not vote twice", async function () {
    const { threatRegistry, kisa } =
      await deployThreatRegistry();

    await threatRegistry.submitThreat(
      urlHash,
      apkHash,
      evidenceHash,
      c2,
      riskScore
    );

    const threatId = ethersId(urlHash, apkHash, evidenceHash);

    await threatRegistry
      .connect(kisa)
      .approveThreat(threatId);

    await expect(
      threatRegistry
        .connect(kisa)
        .approveThreat(threatId)
    ).to.be.revertedWith("Already voted");
  });

  // TEST 8. Validator가 아닌 계정의 투표 방지
  it("8. Non-validator should not be able to approve", async function () {
    const { threatRegistry, outsider } =
      await deployThreatRegistry();

    await threatRegistry.submitThreat(
      urlHash,
      apkHash,
      evidenceHash,
      c2,
      riskScore
    );

    const threatId = ethersId(urlHash, apkHash, evidenceHash);

    await expect(
      threatRegistry
        .connect(outsider)
        .approveThreat(threatId)
    ).to.be.revertedWith("Not validator");
  });
});


// --------------------------------------------------
// Solidity의 threatId 생성 방식을 똑같이 구현
// --------------------------------------------------

import { ethers } from "ethers";

function ethersId(
  urlHash: string,
  apkHash: string,
  evidenceHash: string
) {
  return ethers.keccak256(
    ethers.solidityPacked(
      ["bytes32", "bytes32", "bytes32"],
      [urlHash, apkHash, evidenceHash]
    )
  );
}
