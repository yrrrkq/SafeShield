// Sepolia에 컨트랙트 올리기

import hre from "hardhat";

const { ethers } = await hre.network.connect();

async function main() {
  const signers = await ethers.getSigners();

  const deployer = signers[0];
  const kisa = signers[1];
  const police = signers[2];
  const ahnlab = signers[3];

  console.log("Deployer:", deployer.address);
  console.log("KISA:", kisa.address);
  console.log("Police:", police.address);
  console.log("AhnLab:", ahnlab.address);

  const ThreatRegistry = await ethers.getContractFactory("ThreatRegistry");

  const threatRegistry = await ThreatRegistry.deploy([
    kisa.address,
    police.address,
    ahnlab.address,
  ]);

  await threatRegistry.waitForDeployment();

  const contractAddress = await threatRegistry.getAddress();

  console.log("\nThreatRegistry deployed!");
  console.log("Contract address:", contractAddress);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});