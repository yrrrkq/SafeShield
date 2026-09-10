const hre = require("hardhat");

async function main() {
  console.log("==================================================");
  console.log("🛡️  Deploying SafeShield Multi-Sig Threat Oracle...");
  console.log("==================================================");

  const [deployer, nodeKISA, nodeAhnLab, nodePolice, nodeFSS] = await hre.ethers.getSigners();
  console.log(`Deployer Account: ${deployer.address}`);

  // Deploy SafeShieldOracle with threshold = 2 signatures
  const SafeShieldOracle = await hre.ethers.getContractFactory("SafeShieldOracle");
  const oracle = await SafeShieldOracle.deploy(2);
  await oracle.waitForDeployment();

  const oracleAddress = await oracle.getAddress();
  console.log(`✅ SafeShieldOracle deployed to: ${oracleAddress}`);
  console.log(`Required Signatures Threshold: 2\n`);

  // Register Authorized Oracle Nodes
  console.log("Registering Authorized Cybersecurity Nodes...");
  const nodes = [
    { address: nodeKISA ? nodeKISA.address : "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", name: "KISA (Korea Internet & Security Agency)" },
    { address: nodeAhnLab ? nodeAhnLab.address : "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC", name: "AhnLab Cyber Threat Defense" },
    { address: nodePolice ? nodePolice.address : "0x90F79bf6EB2c4f870365E785982E1f101E93b906", name: "National Police Agency Cyber Bureau" },
    { address: nodeFSS ? nodeFSS.address : "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65", name: "FSS Financial Anti-Phishing Center" }
  ];

  for (const node of nodes) {
    const tx = await oracle.addOracleNode(node.address, node.name);
    await tx.wait();
    console.log(`  ➕ Added Node: ${node.name} (${node.address})`);
  }

  // Pre-seed sample known smishing malware
  console.log("\nPre-seeding Verified Zero-Day Smishing Hash on-chain...");
  const sampleHash = hre.ethers.keccak256(hre.ethers.toUtf8Bytes("MALICIOUS_VOICE_PHISHING_APK_CJ_EXPRESS_v2.4"));
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

  // Propose from Deployer / Node 1
  let tx = await oracle.proposeThreat(
    sampleHash,
    sampleUrl,
    sampleType,
    sampleScore,
    samplePermissions
  );
  await tx.wait();
  console.log(`  🚨 Proposed Threat: ${sampleHash.substring(0, 18)}...`);

  // Endorse from Node 2 to achieve 2-of-2 consensus
  if (nodeAhnLab) {
    tx = await oracle.connect(nodeAhnLab).endorseThreat(sampleHash);
    await tx.wait();
    console.log(`  ✍️  Endorsed by AhnLab. Consensus reached! Status: isConfirmed = true`);
  }

  console.log("\n🎉 Deployment & Pre-seeding completed successfully!");
  console.log(`Save this contract address: ${oracleAddress}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
