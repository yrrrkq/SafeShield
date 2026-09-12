// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title SafeShieldOracle
 * @dev Decentralized Multi-Sig Threat Intelligence Oracle for Smishing & Voice Phishing Prevention
 * Requires M-of-N consensus from authorized cybersecurity nodes (KISA, AhnLab, Police, etc.)
 * to confirm and globally broadcast malicious APK/URL fingerprints.
 */
contract SafeShieldOracle {
    // Contract Owner / Admin
    address public owner;
    
    // Minimum endorsements required for on-chain malware confirmation
    uint256 public requiredSignatures;

    // Threat details structure
    struct ThreatReport {
        bytes32 apkHash;              // SHA-256 Hash of malicious APK binary
        string url;                   // Phishing/Smishing landing URL
        string threatType;            // e.g. "Voice Phishing (Trojan.Banker)", "CJ Smishing", "Fake Police"
        uint8 threatScore;            // AI Risk Score (0 - 100)
        string[] detectedPermissions; // Android permissions (READ_SMS, CALL_PHONE, etc.)
        address proposer;             // Node/Sandbox that submitted the report
        uint256 proposedAt;           // Timestamp when proposed
        uint256 confirmedAt;          // Timestamp when consensus reached
        bool isConfirmed;             // Whether consensus threshold is met
        bool isRevoked;               // Marked false positive
        uint256 approvalCount;        // Current number of oracle endorsements
    }

    // Oracle Node metadata
    struct OracleNode {
        string name;                  // e.g., "KISA (Korea Internet & Security Agency)"
        bool isAuthorized;            // Authorization status
        uint256 totalEndorsements;    // Reputation metric
    }

    // Storage
    mapping(address => OracleNode) public oracleNodes;
    address[] public oracleNodeList;

    // apkHash => ThreatReport
    mapping(bytes32 => ThreatReport) public threats;
    bytes32[] public allThreatHashes;

    // apkHash => (oracleAddress => hasApproved)
    mapping(bytes32 => mapping(address => bool)) public hasEndorsed;

    // Events
    event OracleNodeAdded(address indexed nodeAddress, string name);
    event OracleNodeRemoved(address indexed nodeAddress);
    event ThreatProposed(
        bytes32 indexed apkHash,
        string url,
        string threatType,
        address indexed proposer,
        uint8 threatScore,
        uint256 timestamp
    );
    event ThreatEndorsed(
        bytes32 indexed apkHash,
        address indexed oracleNode,
        string oracleName,
        uint256 currentApprovals,
        uint256 requiredApprovals
    );
    event MalwareConfirmed(
        bytes32 indexed apkHash,
        string url,
        string threatType,
        uint8 threatScore,
        uint256 confirmedAt
    );
    event ThreatRevoked(bytes32 indexed apkHash, address indexed revoker, string reason);

    modifier onlyOwner() {
        require(msg.sender == owner, "SafeShield: Only owner can call this");
        _;
    }

    modifier onlyAuthorizedNode() {
        require(oracleNodes[msg.sender].isAuthorized || msg.sender == owner, "SafeShield: Caller is not an authorized Oracle Node");
        _;
    }

    constructor(uint256 _requiredSignatures) {
        owner = msg.sender;
        requiredSignatures = _requiredSignatures > 0 ? _requiredSignatures : 2;
    }

    /**
     * @notice Registers or authorizes a cybersecurity organization node
     */
    function addOracleNode(address _node, string calldata _name) external onlyOwner {
        require(_node != address(0), "Invalid address");
        if (!oracleNodes[_node].isAuthorized) {
            oracleNodeList.push(_node);
        }
        oracleNodes[_node] = OracleNode({
            name: _name,
            isAuthorized: true,
            totalEndorsements: oracleNodes[_node].totalEndorsements
        });
        emit OracleNodeAdded(_node, _name);
    }

    /**
     * @notice Revokes authorization of a node
     */
    function removeOracleNode(address _node) external onlyOwner {
        require(oracleNodes[_node].isAuthorized, "Node not authorized");
        oracleNodes[_node].isAuthorized = false;
        emit OracleNodeRemoved(_node);
    }

    /**
     * @notice Updates the required number of consensus signatures
     */
    function setRequiredSignatures(uint256 _newThreshold) external onlyOwner {
        require(_newThreshold > 0 && _newThreshold <= oracleNodeList.length, "Invalid threshold");
        requiredSignatures = _newThreshold;
    }

    /**
     * @notice Submits a new threat detected by AI Sandbox
     * Automatically counts the proposer's signature if they are an authorized node
     */
    function proposeThreat(
        bytes32 _apkHash,
        string calldata _url,
        string calldata _threatType,
        uint8 _threatScore,
        string[] calldata _permissions
    ) external onlyAuthorizedNode {
        require(_apkHash != bytes32(0), "Invalid hash");
        require(threats[_apkHash].proposedAt == 0, "Threat hash already registered");

        ThreatReport storage report = threats[_apkHash];
        report.apkHash = _apkHash;
        report.url = _url;
        report.threatType = _threatType;
        report.threatScore = _threatScore;
report.detectedPermissions = _permissions;
        report.proposer = msg.sender;
        report.proposedAt = block.timestamp;
        report.isConfirmed = false;
        report.isRevoked = false;
        report.approvalCount = 0;

        allThreatHashes.push(_apkHash);

        emit ThreatProposed(
            _apkHash,
            _url,
            _threatType,
            msg.sender,
            _threatScore,
            block.timestamp
        );

        // Auto-endorse by proposer
        endorseThreat(_apkHash);
    }

    /**
     * @notice Oracle Node endorses a proposed threat after sandbox / heuristic validation
     */
    function endorseThreat(bytes32 _apkHash) public onlyAuthorizedNode {
        ThreatReport storage report = threats[_apkHash];
        require(report.proposedAt > 0, "Threat report does not exist");
        require(!report.isRevoked, "Threat report has been revoked");
        require(!hasEndorsed[_apkHash][msg.sender], "Oracle has already endorsed this threat");

        hasEndorsed[_apkHash][msg.sender] = true;
        report.approvalCount += 1;
        oracleNodes[msg.sender].totalEndorsements += 1;

        emit ThreatEndorsed(
            _apkHash,
            msg.sender,
            oracleNodes[msg.sender].name,
            report.approvalCount,
            requiredSignatures
        );

        // Check if consensus threshold reached
        if (!report.isConfirmed && report.approvalCount >= requiredSignatures) {
            report.isConfirmed = true;
            report.confirmedAt = block.timestamp;

            emit MalwareConfirmed(
                _apkHash,
                report.url,
                report.threatType,
                report.threatScore,
                block.timestamp
            );
        }
    }

    /**
     * @notice Revokes a false positive threat report (admin or 2 nodes)
     */
    function revokeThreat(bytes32 _apkHash, string calldata _reason) external onlyOwner {
        ThreatReport storage report = threats[_apkHash];
        require(report.proposedAt > 0, "Threat report not found");
        report.isRevoked = true;
        report.isConfirmed = false;
        emit ThreatRevoked(_apkHash, msg.sender, _reason);
    }

    /**
     * @notice Verifies if an APK SHA-256 is a confirmed malware in real time
     */
    function isMalwareConfirmed(bytes32 _apkHash) external view returns (bool, uint8, string memory) {
        ThreatReport memory report = threats[_apkHash];
        if (report.isConfirmed && !report.isRevoked) {
            return (true, report.threatScore, report.threatType);
        }
        return (false, 0, "");
    }

    /**
     * @notice Get full threat information by hash
     */
    function getThreat(bytes32 _apkHash) external view returns (
        bytes32 apkHash,
        string memory url,
        string memory threatType,
        uint8 threatScore,
        string[] memory detectedPermissions,
        address proposer,
        uint256 proposedAt,
        uint256 confirmedAt,
        bool isConfirmed,
        bool isRevoked,
        uint256 approvalCount
    ) {
        ThreatReport memory report = threats[_apkHash];
        require(report.proposedAt > 0, "Threat report not found");
        return (
            report.apkHash,
            report.url,
            report.threatType,
            report.threatScore,
            report.detectedPermissions,
            report.proposer,
            report.proposedAt,
            report.confirmedAt,
            report.isConfirmed,
            report.isRevoked,
            report.approvalCount
        );
    }

    /**
     * @notice Get all threat hashes count
     */
    function getThreatCount() external view returns (uint256) {
        return allThreatHashes.length;
    }

    /**
     * @notice Get list of all oracle nodes
     */
    function getOracleNodes() external view returns (address[] memory, string[] memory, bool[] memory) {
        uint256 count = oracleNodeList.length;
        string[] memory names = new string[](count);
        bool[] memory statuses = new bool[](count);

        for (uint256 i = 0; i < count; i++) {
            address nodeAddr = oracleNodeList[i];
            names[i] = oracleNodes[nodeAddr].name;
            statuses[i] = oracleNodes[nodeAddr].isAuthorized;
        }

        return (oracleNodeList, names, statuses);
    }
}
