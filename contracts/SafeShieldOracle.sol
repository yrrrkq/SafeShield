// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SafeShieldOracle {
    address public owner;
    uint256 public requiredSignatures;

    struct ThreatReport {
        bytes32 apkHash;
        string url;
        string threatType;
        uint8 threatScore;
        string[] detectedPermissions;
        address proposer;
        uint256 proposedAt;
        uint256 confirmedAt;
        bool isConfirmed;
        bool isRevoked;
        uint256 approvalCount;
    }

    struct OracleNode {
        string name;
        bool isAuthorized;
        uint256 totalEndorsements;
    }

    mapping(address => OracleNode) public oracleNodes;
    address[] public oracleNodeList;

    mapping(bytes32 => ThreatReport) public threats;
    bytes32[] public allThreatHashes;

    mapping(bytes32 => mapping(address => bool)) public hasEndorsed;

    event OracleNodeAdded(
        address indexed nodeAddress,
        string name
    );

    event OracleNodeRemoved(
        address indexed nodeAddress
    );

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

    event ThreatRevoked(
        bytes32 indexed apkHash,
        address indexed revoker,
        string reason
    );

    modifier onlyOwner() {
        require(
            msg.sender == owner,
            "SafeShield: Only owner can call this"
        );
        _;
    }

    modifier onlyAuthorizedNode() {
        require(
            oracleNodes[msg.sender].isAuthorized || msg.sender == owner,
            "SafeShield: Caller is not an authorized Oracle Node"
        );
        _;
    }

    constructor(uint256 _requiredSignatures) {
        owner = msg.sender;
        requiredSignatures =
            _requiredSignatures > 0 ? _requiredSignatures : 2;
    }

    // Oracle Node 등록
    function addOracleNode(
        address _node,
        string calldata _name
    ) external onlyOwner {
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

    // Oracle Node 권한 해제
    function removeOracleNode(
        address _node
    ) external onlyOwner {
        require(
            oracleNodes[_node].isAuthorized,
            "Node not authorized"
        );

        oracleNodes[_node].isAuthorized = false;

        emit OracleNodeRemoved(_node);
    }

    // 검증에 필요한 최소 승인 수 변경
    function setRequiredSignatures(
        uint256 _newThreshold
    ) external onlyOwner {
        require(
            _newThreshold > 0 &&
            _newThreshold <= oracleNodeList.length,
            "Invalid threshold"
        );

        requiredSignatures = _newThreshold;
    }

    // AI Sandbox가 탐지한 위협 등록
    function proposeThreat(
        bytes32 _apkHash,
        string calldata _url,
        string calldata _threatType,
        uint8 _threatScore,
        string[] calldata _permissions
    ) external onlyAuthorizedNode {
        require(
            _apkHash != bytes32(0),
            "Invalid hash"
        );

        require(
            threats[_apkHash].proposedAt == 0,
            "Threat hash already registered"
        );

        ThreatReport storage report = threats[_apkHash];

        report.apkHash = _apkHash;
        report.url = _url;
        report.threatType = _threatType;
        report.threatScore = _threatScore;

        // calldata 배열을 storage에 하나씩 저장
        for (uint256 i = 0; i < _permissions.length; i++) {
            report.detectedPermissions.push(_permissions[i]);
        }

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

        // 제안자가 첫 번째 승인자로 자동 등록
        endorseThreat(_apkHash);
    }

    // Oracle Node 위협 승인
    function endorseThreat(
        bytes32 _apkHash
    ) public onlyAuthorizedNode {
        ThreatReport storage report = threats[_apkHash];

        require(
            report.proposedAt > 0,
            "Threat report does not exist"
        );

        require(
            !report.isRevoked,
            "Threat report has been revoked"
        );

        require(
            !hasEndorsed[_apkHash][msg.sender],
            "Oracle has already endorsed this threat"
        );

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

        // 필요한 승인 수에 도달하면 악성 위협 확정
        if (
            !report.isConfirmed &&
            report.approvalCount >= requiredSignatures
        ) {
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

    // 오탐으로 판단된 위협 취소
    function revokeThreat(
        bytes32 _apkHash,
        string calldata _reason
    ) external onlyOwner {
        ThreatReport storage report = threats[_apkHash];

        require(
            report.proposedAt > 0,
            "Threat report not found"
        );

        report.isRevoked = true;
        report.isConfirmed = false;

        emit ThreatRevoked(
            _apkHash,
            msg.sender,
            _reason
        );
    }

    // APK가 확정된 악성코드인지 확인
    function isMalwareConfirmed(
        bytes32 _apkHash
    )
        external
        view
        returns (
            bool,
            uint8,
            string memory
        )
    {
        ThreatReport memory report = threats[_apkHash];

        if (
            report.isConfirmed &&
            !report.isRevoked
        ) {
            return (
                true,
                report.threatScore,
                report.threatType
            );
        }

        return (false, 0, "");
    }

    // 위협 상세 정보 조회
    function getThreat(
        bytes32 _apkHash
    )
        external
        view
        returns (
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
        )
    {
        ThreatReport memory report = threats[_apkHash];

        require(
            report.proposedAt > 0,
            "Threat report not found"
        );

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

    function getThreatCount()
        external
        view
        returns (uint256)
    {
        return allThreatHashes.length;
    }

    // 등록된 Oracle Node 목록 조회
    function getOracleNodes()
        external
        view
        returns (
            address[] memory,
            string[] memory,
            bool[] memory
        )
    {
        uint256 count = oracleNodeList.length;

        string[] memory names =
            new string[](count);

        bool[] memory statuses =
            new bool[](count);

        for (uint256 i = 0; i < count; i++) {
            address nodeAddr =
                oracleNodeList[i];

            names[i] =
                oracleNodes[nodeAddr].name;

            statuses[i] =
                oracleNodes[nodeAddr].isAuthorized;
        }

        return (
            oracleNodeList,
            names,
            statuses
        );
    }
}