// 블록체인 핵심 로직

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ThreatRegistry {

    // 1. 위협의 현재 상태
    enum Status {
        NONE,
        PENDING,
        CONFIRMED,
        REJECTED
    }

    // 2. 위협 하나에 저장할 정보
    struct Threat {
        bytes32 urlHash;
        bytes32 apkHash;
        bytes32 evidenceHash;
        string c2;

        uint8 riskScore;
        uint8 approveCount;
        uint8 rejectCount;

        Status status;
        uint256 createdAt;
    }

    // 3. 검증기관인지 확인
    mapping(address => bool) public validators;

    // 4. threatId → 위협 정보
    mapping(bytes32 => Threat) public threats;

    // 5. 한 기관이 중복 투표하는 것 방지
    mapping(bytes32 => mapping(address => bool)) public voted;

    // 참여 Validator의 과반수가 승인하면 확정
    uint256 public validatorCount;
    uint256 public threshold;

    constructor(address[] memory _validators) {
        require(_validators.length > 0, "No validators");

        validatorCount = _validators.length;
        threshold = validatorCount / 2 + 1;

        for (uint256 i = 0; i < _validators.length; i++) {
            validators[_validators[i]] = true;
        }
    }


    // Events
    event ThreatSubmitted(
        bytes32 indexed threatId
    );
    event ThreatApproved(
        bytes32 indexed threatId,
        address indexed validator,
        uint8 approveCount
    );
    event ThreatRejected(
        bytes32 indexed threatId,
        address indexed validator,
        uint8 rejectCount
    );
    event ThreatConfirmed(
        bytes32 indexed threatId,
        bytes32 urlHash,
        bytes32 apkHash
    );


    // 검증기관만 실행 가능
    modifier onlyValidator() {
        require(
            validators[msg.sender],
            "Not validator"
        );
        _;
    }


    // 1. 위협 등록 (악성 의심 정보 등록)
    function submitThreat(
        bytes32 _urlHash,
        bytes32 _apkHash,
        bytes32 _evidenceHash,
        string memory _c2,
        uint8 _riskScore
    ) public returns (bytes32) {

        bytes32 threatId = keccak256(
            abi.encodePacked(
                _urlHash,
                _apkHash,
                _evidenceHash
            )
        );

        require(
            threats[threatId].status == Status.NONE,
            "Already registered"
        );

        threats[threatId] = Threat({
            urlHash: _urlHash,
            apkHash: _apkHash,
            evidenceHash: _evidenceHash,
            c2: _c2,

            riskScore: _riskScore,

            approveCount: 0,
            rejectCount: 0,

            status: Status.PENDING,

            createdAt: block.timestamp
        });
        emit ThreatSubmitted(threatId);
        return threatId;
    }


    // 2. 기관 승인 (악성이라고 승인)
    function approveThreat(
        bytes32 _threatId
    ) public onlyValidator {

        Threat storage threat =
            threats[_threatId];

        require(
            threat.status == Status.PENDING,
            "Not pending"
        );

        require(
            !voted[_threatId][msg.sender],
            "Already voted"
        );

        voted[_threatId][msg.sender] = true;
        threat.approveCount++;

        emit ThreatApproved(
            _threatId,
            msg.sender,
            threat.approveCount
        );

        // 과반수 승인했는지 검사
        if (threat.approveCount >= threshold) {
            threat.status = Status.CONFIRMED;
            emit ThreatConfirmed(
                _threatId,
                threat.urlHash,
                threat.apkHash
            );
        }
    }


    // 3. 기관 거절 (정상이라고 거절)
    function rejectThreat(
        bytes32 _threatId
    ) public onlyValidator {

        Threat storage threat =
            threats[_threatId];

        require(
            threat.status == Status.PENDING,
            "Not pending"
        );
        require(
            !voted[_threatId][msg.sender],
            "Already voted"
        );

        voted[_threatId][msg.sender] = true;

        threat.rejectCount++;

        emit ThreatRejected(
            _threatId,
            msg.sender,
            threat.rejectCount
        );

        // 과반수가 거절하면 REJECTED
        if (threat.rejectCount >= threshold) {
            threat.status = Status.REJECTED;
        }
    }

    // 4. 최종 블랙리스트인지 조회
    function isBlacklisted(
        bytes32 _threatId
    ) public view returns (bool) {

        return threats[_threatId].status
            == Status.CONFIRMED;
    }
}