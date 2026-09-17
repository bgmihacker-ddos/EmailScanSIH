// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract EvidenceLedger {
    mapping(string => bytes32) public evidenceHashes;
    address public owner;

    event EvidenceAnchored(string analysisId, bytes32 hash, uint256 timestamp);

    constructor() {
        owner = msg.sender;
    }

    function anchorEvidence(string memory analysisId, bytes32 hash) public {
        evidenceHashes[analysisId] = hash;
        emit EvidenceAnchored(analysisId, hash, block.timestamp);
    }

    function getEvidenceHash(string memory analysisId) public view returns (bytes32) {
        return evidenceHashes[analysisId];
    }
}
