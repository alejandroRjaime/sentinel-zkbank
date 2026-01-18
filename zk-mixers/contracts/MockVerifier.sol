// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "./IVerifier.sol";

/// @title Verificador Mock para testing
/// @notice Implementación simulada para testing y desarrollo
contract MockVerifier is IVerifier {
    address public admin;
    bool public paused;

    uint256 public totalVerified;
    uint256 public totalFailed;
    uint256 public lastVerification;

    // Para testing controlado
    mapping(bytes32 => bool) private _shouldVerify;

    constructor(address _admin) {
        admin = _admin;
    }

    function verifyProof(
        bytes calldata proof,
        bytes calldata inputs
    ) external override returns (bool) {
        require(!paused, "MockVerifier: paused");

        bytes32 proofHash = keccak256(proof);
        bool shouldVerify = _shouldVerify[proofHash];

        if (shouldVerify) {
            totalVerified++;
            emit VerificationSuccess(address(this), proofHash, block.timestamp);
            return true;
        } else {
            totalFailed++;
            emit VerificationFailure(address(this), proofHash, "Mock failure", block.timestamp);
            return false;
        }
    }

    function verifyProofWithContext(
        bytes calldata proof,
        bytes calldata inputs,
        bytes calldata extraData
    ) external override returns (bool) {
        // Implementación mock
        return this.verifyProof(proof, inputs);
    }

    function verifyProofBatch(
        bytes[] calldata proofs,
        bytes[] calldata inputs
    ) external override returns (bool[] memory) {
        require(proofs.length == inputs.length, "MockVerifier: length mismatch");

        bool[] memory results = new bool[](proofs.length);
        for (uint256 i = 0; i < proofs.length; i++) {
            results[i] = this.verifyProof(proofs[i], inputs[i]);
        }
        return results;
    }

    function getVerifierInfo() external view override returns (
        string memory version,
        bool isPaused,
        address adminAddress,
        uint256 constraints
    ) {
        return (
            "1.0.0-mock",
            paused,
            admin,
            500000 // Mock constraints
        );
    }

    function getVerificationStats() external view override returns (
        uint256 verified,
        uint256 failed,
        uint256 last
    ) {
        return (totalVerified, totalFailed, lastVerification);
    }

    function updateParameters(bytes calldata newParams) external override {
        require(msg.sender == admin, "MockVerifier: only admin");
        // Mock implementation
    }

    function setPaused(bool _paused) external override {
        require(msg.sender == admin, "MockVerifier: only admin");
        paused = _paused;
        emit VerifierStateUpdated(address(this), _paused, admin, block.timestamp);
    }

    // Funciones específicas para testing
    function setShouldVerify(bytes32 proofHash, bool shouldVerify) external {
        require(msg.sender == admin, "MockVerifier: only admin");
        _shouldVerify[proofHash] = shouldVerify;
    }

    function resetStats() external {
        require(msg.sender == admin, "MockVerifier: only admin");
        totalVerified = 0;
        totalFailed = 0;
    }
}