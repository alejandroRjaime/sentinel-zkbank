// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IPoseidonT3 {
    function poseidon(uint256[2] memory inputs) external pure returns (uint256);
}

contract HasherWrapper {
    IPoseidonT3 public immutable poseidonImpl;
    
    constructor(address _poseidon) {
        poseidonImpl = IPoseidonT3(_poseidon);
    }
    
    function poseidon(bytes32[2] calldata inputs) external view returns (bytes32) {
        uint256[2] memory uintInputs = [uint256(inputs[0]), uint256(inputs[1])];
        return bytes32(poseidonImpl.poseidon(uintInputs));
    }
}
