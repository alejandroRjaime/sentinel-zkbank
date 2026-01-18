// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

interface IVerifier {
    function verifyProof(
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint[3] calldata _pubSignals
    ) external view returns (bool);
}

interface IHasher {
    function poseidon(bytes32[2] calldata inputs) external view returns (bytes32);
}

contract ZKSentinel is ReentrancyGuard, Ownable {
    IVerifier public immutable verifier;
    IHasher public immutable hasher;
    
    uint256 public constant DENOMINATION = 0.01 ether;
    uint256 public constant MERKLE_TREE_HEIGHT = 20;
    uint256 public constant FIELD_SIZE = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    
    // Merkle tree
    mapping(uint256 => bytes32) public filledSubtrees;
    mapping(uint256 => bytes32) public roots;
    bytes32[MERKLE_TREE_HEIGHT] public zeros;
    uint32 public currentRootIndex = 0;
    uint32 public nextIndex = 0;
    uint32 public constant ROOT_HISTORY_SIZE = 100;
    
    mapping(bytes32 => bool) public commitments;
    mapping(bytes32 => bool) public nullifierHashes;
    
    uint256 public decoyPoolBalance;
    
    event Deposit(bytes32 indexed commitment, uint32 leafIndex, uint256 timestamp);
    event Withdrawal(address recipient, bytes32 nullifierHash, address relayer, uint256 fee);
    
    constructor(
        IVerifier _verifier,
        IHasher _hasher
    ) Ownable(msg.sender) {
        verifier = _verifier;
        hasher = _hasher;
        
        // Init Merkle tree zeros
        bytes32 currentZero = bytes32(0);
        zeros[0] = currentZero;
        filledSubtrees[0] = currentZero;
        
        for (uint32 i = 1; i < MERKLE_TREE_HEIGHT; i++) {
            currentZero = _hashLeftRight(currentZero, currentZero);
            zeros[i] = currentZero;
            filledSubtrees[i] = currentZero;
        }
        roots[0] = _hashLeftRight(currentZero, currentZero);
    }
    
    function deposit(bytes32 _commitment) external payable nonReentrant {
        require(msg.value == DENOMINATION, "Invalid amount");
        require(!commitments[_commitment], "Duplicate commitment");
        require(uint256(_commitment) < FIELD_SIZE, "Invalid commitment");
        
        uint32 idx = _insert(_commitment);
        commitments[_commitment] = true;
        
        emit Deposit(_commitment, idx, block.timestamp);
    }
    
    function withdraw(
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        bytes32 _root,
        bytes32 _nullifierHash,
        address payable _recipient,
        address payable _relayer,
        uint256 _fee
    ) external nonReentrant {
        require(_fee <= DENOMINATION, "Fee too high");
        require(!nullifierHashes[_nullifierHash], "Already spent");
        require(isKnownRoot(_root), "Invalid root");
        
        // CORRECT ORDER: [nullifierHash, root, recipient]
        uint[3] memory pubSignals = [
            uint256(_nullifierHash),
            uint256(_root),
            uint256(uint160(address(_recipient)))
        ];
        
        require(verifier.verifyProof(_pA, _pB, _pC, pubSignals), "Invalid proof");
        
        nullifierHashes[_nullifierHash] = true;
        
        uint256 payment = DENOMINATION - _fee;
        _recipient.transfer(payment);
        
        if (_fee > 0) {
            _relayer.transfer(_fee);
        }
        
        emit Withdrawal(_recipient, _nullifierHash, _relayer, _fee);
    }
    
    function fundDecoyPool() external payable {
        decoyPoolBalance += msg.value;
    }
    
    function _hashLeftRight(bytes32 _left, bytes32 _right) internal view returns (bytes32) {
        bytes32[2] memory inputs = [_left, _right];
        return hasher.poseidon(inputs);
    }
    
    function _insert(bytes32 _leaf) internal returns (uint32) {
        uint32 _nextIndex = nextIndex;
        require(_nextIndex < uint32(2**MERKLE_TREE_HEIGHT), "Tree full");
        
        uint32 currentIndex = _nextIndex;
        bytes32 currentHash = _leaf;
        bytes32 left;
        bytes32 right;
        
        for (uint32 i = 0; i < MERKLE_TREE_HEIGHT; i++) {
            if (currentIndex % 2 == 0) {
                left = currentHash;
                right = zeros[i];
                filledSubtrees[i] = currentHash;
            } else {
                left = filledSubtrees[i];
                right = currentHash;
            }
            currentHash = _hashLeftRight(left, right);
            currentIndex /= 2;
        }
        
        uint32 newRootIndex = (currentRootIndex + 1) % ROOT_HISTORY_SIZE;
        currentRootIndex = newRootIndex;
        roots[newRootIndex] = currentHash;
        nextIndex = _nextIndex + 1;
        
        return _nextIndex;
    }
    
    function isKnownRoot(bytes32 _root) public view returns (bool) {
        if (_root == bytes32(0)) return false;
        uint32 i = currentRootIndex;
        do {
            if (_root == roots[i]) return true;
            if (i == 0) i = ROOT_HISTORY_SIZE;
            i--;
        } while (i != currentRootIndex);
        return false;
    }
    
    function getLastRoot() public view returns (bytes32) {
        return roots[currentRootIndex];
    }
    
    function isSpent(bytes32 _nullifierHash) public view returns (bool) {
        return nullifierHashes[_nullifierHash];
    }
}
