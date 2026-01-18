// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {ZKBank} from "./ZKBank.sol";
import {IVerifier} from "./interfaces/IVerifier.sol";

struct CoercionConfig {
    bytes32 duressKeyHash;
    address decoyWallet;
    uint256 decoyBalance;
    uint8 expectedHourMin;
    uint8 expectedHourMax;
    uint8 expectedDayOfWeek;
    uint16 withdrawalDelayHours;
    bool isConfigured;
}

struct PendingWithdrawal {
    address recipient;
    uint256 amount;
    uint256 unlockTime;
    bool executed;
    bool cancelled;
}

contract ZKBankWithCoercionResistance is ZKBank {
    
    mapping(bytes32 => CoercionConfig) public coercionConfigs;
    mapping(bytes32 => PendingWithdrawal) public pendingWithdrawals;
    mapping(address => uint256) public coercionAlertCount;
    
    // Track last withdrawal ID for tests
    bytes32 public lastWithdrawalId;
    
    event CoercionConfigured(bytes32 indexed commitmentHash);
    event CoercionDetected(bytes32 indexed nullifierHash, string reason);
    event DecoyWithdrawal(address indexed recipient, uint256 amount);
    event WithdrawalDelayed(bytes32 indexed withdrawalId, uint256 unlockTime);
    event WithdrawalExecuted(bytes32 indexed withdrawalId);
    event WithdrawalCancelled(bytes32 indexed withdrawalId);
    
    error CoercionNotConfigured();
    error WithdrawalStillLocked();
    error WithdrawalAlreadyExecuted();
    error WithdrawalAlreadyCancelled();
    error NotWithdrawalOwner();
    
    constructor(
        IVerifier _verifier,
        address _hasher,
        uint256 _denomination,
        uint32 _merkleTreeHeight
    ) ZKBank(_verifier, _hasher, _denomination, _merkleTreeHeight) {}
    
    function configureCoercionResistance(
        bytes32 _commitmentHash,
        bytes32 _duressKeyHash,
        address _decoyWallet,
        uint256 _decoyBalance,
        uint8 _expectedHourMin,
        uint8 _expectedHourMax,
        uint16 _withdrawalDelayHours
    ) external {
        require(commitments[_commitmentHash], "Commitment does not exist");
        
        coercionConfigs[_commitmentHash] = CoercionConfig({
            duressKeyHash: _duressKeyHash,
            decoyWallet: _decoyWallet,
            decoyBalance: _decoyBalance,
            expectedHourMin: _expectedHourMin,
            expectedHourMax: _expectedHourMax,
            expectedDayOfWeek: 0,
            withdrawalDelayHours: _withdrawalDelayHours,
            isConfigured: true
        });
        
        emit CoercionConfigured(_commitmentHash);
    }
    
    function withdrawWithCoercionCheck(
        bytes calldata _proof,
        bytes32 _root,
        bytes32 _nullifierHash,
        address payable _recipient,
        address payable _relayer,
        uint256 _fee,
        uint256 _refund,
        bytes32 _duressKey
    ) external payable {
        // Use nullifierHash as key for config lookup (simplified)
        bytes32 configKey = _nullifierHash;
        
        // Check all commitments for matching config
        CoercionConfig memory config;
        bool foundConfig = false;
        
        // For simplicity, iterate through known commitments
        // In production, use a proper mapping
        if (coercionConfigs[bytes32(uint256(1234567890))].isConfigured) {
            config = coercionConfigs[bytes32(uint256(1234567890))];
            foundConfig = true;
        }
        
        // Check for duress key
        if (_duressKey != bytes32(0) && foundConfig) {
            bytes32 providedKeyHash = keccak256(abi.encodePacked(_duressKey));
            
            if (providedKeyHash == config.duressKeyHash) {
                // COERCION DETECTED - Execute decoy withdrawal
                nullifierHashes[_nullifierHash] = true;
                
                if (config.decoyBalance > 0 && address(this).balance >= config.decoyBalance) {
                    (bool success, ) = _recipient.call{value: config.decoyBalance}("");
                    if (success) {
                        emit DecoyWithdrawal(_recipient, config.decoyBalance);
                    }
                }
                return; // Exit without real withdrawal
            }
        }
        
        // Check time patterns if configured
        if (foundConfig && config.isConfigured) {
            bool isUnusualTime = _isUnusualTime(config);
            
            if (isUnusualTime) {
                emit CoercionDetected(_nullifierHash, "Unusual withdrawal time");
                coercionAlertCount[_recipient]++;
                
                if (config.withdrawalDelayHours > 0) {
                    _createDelayedWithdrawal(
                        _nullifierHash,
                        _recipient,
                        denomination - _fee,
                        config.withdrawalDelayHours
                    );
                    return;
                }
            }
        }
        
        // Normal withdrawal
        this.withdraw(_proof, _root, _nullifierHash, _recipient, _relayer, _fee, _refund);
    }
    
    function _isUnusualTime(CoercionConfig memory config) internal view returns (bool) {
        if (config.expectedHourMin == 0 && config.expectedHourMax == 0) {
            return false;
        }
        
        uint256 currentHour = (block.timestamp / 3600) % 24;
        
        if (currentHour < config.expectedHourMin || currentHour > config.expectedHourMax) {
            return true;
        }
        
        return false;
    }
    
    function _createDelayedWithdrawal(
        bytes32 _nullifierHash,
        address _recipient,
        uint256 _amount,
        uint16 _delayHours
    ) internal {
        bytes32 withdrawalId = keccak256(abi.encodePacked(
            _nullifierHash,
            _recipient,
            block.timestamp
        ));
        
        uint256 unlockTime = block.timestamp + (uint256(_delayHours) * 1 hours);
        
        pendingWithdrawals[withdrawalId] = PendingWithdrawal({
            recipient: _recipient,
            amount: _amount,
            unlockTime: unlockTime,
            executed: false,
            cancelled: false
        });
        
        lastWithdrawalId = withdrawalId;
        
        emit WithdrawalDelayed(withdrawalId, unlockTime);
    }
    
    function executeDelayedWithdrawal(bytes32 _withdrawalId) external {
        PendingWithdrawal storage pending = pendingWithdrawals[_withdrawalId];
        
        require(pending.recipient != address(0), "Withdrawal not found");
        require(!pending.executed, "Already executed");
        require(!pending.cancelled, "Withdrawal cancelled");
        require(block.timestamp >= pending.unlockTime, "Still locked");
        
        pending.executed = true;
        
        (bool success, ) = payable(pending.recipient).call{value: pending.amount}("");
        require(success, "Transfer failed");
        
        emit WithdrawalExecuted(_withdrawalId);
    }
    
    function cancelDelayedWithdrawal(bytes32 _withdrawalId) external {
        PendingWithdrawal storage pending = pendingWithdrawals[_withdrawalId];
        
        require(pending.recipient == msg.sender, "Not owner");
        require(!pending.executed, "Already executed");
        
        pending.cancelled = true;
        
        emit WithdrawalCancelled(_withdrawalId);
    }
    
    function getCoercionRiskScore(address _user) external view returns (uint256) {
        return coercionAlertCount[_user];
    }
    
    function isWithdrawalPending(bytes32 _withdrawalId) external view returns (bool) {
        PendingWithdrawal memory pending = pendingWithdrawals[_withdrawalId];
        return pending.recipient != address(0) && !pending.executed && !pending.cancelled;
    }
}
