// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test, console2} from "forge-std/Test.sol";
import {ZKBank} from "../contracts/ZKBank.sol";
import {ZKBankWithCoercionResistance} from "../contracts/ZKBankWithCoercionResistance.sol";
import {IVerifier} from "../contracts/interfaces/IVerifier.sol";

contract MockVerifier is IVerifier {
    bool public shouldVerify = true;
    
    function setVerifyResult(bool _result) external {
        shouldVerify = _result;
    }
    
    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[6] calldata
    ) external view override returns (bool) {
        return shouldVerify;
    }
}

contract MockHasher {
    function poseidon(bytes32[2] calldata inputs) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(inputs[0], inputs[1]));
    }
}

contract ZKBankTest is Test {
    
    ZKBank public zkbank;
    ZKBankWithCoercionResistance public zkbankCoercion;
    MockVerifier public verifier;
    MockHasher public hasher;
    
    address public alice = makeAddr("alice");
    address public bob = makeAddr("bob");
    address public attacker = makeAddr("attacker");
    address public relayer = makeAddr("relayer");
    
    uint256 constant DENOMINATION = 1 ether;
    uint32 constant MERKLE_HEIGHT = 20;
    
    bytes32 constant TEST_COMMITMENT = bytes32(uint256(1234567890));
    bytes32 constant TEST_NULLIFIER_HASH = bytes32(uint256(9876543210));
    
    function setUp() public {
        verifier = new MockVerifier();
        hasher = new MockHasher();
        
        zkbank = new ZKBank(
            IVerifier(address(verifier)),
            address(hasher),
            DENOMINATION,
            MERKLE_HEIGHT
        );
        
        zkbankCoercion = new ZKBankWithCoercionResistance(
            IVerifier(address(verifier)),
            address(hasher),
            DENOMINATION,
            MERKLE_HEIGHT
        );
        
        vm.deal(alice, 100 ether);
        vm.deal(bob, 100 ether);
        vm.deal(attacker, 10 ether);
        vm.deal(address(zkbankCoercion), 10 ether);
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // DEPOSIT TESTS
    // ═══════════════════════════════════════════════════════════════════════
    
    function test_Deposit() public {
        vm.prank(alice);
        zkbank.deposit{value: DENOMINATION}(TEST_COMMITMENT);
        
        assertTrue(zkbank.commitments(TEST_COMMITMENT));
        assertEq(address(zkbank).balance, DENOMINATION);
    }
    
    function test_Deposit_RevertIfWrongAmount() public {
        vm.prank(alice);
        vm.expectRevert(ZKBank.InvalidDenomination.selector);
        zkbank.deposit{value: 0.5 ether}(TEST_COMMITMENT);
    }
    
    function test_Deposit_RevertIfDuplicate() public {
        vm.prank(alice);
        zkbank.deposit{value: DENOMINATION}(TEST_COMMITMENT);
        
        vm.prank(alice);
        vm.expectRevert(ZKBank.CommitmentAlreadyExists.selector);
        zkbank.deposit{value: DENOMINATION}(TEST_COMMITMENT);
    }
    
    function test_MultipleDeposits() public {
        for (uint256 i = 0; i < 10; i++) {
            bytes32 commitment = bytes32(uint256(i + 1));
            vm.prank(alice);
            zkbank.deposit{value: DENOMINATION}(commitment);
        }
        
        assertEq(address(zkbank).balance, 10 ether);
        assertEq(zkbank.nextIndex(), 10);
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // WITHDRAW TESTS
    // ═══════════════════════════════════════════════════════════════════════
    
    function test_Withdraw() public {
        vm.prank(alice);
        zkbank.deposit{value: DENOMINATION}(TEST_COMMITMENT);
        
        bytes32 root = zkbank.getLastRoot();
        bytes memory proof = _createMockProof();
        
        uint256 bobBalanceBefore = bob.balance;
        
        zkbank.withdraw(
            proof,
            root,
            TEST_NULLIFIER_HASH,
            payable(bob),
            payable(address(0)),
            0,
            0
        );
        
        assertEq(bob.balance, bobBalanceBefore + DENOMINATION);
        assertTrue(zkbank.isSpent(TEST_NULLIFIER_HASH));
    }
    
    function test_Withdraw_WithRelayerFee() public {
        vm.prank(alice);
        zkbank.deposit{value: DENOMINATION}(TEST_COMMITMENT);
        
        bytes32 root = zkbank.getLastRoot();
        bytes memory proof = _createMockProof();
        
        uint256 fee = 0.01 ether;
        uint256 bobBalanceBefore = bob.balance;
        uint256 relayerBalanceBefore = relayer.balance;
        
        zkbank.withdraw(
            proof,
            root,
            TEST_NULLIFIER_HASH,
            payable(bob),
            payable(relayer),
            fee,
            0
        );
        
        assertEq(bob.balance, bobBalanceBefore + DENOMINATION - fee);
        assertEq(relayer.balance, relayerBalanceBefore + fee);
    }
    
    function test_Withdraw_RevertIfDoubleSpend() public {
        vm.prank(alice);
        zkbank.deposit{value: DENOMINATION}(TEST_COMMITMENT);
        
        bytes32 root = zkbank.getLastRoot();
        bytes memory proof = _createMockProof();
        
        zkbank.withdraw(
            proof, root, TEST_NULLIFIER_HASH,
            payable(bob), payable(address(0)), 0, 0
        );
        
        vm.expectRevert(ZKBank.NullifierAlreadyUsed.selector);
        zkbank.withdraw(
            proof, root, TEST_NULLIFIER_HASH,
            payable(bob), payable(address(0)), 0, 0
        );
    }
    
    function test_Withdraw_RevertIfInvalidProof() public {
        vm.prank(alice);
        zkbank.deposit{value: DENOMINATION}(TEST_COMMITMENT);
        
        bytes32 root = zkbank.getLastRoot();
        bytes memory proof = _createMockProof();
        
        verifier.setVerifyResult(false);
        
        vm.expectRevert(ZKBank.InvalidProof.selector);
        zkbank.withdraw(
            proof, root, TEST_NULLIFIER_HASH,
            payable(bob), payable(address(0)), 0, 0
        );
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // COERCION RESISTANCE TESTS
    // ═══════════════════════════════════════════════════════════════════════
    
    function test_ConfigureCoercionResistance() public {
        vm.prank(alice);
        zkbankCoercion.deposit{value: DENOMINATION}(TEST_COMMITMENT);
        
        bytes32 duressKeyHash = keccak256(abi.encodePacked(bytes32(uint256(1111))));
        address decoyWallet = makeAddr("decoy");
        
        zkbankCoercion.configureCoercionResistance(
            TEST_COMMITMENT,
            duressKeyHash,
            decoyWallet,
            0.1 ether,
            9,
            17,
            24
        );
        
        (
            bytes32 storedDuressKeyHash,
            address storedDecoyWallet,
            uint256 storedDecoyBalance,
            uint8 hourMin,
            uint8 hourMax,
            ,
            uint16 delay,
            bool isConfigured
        ) = zkbankCoercion.coercionConfigs(TEST_COMMITMENT);
        
        assertTrue(isConfigured);
        assertEq(storedDuressKeyHash, duressKeyHash);
        assertEq(storedDecoyWallet, decoyWallet);
        assertEq(storedDecoyBalance, 0.1 ether);
        assertEq(hourMin, 9);
        assertEq(hourMax, 17);
        assertEq(delay, 24);
    }
    
    function test_CoercionDetection_DuressKey() public {
        vm.prank(alice);
        zkbankCoercion.deposit{value: DENOMINATION}(TEST_COMMITMENT);
        
        bytes32 duressKey = bytes32(uint256(1111));
        bytes32 duressKeyHash = keccak256(abi.encodePacked(duressKey));
        address decoyWallet = makeAddr("decoy");
        
        zkbankCoercion.configureCoercionResistance(
            TEST_COMMITMENT,
            duressKeyHash,
            decoyWallet,
            0.1 ether,
            0, 0, 0
        );
        
        bytes32 root = zkbankCoercion.getLastRoot();
        bytes memory proof = _createMockProof();
        
        uint256 attackerBalanceBefore = attacker.balance;
        
        zkbankCoercion.withdrawWithCoercionCheck(
            proof, root, TEST_NULLIFIER_HASH,
            payable(attacker), payable(address(0)), 0, 0,
            duressKey
        );
        
        // Attacker only gets decoy amount
        assertEq(attacker.balance, attackerBalanceBefore + 0.1 ether);
        // Nullifier marked as used
        assertTrue(zkbankCoercion.isSpent(TEST_NULLIFIER_HASH));
    }
    
    function test_CoercionDetection_UnusualTime() public {
        vm.prank(alice);
        zkbankCoercion.deposit{value: DENOMINATION}(TEST_COMMITMENT);
        
        zkbankCoercion.configureCoercionResistance(
            TEST_COMMITMENT,
            bytes32(0),
            address(0),
            0,
            9, 17, 24
        );
        
        // Set time to 3 AM (unusual)
        vm.warp(3 * 3600);
        
        bytes32 root = zkbankCoercion.getLastRoot();
        bytes memory proof = _createMockProof();
        
        zkbankCoercion.withdrawWithCoercionCheck(
            proof, root, TEST_NULLIFIER_HASH,
            payable(bob), payable(address(0)), 0, 0, bytes32(0)
        );
        
        assertEq(zkbankCoercion.getCoercionRiskScore(bob), 1);
    }
    
    function test_DelayedWithdrawal_Execute() public {
        vm.prank(alice);
        zkbankCoercion.deposit{value: DENOMINATION}(TEST_COMMITMENT);
        
        zkbankCoercion.configureCoercionResistance(
            TEST_COMMITMENT, bytes32(0), address(0), 0,
            9, 17, 24
        );
        
        vm.warp(3 * 3600);
        
        bytes32 root = zkbankCoercion.getLastRoot();
        bytes memory proof = _createMockProof();
        
        zkbankCoercion.withdrawWithCoercionCheck(
            proof, root, TEST_NULLIFIER_HASH,
            payable(bob), payable(address(0)), 0, 0, bytes32(0)
        );
        
        // Get the actual withdrawal ID from contract
        bytes32 withdrawalId = zkbankCoercion.lastWithdrawalId();
        
        assertTrue(zkbankCoercion.isWithdrawalPending(withdrawalId));
        
        // Try before delay
        vm.expectRevert("Still locked");
        zkbankCoercion.executeDelayedWithdrawal(withdrawalId);
        
        // Fast forward 25 hours
        vm.warp(block.timestamp + 25 hours);
        
        uint256 bobBalanceBefore = bob.balance;
        zkbankCoercion.executeDelayedWithdrawal(withdrawalId);
        
        assertEq(bob.balance, bobBalanceBefore + DENOMINATION);
    }
    
    function test_DelayedWithdrawal_Cancel() public {
        vm.prank(alice);
        zkbankCoercion.deposit{value: DENOMINATION}(TEST_COMMITMENT);
        
        zkbankCoercion.configureCoercionResistance(
            TEST_COMMITMENT, bytes32(0), address(0), 0,
            9, 17, 24
        );
        
        vm.warp(3 * 3600);
        
        bytes32 root = zkbankCoercion.getLastRoot();
        bytes memory proof = _createMockProof();
        
        zkbankCoercion.withdrawWithCoercionCheck(
            proof, root, TEST_NULLIFIER_HASH,
            payable(bob), payable(address(0)), 0, 0, bytes32(0)
        );
        
        bytes32 withdrawalId = zkbankCoercion.lastWithdrawalId();
        
        vm.prank(bob);
        zkbankCoercion.cancelDelayedWithdrawal(withdrawalId);
        
        assertFalse(zkbankCoercion.isWithdrawalPending(withdrawalId));
    }
    
    function _createMockProof() internal pure returns (bytes memory) {
        uint256[8] memory proof;
        for (uint i = 0; i < 8; i++) {
            proof[i] = i + 1;
        }
        return abi.encode(proof);
    }
}
