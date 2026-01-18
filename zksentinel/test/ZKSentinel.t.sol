// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../contracts/ZKSentinel.sol";
import "../contracts/Hasher.sol";

/**
 * Mock Verifier for testing (always returns true)
 */
contract MockVerifier is IVerifier {
    bool public shouldPass = true;
    
    function setPass(bool _pass) external {
        shouldPass = _pass;
    }
    
    function verifyProof(
        uint[2] calldata,
        uint[2][2] calldata,
        uint[2] calldata,
        uint[3] calldata
    ) external view returns (bool) {
        return shouldPass;
    }
}

contract ZKSentinelTest is Test {
    ZKSentinel public zkSentinel;
    MockVerifier public verifier;
    Hasher public hasher;
    
    address public user1 = address(0x1);
    address public user2 = address(0x2);
    address public relayer = address(0x3);
    
    bytes32 public constant COMMITMENT_1 = bytes32(uint256(12345));
    bytes32 public constant COMMITMENT_2 = bytes32(uint256(67890));
    bytes32 public constant NULLIFIER_HASH_1 = bytes32(uint256(11111));
    bytes32 public constant NULLIFIER_HASH_2 = bytes32(uint256(22222));
    
    function setUp() public {
        verifier = new MockVerifier();
        hasher = new Hasher();
        zkSentinel = new ZKSentinel(
            IVerifier(address(verifier)),
            IHasher(address(hasher))
        );
        
        // Fund test accounts
        vm.deal(user1, 100 ether);
        vm.deal(user2, 100 ether);
    }
    
    // ============ DEPOSIT TESTS ============
    
    function testDeposit() public {
        vm.prank(user1);
        zkSentinel.deposit{value: 1 ether}(COMMITMENT_1);
        
        assertTrue(zkSentinel.commitments(COMMITMENT_1));
        assertEq(address(zkSentinel).balance, 1 ether);
    }
    
    function testDepositEmitsEvent() public {
    vm.prank(user1);
    vm.recordLogs();
    zkSentinel.deposit{value: 1 ether}(COMMITMENT_1);
    
    Vm.Log[] memory entries = vm.getRecordedLogs();
    assertEq(entries.length, 1);
    }
    
    function testDepositFailsWithWrongAmount() public {
        vm.prank(user1);
        vm.expectRevert("Invalid amount");
        zkSentinel.deposit{value: 0.5 ether}(COMMITMENT_1);
    }
    
    function testDepositFailsDuplicate() public {
        vm.prank(user1);
        zkSentinel.deposit{value: 1 ether}(COMMITMENT_1);
        
        vm.prank(user2);
        vm.expectRevert("Duplicate commitment");
        zkSentinel.deposit{value: 1 ether}(COMMITMENT_1);
    }
    
    function testMultipleDeposits() public {
        vm.prank(user1);
        zkSentinel.deposit{value: 1 ether}(COMMITMENT_1);
        
        vm.prank(user2);
        zkSentinel.deposit{value: 1 ether}(COMMITMENT_2);
        
        assertTrue(zkSentinel.commitments(COMMITMENT_1));
        assertTrue(zkSentinel.commitments(COMMITMENT_2));
        assertEq(address(zkSentinel).balance, 2 ether);
    }
    
    // ============ WITHDRAW TESTS ============
    
    function testWithdraw() public {
        // First deposit
        vm.prank(user1);
        zkSentinel.deposit{value: 1 ether}(COMMITMENT_1);
        
        bytes32 root = zkSentinel.getLastRoot();
        
        // Mock proof data
        uint[2] memory pA = [uint(0), uint(0)];
        uint[2][2] memory pB = [[uint(0), uint(0)], [uint(0), uint(0)]];
        uint[2] memory pC = [uint(0), uint(0)];
        
        uint256 balanceBefore = user2.balance;
        
        // Withdraw
        vm.prank(user2);
        zkSentinel.withdraw(
            pA, pB, pC,
            root,
            NULLIFIER_HASH_1,
            payable(user2),
            payable(address(0)),
            0
        );
        
        assertTrue(zkSentinel.isSpent(NULLIFIER_HASH_1));
        assertEq(user2.balance, balanceBefore + 1 ether);
    }
    
    function testWithdrawWithRelayer() public {
        vm.prank(user1);
        zkSentinel.deposit{value: 1 ether}(COMMITMENT_1);
        
        bytes32 root = zkSentinel.getLastRoot();
        
        uint[2] memory pA = [uint(0), uint(0)];
        uint[2][2] memory pB = [[uint(0), uint(0)], [uint(0), uint(0)]];
        uint[2] memory pC = [uint(0), uint(0)];
        
        uint256 fee = 0.01 ether;
        uint256 userBalanceBefore = user2.balance;
        uint256 relayerBalanceBefore = relayer.balance;
        
        vm.prank(relayer);
        zkSentinel.withdraw(
            pA, pB, pC,
            root,
            NULLIFIER_HASH_1,
            payable(user2),
            payable(relayer),
            fee
        );
        
        assertEq(user2.balance, userBalanceBefore + 1 ether - fee);
        assertEq(relayer.balance, relayerBalanceBefore + fee);
    }
    
    function testWithdrawFailsDoubleSpend() public {
        vm.prank(user1);
        zkSentinel.deposit{value: 1 ether}(COMMITMENT_1);
        
        bytes32 root = zkSentinel.getLastRoot();
        
        uint[2] memory pA = [uint(0), uint(0)];
        uint[2][2] memory pB = [[uint(0), uint(0)], [uint(0), uint(0)]];
        uint[2] memory pC = [uint(0), uint(0)];
        
        // First withdraw
        zkSentinel.withdraw(
            pA, pB, pC,
            root,
            NULLIFIER_HASH_1,
            payable(user2),
            payable(address(0)),
            0
        );
        
        // Try double spend
        vm.expectRevert("Already spent");
        zkSentinel.withdraw(
            pA, pB, pC,
            root,
            NULLIFIER_HASH_1,
            payable(user2),
            payable(address(0)),
            0
        );
    }
    
    function testWithdrawFailsInvalidProof() public {
        vm.prank(user1);
        zkSentinel.deposit{value: 1 ether}(COMMITMENT_1);
        
        bytes32 root = zkSentinel.getLastRoot();
        
        // Set verifier to fail
        verifier.setPass(false);
        
        uint[2] memory pA = [uint(0), uint(0)];
        uint[2][2] memory pB = [[uint(0), uint(0)], [uint(0), uint(0)]];
        uint[2] memory pC = [uint(0), uint(0)];
        
        vm.expectRevert("Invalid proof");
        zkSentinel.withdraw(
            pA, pB, pC,
            root,
            NULLIFIER_HASH_1,
            payable(user2),
            payable(address(0)),
            0
        );
    }
    
    function testWithdrawFailsInvalidRoot() public {
        vm.prank(user1);
        zkSentinel.deposit{value: 1 ether}(COMMITMENT_1);
        
        uint[2] memory pA = [uint(0), uint(0)];
        uint[2][2] memory pB = [[uint(0), uint(0)], [uint(0), uint(0)]];
        uint[2] memory pC = [uint(0), uint(0)];
        
        bytes32 fakeRoot = bytes32(uint256(99999));
        
        vm.expectRevert("Invalid root");
        zkSentinel.withdraw(
            pA, pB, pC,
            fakeRoot,
            NULLIFIER_HASH_1,
            payable(user2),
            payable(address(0)),
            0
        );
    }
    
    function testWithdrawFailsFeeTooHigh() public {
        vm.prank(user1);
        zkSentinel.deposit{value: 1 ether}(COMMITMENT_1);
        
        bytes32 root = zkSentinel.getLastRoot();
        
        uint[2] memory pA = [uint(0), uint(0)];
        uint[2][2] memory pB = [[uint(0), uint(0)], [uint(0), uint(0)]];
        uint[2] memory pC = [uint(0), uint(0)];
        
        vm.expectRevert("Fee too high");
        zkSentinel.withdraw(
            pA, pB, pC,
            root,
            NULLIFIER_HASH_1,
            payable(user2),
            payable(relayer),
            2 ether  // More than denomination
        );
    }
    
    // ============ DECOY POOL TESTS ============
    
    function testFundDecoyPool() public {
        vm.prank(user1);
        zkSentinel.fundDecoyPool{value: 5 ether}();
        
        assertEq(zkSentinel.decoyPoolBalance(), 5 ether);
    }
    
    // ============ MERKLE TREE TESTS ============
    
    function testMerkleRootUpdates() public {
        bytes32 root1 = zkSentinel.getLastRoot();
        
        vm.prank(user1);
        zkSentinel.deposit{value: 1 ether}(COMMITMENT_1);
        
        bytes32 root2 = zkSentinel.getLastRoot();
        
        assertTrue(root1 != root2);
        assertTrue(zkSentinel.isKnownRoot(root2));
    }
    
    function testRootHistoryMaintained() public {
        bytes32 root0 = zkSentinel.getLastRoot();
        
        vm.prank(user1);
        zkSentinel.deposit{value: 1 ether}(COMMITMENT_1);
        bytes32 root1 = zkSentinel.getLastRoot();
        
        vm.prank(user2);
        zkSentinel.deposit{value: 1 ether}(COMMITMENT_2);
        bytes32 root2 = zkSentinel.getLastRoot();
        
        // All roots should be known
        assertTrue(zkSentinel.isKnownRoot(root0));
        assertTrue(zkSentinel.isKnownRoot(root1));
        assertTrue(zkSentinel.isKnownRoot(root2));
    }
    
    // ============ VIEW FUNCTIONS ============
    
    function testIsSpent() public {
        assertFalse(zkSentinel.isSpent(NULLIFIER_HASH_1));
        
        vm.prank(user1);
        zkSentinel.deposit{value: 1 ether}(COMMITMENT_1);
        
        bytes32 root = zkSentinel.getLastRoot();
        
        uint[2] memory pA = [uint(0), uint(0)];
        uint[2][2] memory pB = [[uint(0), uint(0)], [uint(0), uint(0)]];
        uint[2] memory pC = [uint(0), uint(0)];
        
        zkSentinel.withdraw(
            pA, pB, pC,
            root,
            NULLIFIER_HASH_1,
            payable(user2),
            payable(address(0)),
            0
        );
        
        assertTrue(zkSentinel.isSpent(NULLIFIER_HASH_1));
    }
}
