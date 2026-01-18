// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Script, console2} from "forge-std/Script.sol";
import {ZKBank} from "../contracts/ZKBank.sol";
import {ZKBankWithCoercionResistance} from "../contracts/ZKBankWithCoercionResistance.sol";
import {IVerifier} from "../contracts/interfaces/IVerifier.sol";

contract MockVerifier is IVerifier {
    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[6] calldata
    ) external pure returns (bool) {
        return true;
    }
}

contract MockHasher {
    function poseidon(bytes32[2] calldata inputs) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(inputs[0], inputs[1]));
    }
}

contract DeploySimple is Script {
    function run() external {
        vm.startBroadcast();

        MockVerifier verifier = new MockVerifier();
        MockHasher hasher = new MockHasher();
        
        ZKBank zkbank = new ZKBank(
            IVerifier(address(verifier)),
            address(hasher),
            0.01 ether,
            20
        );

        ZKBankWithCoercionResistance zkbankCoercion = new ZKBankWithCoercionResistance(
            IVerifier(address(verifier)),
            address(hasher),
            0.01 ether,
            20
        );

        vm.stopBroadcast();

        console2.log("=== ZK Bank Deployed ===");
        console2.log("Verifier:", address(verifier));
        console2.log("Hasher:", address(hasher));
        console2.log("ZKBank:", address(zkbank));
        console2.log("ZKBankCoercion:", address(zkbankCoercion));
    }
}
