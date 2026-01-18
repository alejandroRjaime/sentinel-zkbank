// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../contracts/ZKSentinel.sol";

contract DeployZKSentinel is Script {
    function run() external {
        vm.startBroadcast();
        
        ZKSentinel zkSentinel = new ZKSentinel(
            IVerifier(0xb4d9DdF8de53385932db1285a0E0d13016A24626),
            IHasher(0x9aeB1EF03F83e6a20E30537dEb2E63ed9134356e)
        );
        
        vm.stopBroadcast();
    }
}
