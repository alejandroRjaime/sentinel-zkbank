// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../contracts/ZKSentinel.sol";
import "../contracts/HasherWrapper.sol";
import "../contracts/Verifier.sol";

contract DeployAll is Script {
    function run() external {
        vm.startBroadcast();
        
        // Poseidon ya desplegado
        address poseidonAddr = 0xdBb0617Ac7E21744132127719D6a50C71910Bd8f;
        
        // Deploy Verifier
        Groth16Verifier verifier = new Groth16Verifier();
        console.log("Verifier:", address(verifier));
        
        // Deploy HasherWrapper
        HasherWrapper hasher = new HasherWrapper(poseidonAddr);
        console.log("HasherWrapper:", address(hasher));
        
        // Deploy ZKSentinel
        ZKSentinel zkSentinel = new ZKSentinel(
            IVerifier(address(verifier)),
            IHasher(address(hasher))
        );
        console.log("ZKSentinel:", address(zkSentinel));
        
        vm.stopBroadcast();
    }
}
