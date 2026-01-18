// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Script, console2} from "forge-std/Script.sol";
import {ZKBank} from "../contracts/ZKBank.sol";
import {ZKBankWithCoercionResistance} from "../contracts/ZKBankWithCoercionResistance.sol";
import {Hasher} from "../contracts/Hasher.sol";
import {IVerifier} from "../contracts/interfaces/IVerifier.sol";

/**
 * @title DeployZKBank
 * @notice Script de deployment para ZK Bank
 * 
 * Uso:
 *   forge script scripts/Deploy.s.sol:DeployZKBank --rpc-url $RPC_URL --broadcast
 *   
 * Con verificación:
 *   forge script scripts/Deploy.s.sol:DeployZKBank --rpc-url $RPC_URL --broadcast --verify
 */
contract DeployZKBank is Script {
    
    // Configuración por defecto
    uint256 constant DENOMINATION = 1 ether;
    uint32 constant MERKLE_HEIGHT = 20;  // Soporta ~1M deposits
    
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address verifierAddress = vm.envOr("VERIFIER_ADDRESS", address(0));
        
        vm.startBroadcast(deployerPrivateKey);
        
        // 1. Deploy Hasher (Poseidon)
        Hasher hasher = new Hasher();
        console2.log("Hasher deployed:", address(hasher));
        
        // 2. Deploy o usar Verifier existente
        if (verifierAddress == address(0)) {
            // En producción, el Verifier se genera con snarkjs
            // Por ahora usamos un mock
            console2.log("WARNING: Using mock verifier. Generate real one with snarkjs.");
            verifierAddress = address(new MockVerifier());
        }
        console2.log("Verifier:", verifierAddress);
        
        // 3. Deploy ZKBank básico
        ZKBank zkbank = new ZKBank(
            IVerifier(verifierAddress),
            address(hasher),
            DENOMINATION,
            MERKLE_HEIGHT
        );
        console2.log("ZKBank deployed:", address(zkbank));
        
        // 4. Deploy ZKBank con resistencia a coerción
        ZKBankWithCoercionResistance zkbankCoercion = new ZKBankWithCoercionResistance(
            IVerifier(verifierAddress),
            address(hasher),
            DENOMINATION,
            MERKLE_HEIGHT
        );
        console2.log("ZKBankWithCoercionResistance deployed:", address(zkbankCoercion));
        
        vm.stopBroadcast();
        
        // Output para fácil referencia
        console2.log("\n========================================");
        console2.log("DEPLOYMENT COMPLETE");
        console2.log("========================================");
        console2.log("Network:", block.chainid);
        console2.log("Denomination:", DENOMINATION / 1e18, "ETH");
        console2.log("Merkle Height:", MERKLE_HEIGHT);
        console2.log("Max Deposits:", uint256(2) ** MERKLE_HEIGHT);
        console2.log("----------------------------------------");
        console2.log("Hasher:", address(hasher));
        console2.log("Verifier:", verifierAddress);
        console2.log("ZKBank:", address(zkbank));
        console2.log("ZKBankCoercion:", address(zkbankCoercion));
        console2.log("========================================\n");
    }
}

/**
 * @title DeployToSepolia
 * @notice Deploy específico para Sepolia testnet
 */
contract DeployToSepolia is Script {
    
    uint256 constant DENOMINATION = 0.01 ether;  // Menor para testnet
    uint32 constant MERKLE_HEIGHT = 16;  // Menor para testnet
    
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        
        vm.startBroadcast(deployerPrivateKey);
        
        Hasher hasher = new Hasher();
        MockVerifier verifier = new MockVerifier();
        
        ZKBankWithCoercionResistance zkbank = new ZKBankWithCoercionResistance(
            IVerifier(address(verifier)),
            address(hasher),
            DENOMINATION,
            MERKLE_HEIGHT
        );
        
        vm.stopBroadcast();
        
        console2.log("\n=== SEPOLIA DEPLOYMENT ===");
        console2.log("ZKBank:", address(zkbank));
        console2.log("Denomination: 1 ETH");
        console2.log("==========================\n");
    }
}

/**
 * @title MockVerifier
 * @notice Mock verifier for testing (always returns true)
 */
contract MockVerifier is IVerifier {
    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[6] calldata
    ) external pure override returns (bool) {
        return true;
    }
}
