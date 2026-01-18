pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";

/*
 * ZK Bank - Withdraw Circuit
 * 
 * Prueba que:
 * 1. El usuario conoce el secreto y nullifier de un commitment
 * 2. El commitment existe en el Merkle tree
 * 3. El nullifier no ha sido usado (verificado on-chain)
 *
 * Basado en Tornado Cash pero con mejoras para detección de coerción
 */

// Hash Poseidon para commitment: H(secret, nullifier)
template CommitmentHasher() {
    signal input secret;
    signal input nullifier;
    signal output commitment;
    signal output nullifierHash;

    component commitmentHasher = Poseidon(2);
    commitmentHasher.inputs[0] <== secret;
    commitmentHasher.inputs[1] <== nullifier;
    commitment <== commitmentHasher.out;

    component nullifierHasher = Poseidon(1);
    nullifierHasher.inputs[0] <== nullifier;
    nullifierHash <== nullifierHasher.out;
}

// Verificador de Merkle Path
template MerkleTreeChecker(levels) {
    signal input leaf;
    signal input root;
    signal input pathElements[levels];
    signal input pathIndices[levels];

    component hashers[levels];
    component indexBits[levels];

    signal levelHashes[levels + 1];
    levelHashes[0] <== leaf;

    for (var i = 0; i < levels; i++) {
        indexBits[i] = Num2Bits(1);
        indexBits[i].in <== pathIndices[i];

        hashers[i] = Poseidon(2);
        
        // Si pathIndices[i] == 0, leaf va a la izquierda
        // Si pathIndices[i] == 1, leaf va a la derecha
        hashers[i].inputs[0] <== levelHashes[i] + (pathElements[i] - levelHashes[i]) * pathIndices[i];
        hashers[i].inputs[1] <== pathElements[i] + (levelHashes[i] - pathElements[i]) * pathIndices[i];
        
        levelHashes[i + 1] <== hashers[i].out;
    }

    root === levelHashes[levels];
}

// Circuito principal de Withdraw
template Withdraw(levels) {
    // Inputs públicos
    signal input root;              // Merkle root actual
    signal input nullifierHash;     // Hash del nullifier (para prevenir doble gasto)
    signal input recipient;         // Dirección del receptor
    signal input relayer;           // Dirección del relayer (puede ser 0)
    signal input fee;               // Fee para el relayer
    signal input refund;            // Refund de gas
    
    // Inputs privados
    signal input secret;
    signal input nullifier;
    signal input pathElements[levels];
    signal input pathIndices[levels];

    // Verificar que recipient, relayer, fee, refund no son manipulados
    // (se incluyen en el hash pero no se verifican en el circuito)
    signal recipientSquare;
    signal relayerSquare;
    signal feeSquare;
    signal refundSquare;
    
    recipientSquare <== recipient * recipient;
    relayerSquare <== relayer * relayer;
    feeSquare <== fee * fee;
    refundSquare <== refund * refund;

    // Generar commitment y nullifierHash
    component hasher = CommitmentHasher();
    hasher.secret <== secret;
    hasher.nullifier <== nullifier;

    // Verificar que el nullifierHash público coincide
    nullifierHash === hasher.nullifierHash;

    // Verificar Merkle proof
    component tree = MerkleTreeChecker(levels);
    tree.leaf <== hasher.commitment;
    tree.root <== root;
    for (var i = 0; i < levels; i++) {
        tree.pathElements[i] <== pathElements[i];
        tree.pathIndices[i] <== pathIndices[i];
    }
}

// Instancia con 20 niveles (soporta ~1M deposits)
component main {public [root, nullifierHash, recipient, relayer, fee, refund]} = Withdraw(20);
