pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "./selector.circom";

/**
 * ============================================
 * ZK-Sentinel: Dual-Logic Withdrawal Circuit
 * ============================================
 * 
 * INNOVATION: Computes BOTH real and decoy paths,
 * selects one via arithmetic (no branching).
 * 
 * WITNESS (private):
 *   - secret, nullifier_real, nullifier_decoy
 *   - pathElements[20], pathIndices[20]
 *   - panic_bit (0/1), ia_inference (0/1)
 * 
 * PUBLIC: root, recipient
 * OUTPUT: nullifierHash (indistinguishable)
 */

template CommitmentHasher() {
    signal input secret;
    signal input nullifier;
    signal output commitment;
    signal output nullifierHash;

    component commitHasher = Poseidon(2);
    commitHasher.inputs[0] <== secret;
    commitHasher.inputs[1] <== nullifier;
    commitment <== commitHasher.out;

    component nullHasher = Poseidon(1);
    nullHasher.inputs[0] <== nullifier;
    nullifierHash <== nullHasher.out;
}

template MerkleTreeChecker(levels) {
    signal input leaf;
    signal input root;
    signal input pathElements[levels];
    signal input pathIndices[levels];

    component hashers[levels];
    signal hashes[levels + 1];
    hashes[0] <== leaf;

    for (var i = 0; i < levels; i++) {
        pathIndices[i] * (pathIndices[i] - 1) === 0;
        
        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== hashes[i] + (pathElements[i] - hashes[i]) * pathIndices[i];
        hashers[i].inputs[1] <== pathElements[i] + (hashes[i] - pathElements[i]) * pathIndices[i];
        hashes[i + 1] <== hashers[i].out;
    }

    root === hashes[levels];
}

template WithdrawDual(levels) {
    // === PRIVATE INPUTS ===
    signal input secret;
    signal input nullifier_real;
    signal input nullifier_decoy;
    signal input pathElements[levels];
    signal input pathIndices[levels];
    signal input panic_bit;
    signal input ia_inference;
    
    // === PUBLIC INPUTS ===
    signal input root;
    signal input recipient;
    
    // === PUBLIC OUTPUT ===
    signal output nullifierHash;
    
    // === CONSTRAINTS ===
    
    // 1. Validate binary inputs
    panic_bit * (panic_bit - 1) === 0;
    ia_inference * (ia_inference - 1) === 0;
    
    // 2. Hash REAL nullifier
    component hashReal = Poseidon(1);
    hashReal.inputs[0] <== nullifier_real;
    
    // 3. Hash DECOY nullifier
    component hashDecoy = Poseidon(1);
    hashDecoy.inputs[0] <== nullifier_decoy;
    
    // 4. Coercion = panic_bit OR ia_inference
    component coercionOR = OR();
    coercionOR.a <== panic_bit;
    coercionOR.b <== ia_inference;
    
    // 5. SELECT output (arithmetic, no branching!)
    component selector = Selector();
    selector.in[0] <== hashReal.out;
    selector.in[1] <== hashDecoy.out;
    selector.sel <== coercionOR.out;
    
    nullifierHash <== selector.out;
    
    // 6. Verify Merkle proof for REAL commitment
    component commitHasher = CommitmentHasher();
    commitHasher.secret <== secret;
    commitHasher.nullifier <== nullifier_real;
    
    component merkle = MerkleTreeChecker(levels);
    merkle.leaf <== commitHasher.commitment;
    merkle.root <== root;
    for (var i = 0; i < levels; i++) {
        merkle.pathElements[i] <== pathElements[i];
        merkle.pathIndices[i] <== pathIndices[i];
    }
    
    // 7. Bind recipient
    signal recipientSq;
    recipientSq <== recipient * recipient;
}

component main {public [root, recipient]} = WithdrawDual(20);
