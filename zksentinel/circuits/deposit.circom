pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";

/**
 * ZK-Sentinel: Deposit Circuit
 * 
 * Proves knowledge of (secret, nullifier) -> commitment
 */
template Deposit() {
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

component main = Deposit();
