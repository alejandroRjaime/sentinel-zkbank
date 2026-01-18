pragma circom 2.1.5;

include "../node_modules/circomlib/circuits/poseidon.circom";

/*
 * Wrappers optimizados para funciones hash
 */

// Hash Poseidon con número variable de inputs
template PoseidonHash(nInputs) {
    signal input in[nInputs];
    signal output out;

    component poseidon = Poseidon(nInputs);

    for (var i = 0; i < nInputs; i++) {
        poseidon.inputs[i] <== in[i];
    }

    out <== poseidon.out;
}

// Hash para commitments específicos del dominio
template CommitmentHash() {
    signal input secret;
    signal input nullifier;
    signal input balance;
    signal input extraData;

    signal output hash;

    component hasher = PoseidonHash(4);

    hasher.in[0] <== secret;
    hasher.in[1] <== nullifier;
    hasher.in[2] <== balance;
    hasher.in[3] <== extraData;

    hash <== hasher.out;
}

// Hash para nullifiers con protección contra colisiones
template NullifierHash() {
    signal input secret;
    signal input nullifierSeed;
    signal input nonce;

    signal output hash;

    component hasher = PoseidonHash(3);

    hasher.in[0] <== secret;
    hasher.in[1] <== nullifierSeed;
    hasher.in[2] <== nonce;

    hash <== hasher.out;
}

// Hash para proofs de inclusión
template InclusionProofHash() {
    signal input leaf;
    signal input index;
    signal input root;

    signal output hash;

    component hasher = PoseidonHash(3);

    hasher.in[0] <== leaf;
    hasher.in[1] <== index;
    hasher.in[2] <== root;

    hash <== hasher.out;
}