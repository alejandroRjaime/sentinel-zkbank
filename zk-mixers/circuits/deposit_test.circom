pragma circom 2.1.5;

include "../constants/constants.circom";
include "deposit.circom";

/*
 * Circuito principal de depósito para testing
 * Versión simplificada para benchmarking
 */
template MainDeposit() {
    // Señales públicas (inputs del verificador)
    signal input depositAmount;
    signal input tokenId;
    signal input oldRoot;
    signal input newRoot;
    signal input nonce;

    // Señales privadas
    signal input privateKey;
    signal input nullifierSeed;
    signal input currentBalance;
    signal input currentLeafIndex;
    signal input merklePath[MERKLE_TREE_HEIGHT];
    signal input merklePathIndices[MERKLE_TREE_HEIGHT];

    // Señales de salida
    signal output newBalance;
    signal output commitment;
    signal output nullifierHash;

    // Instanciar el circuito principal
    component deposit = DepositCircuit();

    // Conectar inputs públicos
    deposit.depositAmount <== depositAmount;
    deposit.tokenId <== tokenId;
    deposit.oldRoot <== oldRoot;
    deposit.newRoot <== newRoot;
    deposit.nonce <== nonce;

    // Conectar inputs privados
    deposit.privateKey <== privateKey;
    deposit.nullifierSeed <== nullifierSeed;
    deposit.currentBalance <== currentBalance;
    deposit.currentLeafIndex <== currentLeafIndex;

    for (var i = 0; i < MERKLE_TREE_HEIGHT; i++) {
        deposit.merklePath[i] <== merklePath[i];
        deposit.merklePathIndices[i] <== merklePathIndices[i];
    }

    // Conectar outputs
    newBalance <== deposit.newBalance;
    commitment <== deposit.commitment;
    nullifierHash <== deposit.nullifierHash;
}

/*
 * Versión para testing rápido (árbol más pequeño)
 */
template QuickDepositTest() {
    signal input depositAmount;
    signal input privateKey;
    signal input currentBalance;

    signal output newBalance;
    signal output hash;

    // Circuito simplificado para testing rápido
    component adder = SafeAdder(32);
    component hasher = PoseidonHash(2);

    // Verificar depósito positivo
    depositAmount > 0;
    depositAmount < 1000000;

    // Sumar balance
    adder.a <== currentBalance;
    adder.b <== depositAmount;
    newBalance <== adder.sum;
    adder.overflow === 0;

    // Calcular hash simple
    hasher.in[0] <== privateKey;
    hasher.in[1] <== newBalance;
    hash <== hasher.out;
}