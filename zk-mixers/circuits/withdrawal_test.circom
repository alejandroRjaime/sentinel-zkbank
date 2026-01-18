pragma circom 2.1.5;

include "../constants/constants.circom";
include "withdrawal.circom";

/*
 * Circuito principal de retiro para testing
 */
template MainWithdrawal() {
    // Señales públicas
    signal input withdrawalAmount;
    signal input feeAmount;
    signal input recipientAddress;
    signal input tokenId;
    signal input root;
    signal input nullifierHashes[2];
    signal input nonce;

    // Señales privadas
    signal input secret;
    signal input nullifierSeed;
    signal input currentBalance;
    signal input merklePath[MERKLE_TREE_HEIGHT];
    signal input merklePathIndices[MERKLE_TREE_HEIGHT];
    signal input leafIndex;

    // Señales de salida
    signal output newBalance;
    signal output totalWithdrawn;
    signal output nullifierHash;
    signal output commitment;

    // Instanciar circuito principal
    component withdrawal = WithdrawalCircuit();

    // Conectar inputs públicos
    withdrawal.withdrawalAmount <== withdrawalAmount;
    withdrawal.feeAmount <== feeAmount;
    withdrawal.recipientAddress <== recipientAddress;
    withdrawal.tokenId <== tokenId;
    withdrawal.root <== root;
    withdrawal.nullifierHashes[0] <== nullifierHashes[0];
    withdrawal.nullifierHashes[1] <== nullifierHashes[1];
    withdrawal.nonce <== nonce;

    // Conectar inputs privados
    withdrawal.secret <== secret;
    withdrawal.nullifierSeed <== nullifierSeed;
    withdrawal.currentBalance <== currentBalance;
    withdrawal.leafIndex <== leafIndex;

    for (var i = 0; i < MERKLE_TREE_HEIGHT; i++) {
        withdrawal.merklePath[i] <== merklePath[i];
        withdrawal.merklePathIndices[i] <== merklePathIndices[i];
    }

    // Conectar outputs
    newBalance <== withdrawal.newBalance;
    totalWithdrawn <== withdrawal.totalWithdrawn;
    nullifierHash <== withdrawal.nullifierHash;
    commitment <== withdrawal.commitment;
}

/*
 * Versión simplificada para testing rápido
 */
template QuickWithdrawalTest() {
    signal input withdrawalAmount;
    signal input currentBalance;
    signal input secret;

    signal output newBalance;
    signal output isValid;

    // Verificaciones básicas
    withdrawalAmount > 0;
    withdrawalAmount <= currentBalance;

    // Calcular nuevo balance
    newBalance <== currentBalance - withdrawalAmount;

    // Verificar que no es negativo
    signal isPositive <== newBalance >= 0 ? 1 : 0;

    // Verificar secreto no es cero
    signal secretValid <== secret != 0 ? 1 : 0;

    isValid <== isPositive * secretValid;
}