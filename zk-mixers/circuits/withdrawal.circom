// File: withdrawal.circom
pragma circom 2.1.5;

include "constants.circom";
include "./lib/merkle.circom";
include "./lib/hashes.circom";
include "./lib/utils.circom";

/*
 * Circuito de retiro con:
 * 1. Verificación de ownership
 * 2. Prevención de double spending
 * 3. Verificación de saldo suficiente
 * 4. Fee management
 * 5. Actualización de estado
 */
template WithdrawalCircuit() {
    // ========== INPUTS ==========
    // Privados
    signal input secret;              // Secreto del usuario
    signal input nullifierSeed;       // Semilla para nullifier
    signal input currentBalance;      // Balance actual
    signal input merklePath[MERKLE_TREE_HEIGHT];
    signal input merklePathIndices[MERKLE_TREE_HEIGHT];
    signal input leafIndex;           // Índice del leaf en el árbol

    // Públicos
    signal input withdrawalAmount;    // Cantidad a retirar
    signal input feeAmount;           // Fee para el operador
    signal input recipientAddress;    // Dirección del receptor
    signal input tokenId;             // ID del token
    signal input root;                // Raíz actual del árbol
    signal input nullifierHashes[2];  // Hashes de nullifiers previos (para double spending)
    signal input nonce;               // Nonce para replay protection

    // ========== OUTPUTS ==========
    signal output newBalance;         // Nuevo balance después del retiro
    signal output totalWithdrawn;     // Total retirado (amount + fee)
    signal output nullifierHash;      // Nullifier hash para prevenir reuso
    signal output commitment;         // Nuevo commitment (para balance 0 o actualizado)

    // ========== COMPONENTS ==========
    // Verificadores
    component rangeCheckAmount = RangeCheck(MAX_AMOUNT_BITS);
    component rangeCheckBalance = RangeCheck(MAX_BALANCE_BITS);
    component rangeCheckFee = RangeCheck(MAX_AMOUNT_BITS);

    // Componentes criptográficos
    component hashNullifier = PoseidonHash(3);
    component hashCommitment = PoseidonHash(6);
    component hashLeaf = PoseidonHash(3);

    // Verificador Merkle
    component merkleVerifier = SparseMerkleVerifier(MERKLE_TREE_HEIGHT);

    // Aritmética segura
    component balanceSubtractor = SafeSubtractor(MAX_BALANCE_BITS);
    component amountAdder = SafeAdder(MAX_AMOUNT_BITS);

    // Utilidades
    component feeVerifier = FeeVerifier();
    component doubleSpendChecker = DoubleSpendPrevention();

    // ========== VERIFICACIONES INICIALES ==========

    // 1. Verificar montos válidos
    withdrawalAmount === rangeCheckAmount.in;
    rangeCheckAmount.out === 1;

    feeAmount === rangeCheckFee.in;
    rangeCheckFee.out === 1;

    currentBalance === rangeCheckBalance.in;
    rangeCheckBalance.out === 1;

    // 2. Verificar que el retiro es positivo
    withdrawalAmount > 0;

    // 3. Verificar fee razonable (max 10%)
    feeAmount * 10 <= withdrawalAmount;

    // ========== CÁLCULO DE NULLIFIER ==========

    // 4. Generar nullifier hash (único para este retiro)
    hashNullifier.in[0] <== nullifierSeed;
    hashNullifier.in[1] <== secret;
    hashNullifier.in[2] <== nonce;
    nullifierHash <== hashNullifier.out;

    // 5. Prevenir double spending
    doubleSpendChecker.nullifierHash <== nullifierHash;
    doubleSpendChecker.registeredNullifiers[0] <== nullifierHashes[0];
    doubleSpendChecker.registeredNullifiers[1] <== nullifierHashes[1];
    doubleSpendChecker.isValid === 1;

    // ========== VERIFICACIÓN DE SALDO ==========

    // 6. Calcular total a deducir
    amountAdder.a <== withdrawalAmount;
    amountAdder.b <== feeAmount;
    totalWithdrawn <== amountAdder.sum;
    amountAdder.overflow === 0;

    // 7. Verificar que hay saldo suficiente
    balanceSubtractor.a <== currentBalance;
    balanceSubtractor.b <== totalWithdrawn;
    balanceSubtractor.underflow === 0;

    // 8. Calcular nuevo balance
    newBalance <== balanceSubtractor.difference;

    // 9. Verificar que el nuevo balance es no negativo
    newBalance >= 0;

    // ========== VERIFICACIÓN DE OWNERSHIP ==========

    // 10. Reconstruir leaf original
    component hashOldLeaf = PoseidonHash(3);
    hashOldLeaf.in[0] <== secret;
    hashOldLeaf.in[1] <== nullifierHash;
    hashOldLeaf.in[2] <== currentBalance;
    signal oldLeaf <== hashOldLeaf.out;

    // 11. Verificar que el leaf existe en el árbol
    merkleVerifier.root <== root;
    merkleVerifier.leaf <== oldLeaf;
    merkleVerifier.leafIndex <== leafIndex;

    for (var i = 0; i < MERKLE_TREE_HEIGHT; i++) {
        merkleVerifier.merklePath[i] <== merklePath[i];
        merkleVerifier.pathIndices[i] <== pathIndices[i];
    }

    merkleVerifier.isValid === 1;

    // ========== CREACIÓN DE NUEVO ESTADO ==========

    // 12. Si el nuevo balance es 0, no crear nuevo leaf
    // Si no es 0, crear nuevo leaf
    component hashNewLeaf = PoseidonHash(3);
    hashNewLeaf.in[0] <== secret;
    hashNewLeaf.in[1] <== nullifierHash;
    hashNewLeaf.in[2] <== newBalance;
    signal newLeaf <== hashNewLeaf.out;

    // 13. Crear commitment para la transacción
    hashCommitment.in[0] <== newLeaf;
    hashCommitment.in[1] <== tokenId;
    hashCommitment.in[2] <== leafIndex;
    hashCommitment.in[3] <== recipientAddress;
    hashCommitment.in[4] <== totalWithdrawn;
    hashCommitment.in[5] <== nonce;
    commitment <== hashCommitment.out;

    // ========== VERIFICACIONES FINALES ==========

    // 14. Verificar que el receptor no es la dirección cero
    recipientAddress !== 0;

    // 15. Verificar que el nonce es único (mayor que el anterior)
    nonce > 0;
}

/*
 * Prevención de double spending
 */
template DoubleSpendPrevention() {
    signal input nullifierHash;
    signal input registeredNullifiers[2];
    signal output isValid;

    // Verificar que el nullifier no ha sido usado antes
    signal isNotUsed1;
    signal isNotUsed2;

    isNotUsed1 <== (nullifierHash - registeredNullifiers[0]) !== 0 ? 1 : 0;
    isNotUsed2 <== (nullifierHash - registeredNullifiers[1]) !== 0 ? 1 : 0;

    // Ambos deben ser 1 (no iguales)
    isValid <== isNotUsed1 * isNotUsed2;
}

/*
 * Verificador de fees
 */
template FeeVerifier() {
    signal input amount;
    signal input fee;
    signal output isValid;

    // Fee mínimo: 0.1% del amount
    signal minFee <== amount / 1000;

    // Fee máximo: 10% del amount
    signal maxFee <== amount / 10;

    // Verificar que fee está en rango
    signal feeOk <== (fee >= minFee) && (fee <= maxFee);

    isValid <== feeOk;
}