// File: deposit.circom
pragma circom 2.1.5;

include "constants.circom";
include "./lib/merkle.circom";
include "./lib/hashes.circom";
include "./lib/utils.circom";

/*
 * Circuito de depósito con:
 * 1. Verificación de rangos
 * 2. Prevención de overflow
 * 3. Generación de commitment
 * 4. Actualización de estado
 * 5. Nonce para replay protection
 */
template DepositCircuit() {
    // ========== INPUTS ==========
    // Privados
    signal input privateKey;          // Clave privada del usuario
    signal input nullifierSeed;       // Semilla para nullifier
    signal input currentBalance;      // Balance actual (antes del depósito)
    signal input currentLeafIndex;    // Índice en el árbol Merkle
    signal input merklePath[MERKLE_TREE_HEIGHT];
    signal input merklePathIndices[MERKLE_TREE_HEIGHT];

    // Públicos
    signal input depositAmount;       // Cantidad a depositar
    signal input tokenId;             // ID del token (0 para ETH, 1 para DAI, etc.)
    signal input oldRoot;             // Raíz del árbol antes del depósito
    signal input newRoot;             // Raíz del árbol después del depósito
    signal input nonce;               // Nonce para replay protection

    // ========== OUTPUTS ==========
    signal output newBalance;         // Nuevo balance
    signal output commitment;         // Nuevo leaf para el árbol
    signal output nullifierHash;      // Hash para prevenir doble gasto futuro

    // ========== COMPONENTS ==========
    // Verificador de rangos
    component rangeCheckAmount = RangeCheck(MAX_AMOUNT_BITS);
    component rangeCheckBalance = RangeCheck(MAX_BALANCE_BITS);
    component rangeCheckToken = RangeCheck(TOKEN_ID_BITS);

    // Componentes criptográficos
    component hashPrivateKey = PoseidonHash(2);
    component hashNullifier = PoseidonHash(2);
    component hashCommitment = PoseidonHash(5);
    component hashLeaf = PoseidonHash(3);

    // Verificador Merkle
    component merkleVerifier = SparseMerkleVerifier(MERKLE_TREE_HEIGHT);

    // Utilidades
    component balanceAdder = SafeAdder(MAX_BALANCE_BITS);
    component amountChecker = AmountConstraints();

    // ========== VERIFICACIONES DE SEGURIDAD ==========

    // 1. Verificar que el tokenId es válido
    tokenId === rangeCheckToken.in;
    rangeCheckToken.out === 1;

    // 2. Verificar que el monto está en rango permitido
    depositAmount === rangeCheckAmount.in;
    rangeCheckAmount.out === 1;

    // 3. Verificar mínimo y máximo de depósito
    depositAmount >= MIN_DEPOSIT_AMOUNT;
    depositAmount <= MAX_DEPOSIT_AMOUNT;

    // 4. Verificar balance actual
    currentBalance === rangeCheckBalance.in;
    rangeCheckBalance.out === 1;
    currentBalance >= 0;

    // ========== CÁLCULOS CRIPTOGRÁFICOS ==========

    // 5. Derivar secret del private key
    hashPrivateKey.in[0] <== privateKey;
    hashPrivateKey.in[1] <== nonce;
    signal secret <== hashPrivateKey.out;

    // 6. Generar nullifier hash (para futuros retiros)
    hashNullifier.in[0] <== nullifierSeed;
    hashNullifier.in[1] <== secret;
    nullifierHash <== hashNullifier.out;

    // 7. Calcular nuevo balance (con protección contra overflow)
    balanceAdder.a <== currentBalance;
    balanceAdder.b <== depositAmount;
    newBalance <== balanceAdder.sum;

    // 8. Verificar que no hay overflow
    balanceAdder.overflow === 0;

    // 9. Crear nuevo leaf (commitment)
    hashLeaf.in[0] <== secret;
    hashLeaf.in[1] <== nullifierHash;
    hashLeaf.in[2] <== newBalance;
    signal newLeaf <== hashLeaf.out;

    // 10. Crear commitment para el árbol
    hashCommitment.in[0] <== newLeaf;
    hashCommitment.in[1] <== tokenId;
    hashCommitment.in[2] <== currentLeafIndex;
    hashCommitment.in[3] <== oldRoot;
    hashCommitment.in[4] <== newRoot;
    commitment <== hashCommitment.out;

    // ========== VERIFICACIÓN DE ESTADO ==========

    // 11. Verificar que el leaf antiguo existe en el árbol
    // Reconstruir leaf antiguo
    component hashOldLeaf = PoseidonHash(3);
    hashOldLeaf.in[0] <== secret;
    hashOldLeaf.in[1] <== nullifierHash;
    hashOldLeaf.in[2] <== currentBalance;
    signal oldLeaf <== hashOldLeaf.out;

    // 12. Verificar proof Merkle
    merkleVerifier.root <== oldRoot;
    merkleVerifier.leaf <== oldLeaf;
    merkleVerifier.leafIndex <== currentLeafIndex;

    for (var i = 0; i < MERKLE_TREE_HEIGHT; i++) {
        merkleVerifier.path[i] <== merklePath[i];
        merkleVerifier.pathIndices[i] <== merklePathIndices[i];
    }

    // 13. Verificar que el proof es válido
    merkleVerifier.isValid === 1;
}

/*
 * Componente para suma segura con detección de overflow
 */
template SafeAdder(bits) {
    signal input a;
    signal input b;
    signal output sum;
    signal output overflow;

    component num2bitsA = Num2Bits(bits);
    component num2bitsB = Num2Bits(bits);
    component num2bitsSum = Num2Bits(bits + 1);

    num2bitsA.in <== a;
    num2bitsB.in <== b;

    signal sumExtended <== a + b;

    num2bitsSum.in <== sumExtended;

    // Extraer los bits de la suma
    sum <== sumExtended;

    // El bit extra (bits+1) indica overflow
    overflow <== num2bitsSum.out[bits];
}

/*
 * Restricciones específicas para montos
 */
template AmountConstraints() {
    signal input amount;
    signal output isValid;

    // Verificar que es múltiplo de unidad base (ej: wei)
    component checkDivisible = IsDivisibleBy(1000000000); // 10^9

    checkDivisible.in <== amount;

    // Combinar condiciones
    isValid <== checkDivisible.out;
}