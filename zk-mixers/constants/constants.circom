pragma circom 2.1.5;

/*
 * CONSTANTES DEL SISTEMA PARA TESIS DE INVESTIGACIÓN
 * Valores optimizados para equilibrio entre seguridad y eficiencia
 */

// ========== PARÁMETROS DE SEGURIDAD ==========
const SECURITY_LEVEL = 128;  // Nivel de seguridad en bits

// ========== PARÁMETROS DE CAMPOS ==========
const FIELD_SIZE_BITS = 254;  // Tamaño del campo primo

// ========== PARÁMETROS DE BALANCE ==========
const MAX_BALANCE_BITS = 128;     // 2^128 ≈ 3.4e38 unidades
const MAX_AMOUNT_BITS = 64;       // 2^64 ≈ 1.84e19 unidades
const MIN_DEPOSIT_AMOUNT = 1000;  // Mínimo para evitar dust
const MAX_DEPOSIT_AMOUNT = 2**60; // Máximo por depósito

// ========== PARÁMETROS DE MERKLE TREE ==========
const MERKLE_TREE_HEIGHT = 32;    // Soporta 4,294,967,296 hojas
const MERKLE_ROOT_BITS = 256;     // Tamaño de la raíz

// ========== PARÁMETROS DE IDENTIFICADORES ==========
const TOKEN_ID_BITS = 32;         // Soporta 4,294,967,296 tokens
const NULLIFIER_SIZE_BITS = 256;  // Tamaño de nullifier
const COMMITMENT_SIZE_BITS = 256; // Tamaño de commitment

// ========== PARÁMETROS DE FEE ==========
const FEE_PRECISION = 10000;      // Precisión para fees (0.01%)
const MIN_FEE_PERCENT = 10;       // 0.1% mínimo
const MAX_FEE_PERCENT = 1000;     // 10% máximo

// ========== PARÁMETROS DE NONCE ==========
const NONCE_BITS = 64;            // Nonce de 64 bits
const MAX_NONCE = 2**64 - 1;

// ========== CONSTANTES DE HASH ==========
const POSEIDON_RATE = 2;
const POSEIDON_CAPACITY = 1;
const POSEIDON_ALPHA = 5;

// ========== CONSTANTES PARA TESTING ==========
const TEST_TREE_HEIGHT = 4;       // Para testing rápido
const TEST_MAX_BALANCE = 1000000; // Balance máximo de prueba

// ========== CONSTANTES DE OPTIMIZACIÓN ==========
const USE_LOOKUP_TABLES = 1;      // Usar lookup tables para rangos
const OPTIMIZE_POSEIDON = 1;      // Optimizar instancias de Poseidon

/*
 * Funciones auxiliares para cálculos con constantes
 */
function CalculateMaxUsers() {
    return 2**MERKLE_TREE_HEIGHT;
}

function CalculateMaxTotalValue() {
    return (2**MAX_BALANCE_BITS) * (2**TOKEN_ID_BITS);
}

function CalculateFee(minAmount, maxAmount) {
    return (minAmount * FEE_PRECISION) / maxAmount;
}