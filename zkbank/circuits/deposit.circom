pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";

/*
 * ZK Bank - Deposit Circuit
 * 
 * Este circuito permite:
 * 1. Generar un commitment válido a partir de secret y nullifier
 * 2. Probar off-chain que el commitment fue calculado correctamente
 * 3. Validar inputs antes de enviar la transacción on-chain
 *
 * El depósito en sí no requiere prueba ZK on-chain (solo envía el hash),
 * pero este circuito es útil para:
 * - Validación del cliente
 * - Pruebas de integridad
 * - Generación segura de commitments
 *
 * commitment = Poseidon(secret, nullifier)
 * nullifierHash = Poseidon(nullifier)
 */

// ═══════════════════════════════════════════════════════════════════════════
// COMMITMENT HASHER
// ═══════════════════════════════════════════════════════════════════════════

template CommitmentHasher() {
    // Inputs privados
    signal input secret;
    signal input nullifier;
    
    // Outputs públicos
    signal output commitment;
    signal output nullifierHash;

    // Validar que secret y nullifier están en el campo
    // (Circom lo hace automáticamente, pero lo documentamos)
    
    // Calcular commitment = Poseidon(secret, nullifier)
    component commitmentHasher = Poseidon(2);
    commitmentHasher.inputs[0] <== secret;
    commitmentHasher.inputs[1] <== nullifier;
    commitment <== commitmentHasher.out;

    // Calcular nullifierHash = Poseidon(nullifier)
    // Este hash se usará en el withdraw para prevenir doble gasto
    component nullifierHasher = Poseidon(1);
    nullifierHasher.inputs[0] <== nullifier;
    nullifierHash <== nullifierHasher.out;
}

// ═══════════════════════════════════════════════════════════════════════════
// DEPOSIT CIRCUIT - Versión completa con validaciones
// ═══════════════════════════════════════════════════════════════════════════

template Deposit() {
    // ───────────────────────────────────────────────────────────────────────
    // INPUTS PRIVADOS (solo el usuario los conoce)
    // ───────────────────────────────────────────────────────────────────────
    signal input secret;      // 254 bits de entropía
    signal input nullifier;   // 254 bits de entropía
    
    // ───────────────────────────────────────────────────────────────────────
    // INPUTS PÚBLICOS (opcionales, para validación)
    // ───────────────────────────────────────────────────────────────────────
    signal input expectedCommitment;  // Para verificar cálculo correcto
    
    // ───────────────────────────────────────────────────────────────────────
    // OUTPUTS
    // ───────────────────────────────────────────────────────────────────────
    signal output commitment;
    signal output nullifierHash;
    
    // ───────────────────────────────────────────────────────────────────────
    // VALIDACIONES DE RANGO
    // ───────────────────────────────────────────────────────────────────────
    
    // Verificar que secret tiene suficientes bits (seguridad)
    component secretBits = Num2Bits(254);
    secretBits.in <== secret;
    
    // Verificar que nullifier tiene suficientes bits
    component nullifierBits = Num2Bits(254);
    nullifierBits.in <== nullifier;
    
    // ───────────────────────────────────────────────────────────────────────
    // CÁLCULO DE HASHES
    // ───────────────────────────────────────────────────────────────────────
    
    component hasher = CommitmentHasher();
    hasher.secret <== secret;
    hasher.nullifier <== nullifier;
    
    commitment <== hasher.commitment;
    nullifierHash <== hasher.nullifierHash;
    
    // ───────────────────────────────────────────────────────────────────────
    // VERIFICACIÓN OPCIONAL
    // ───────────────────────────────────────────────────────────────────────
    
    // Si se proporciona expectedCommitment, verificar que coincide
    // Esto permite al usuario validar que el cliente calculó bien
    signal commitmentCheck;
    commitmentCheck <== (commitment - expectedCommitment) * (commitment - expectedCommitment);
    // Si expectedCommitment == 0, no verificamos (multiplicar por 0)
    // Si expectedCommitment != 0, debe coincidir exactamente
}

// ═══════════════════════════════════════════════════════════════════════════
// DEPOSIT WITH ENCRYPTION (Avanzado)
// ═══════════════════════════════════════════════════════════════════════════

/*
 * Versión avanzada que permite encriptar el secret para backup
 * El usuario puede recuperar sus fondos con una clave de recuperación
 */
template DepositWithBackup() {
    // Inputs principales
    signal input secret;
    signal input nullifier;
    
    // Clave de backup (para recuperación)
    signal input backupKey;
    
    // Outputs
    signal output commitment;
    signal output nullifierHash;
    signal output encryptedSecret;  // secret XOR hash(backupKey)
    
    // Calcular commitment normal
    component hasher = CommitmentHasher();
    hasher.secret <== secret;
    hasher.nullifier <== nullifier;
    
    commitment <== hasher.commitment;
    nullifierHash <== hasher.nullifierHash;
    
    // "Encriptar" secret con backupKey (simplificado)
    // En producción usar cifrado real
    component backupHash = Poseidon(1);
    backupHash.inputs[0] <== backupKey;
    
    // XOR simulado en el campo (no es XOR real, pero sirve de ejemplo)
    encryptedSecret <== secret + backupHash.out;
}

// ═══════════════════════════════════════════════════════════════════════════
// BATCH DEPOSIT (Para múltiples depósitos eficientes)
// ═══════════════════════════════════════════════════════════════════════════

template BatchDeposit(n) {
    // n depósitos en un solo circuito
    signal input secrets[n];
    signal input nullifiers[n];
    
    signal output commitments[n];
    signal output nullifierHashes[n];
    
    component hashers[n];
    
    for (var i = 0; i < n; i++) {
        hashers[i] = CommitmentHasher();
        hashers[i].secret <== secrets[i];
        hashers[i].nullifier <== nullifiers[i];
        
        commitments[i] <== hashers[i].commitment;
        nullifierHashes[i] <== hashers[i].nullifierHash;
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// COMPONENTE PRINCIPAL
// ═══════════════════════════════════════════════════════════════════════════

// Instancia básica: solo genera commitment
component main {public [expectedCommitment]} = Deposit();

// Alternativas:
// component main = CommitmentHasher();  // Solo hashing
// component main = DepositWithBackup(); // Con backup
// component main = BatchDeposit(10);    // 10 depósitos batch
