# Contratos Verificadores para Sistema Bancario ZK

## Descripción
Contratos Solidity para verificación on-chain de pruebas ZK-SNARK generadas por los circuitos Circom.

## Estructura

### 1. VerifierDeposit.sol
- **Protocolo**: Groth16
- **Optimización**: Gas efficiency para operaciones frecuentes
- **Características**:
  - Prevención de double spending con nullifiers
  - Rate limiting por bloque
  - Fee management
  - Emergency stops

### 2. VerifierWithdrawal.sol
- **Protocolo**: PLONK
- **Optimización**: Batch verification y cooldown
- **Características**:
  - Verificación por lotes (batch)
  - Límites diarios por token
  - Cooldown por usuario
  - Treasury de fees

### 3. IVerifier.sol
- Interfaz estándar para todos los verificadores
- Define eventos y funciones comunes
- Facilita la interoperabilidad

### 4. MockVerifier.sol
- Para testing y desarrollo
- Implementación controlada
- Útil para integrar con frontends

## Deployment

### Requisitos
- Solidity ^0.8.17
- Compilador optimizado para gas
- Testnets: Goerli, Sepolia
- Mainnet: Ethereum

### Pasos
1. Compilar circuitos con snarkjs
2. Generar verificadores con `snarkjs zkey export solidityverifier`
3. Deployar contratos
4. Configurar administradores y parámetros
5. Realizar pruebas exhaustivas

## Seguridad

### Consideraciones
1. **Trusted Setup**: Ceremonia multi-partita requerida
2. **Administración**: Multi-sig para funciones críticas
3. **Upgradeability**: Considerar proxies para actualizaciones
4. **Monitoring**: Eventos para auditoría

### Auditorías Recomendadas
- Análisis estático (Slither, MythX)
- Auditoría manual por expertos en ZK
- Bug bounty program

## Integración

### Frontend
```javascript
// Ejemplo de integración con ethers.js
const verifier = new ethers.Contract(
  verifierAddress,
  VerifierDeposit.abi,
  provider
);

const proof = await generateProof(circuitInputs);
const isValid = await verifier.verifyDeposit(proof, inputs, nullifierHash);