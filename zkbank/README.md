# 🏦 ZK Bank - Privacy Pool with Coercion Resistance

**Autor:** Alejandro Jaime (Tesis Doctoral UNLP)  
**Director:** Dr. Marcelo Errecalde

Sistema de privacidad financiera basado en zk-SNARKs que aborda el problema del "$5 wrench attack": la criptografía es inútil bajo coerción física.

## 🎯 Problema

```
Atacante: "Dame tu clave privada o te rompo las rodillas"
Víctima: "..." 
         
La criptografía más fuerte del mundo es inútil 
si te pueden torturar para revelar la clave.
```

## 💡 Solución: 7 Capas de Defensa

```
┌─────────────────────────────────────────────────────────────┐
│                    ZK BANK ARCHITECTURE                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   Capa 1: Commitment (secret + nullifier)                   │
│           └─ Prueba de conocimiento sin revelar datos       │
│                                                             │
│   Capa 2: PIN de Coerción (duress_key)                      │
│           └─ PIN alternativo que activa modo señuelo        │
│                                                             │
│   Capa 3: Billetera Señuelo (decoy_wallet)                  │
│           └─ Muestra fondos falsos bajo coerción            │
│                                                             │
│   Capa 4: Patrón Temporal (time_pattern)                    │
│           └─ Detecta retiros en horarios inusuales          │
│                                                             │
│   Capa 5: Delay de Seguridad (withdrawal_delay)             │
│           └─ Tiempo para cancelar si hay anomalía           │
│                                                             │
│   Capa 6: IA Off-chain (behavior_analysis)                  │
│           └─ Análisis de patrones de comportamiento         │
│                                                             │
│   Capa 7: Merkle Tree con Historial                         │
│           └─ Anonimato en el conjunto de depósitos          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## 📁 Estructura del Proyecto

```
zkbank/
├── circuits/
│   └── withdraw.circom       # Circuito zk-SNARK
├── contracts/
│   ├── ZKBank.sol           # Pool de privacidad base
│   ├── ZKBankWithCoercionResistance.sol  # Extensión anti-coerción
│   ├── MerkleTreeWithHistory.sol         # Merkle tree
│   ├── Hasher.sol                        # Poseidon hash
│   └── interfaces/
│       └── IVerifier.sol    # Interface del verificador
├── test/
│   └── ZKBank.t.sol         # Tests Foundry
├── sdk/
│   └── zkbank_client.py     # SDK Python
├── scripts/
│   └── deploy.s.sol         # Script de deployment
└── foundry.toml
```

## 🚀 Instalación

### Requisitos

- [Foundry](https://getfoundry.sh/)
- [Circom](https://docs.circom.io/getting-started/installation/)
- [Node.js](https://nodejs.org/) (para snarkjs)
- Python 3.10+ (para SDK)

### Setup

```bash
# 1. Clonar e instalar dependencias
cd zkbank
forge install OpenZeppelin/openzeppelin-contracts
forge install iden3/circomlib

# 2. Compilar contratos
forge build

# 3. Compilar circuito Circom
cd circuits
circom withdraw.circom --r1cs --wasm --sym

# 4. Trusted setup (usar ceremonia real en producción)
snarkjs groth16 setup withdraw.r1cs pot12_final.ptau withdraw_0000.zkey
snarkjs zkey contribute withdraw_0000.zkey withdraw_final.zkey
snarkjs zkey export verificationkey withdraw_final.zkey verification_key.json
snarkjs zkey export solidityverifier withdraw_final.zkey ../contracts/Verifier.sol

# 5. Tests
cd ..
forge test -vvv
```

## 📖 Uso

### 1. Generar Commitment

```python
from sdk.zkbank_client import ZKBankClient

client = ZKBankClient(
    rpc_url="http://127.0.0.1:8545",
    zkbank_address="0x...",
    private_key="0x..."
)

# Generar nuevo commitment
commitment = client.generate_commitment()
client.save_commitment(commitment, "my_commitment.json")
```

### 2. Depositar

```python
tx_hash = client.deposit(commitment)
print(f"Deposit: {tx_hash}")
```

### 3. Configurar Protección Anti-Coerción

```python
from sdk.zkbank_client import CoercionConfig

config = CoercionConfig(
    duress_key=b"mi_pin_de_panico_1234",
    decoy_wallet="0x...",  # Billetera señuelo
    decoy_balance=0.1 * 10**18,  # 0.1 ETH falsos
    expected_hour_min=9,   # Solo retiros entre 9 AM
    expected_hour_max=17,  # y 5 PM
    withdrawal_delay_hours=24  # 24h de delay si hay anomalía
)

client.configure_coercion(commitment, config)
```

### 4. Retirar

```python
# Retiro normal
proof = client.generate_proof(
    commitment=commitment,
    merkle_path=merkle_path,
    merkle_indices=merkle_indices,
    recipient="0x..."
)
tx_hash = client.withdraw(proof)

# ⚠️ Si estás bajo coerción, usa el duress_key
# El atacante recibirá los fondos señuelo y creerá que funcionó
```

## 🧪 Tests

```bash
# Todos los tests
forge test -vvv

# Tests específicos
forge test --match-test test_CoercionDetection -vvv

# Coverage
forge coverage
```

### Tests Incluidos

- ✅ Deposit básico
- ✅ Retiro con prueba válida
- ✅ Rechazo de doble gasto
- ✅ Detección de clave de coerción
- ✅ Detección de horario inusual
- ✅ Delay de seguridad
- ✅ Cancelación de retiro pendiente

## 📊 Métricas

| Métrica | Valor |
|---------|-------|
| Tiempo de prueba | < 5 segundos |
| Gas deposit | ~150,000 |
| Gas withdraw | ~300,000 |
| Tamaño circuito | 20 niveles (~1M deposits) |
| Anonymity set | Todos los depositantes |

## 🔒 Seguridad

### Consideraciones

1. **Trusted Setup**: Usar ceremonia multi-party (Powers of Tau)
2. **Duress Key**: Memorizar, no guardar digitalmente
3. **Commitment File**: Proteger con encryption + backup offline
4. **Time Patterns**: Configurar según tu rutina real

### Auditorías

- [ ] Audit interno con SENTINEL
- [ ] Audit externo (pendiente)

## 📚 Referencias

- [Tornado Cash](https://tornado.cash/) - Inspiración del mixer
- [Circom](https://docs.circom.io/) - Lenguaje de circuitos
- [snarkjs](https://github.com/iden3/snarkjs) - Librería zk-SNARK
- [Semaphore](https://semaphore.appliedzkp.org/) - Identidad ZK

## 📄 Licencia

MIT

---

**Parte de la Tesis Doctoral:**  
"Aplicaciones de IA Generativa en Arquitecturas Distribuidas para Procesamiento Masivo y Análisis Clínico"  
Universidad Nacional de La Plata (UNLP)
