"""
ZK Bank SDK - Python Client for Privacy Pool with Coercion Resistance

Este SDK permite:
1. Generar commitments (secret + nullifier)
2. Generar proofs zk-SNARK para retiros
3. Configurar resistencia a coerción
4. Interactuar con el contrato

Autor: Alejandro Jaime (Tesis Doctoral UNLP)
"""

import os
import json
import hashlib
import secrets
import subprocess
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, Tuple, List
from web3 import Web3
from eth_account import Account

# ═══════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════

FIELD_SIZE = 21888242871839275222246405745257275088548364400416034343698204186575808495617
MERKLE_HEIGHT = 20

# ═══════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class Commitment:
    """Representa un commitment en ZK Bank"""
    secret: int
    nullifier: int
    commitment_hash: bytes
    nullifier_hash: bytes
    
    def to_dict(self) -> dict:
        return {
            'secret': hex(self.secret),
            'nullifier': hex(self.nullifier),
            'commitment_hash': self.commitment_hash.hex(),
            'nullifier_hash': self.nullifier_hash.hex()
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'Commitment':
        return cls(
            secret=int(data['secret'], 16),
            nullifier=int(data['nullifier'], 16),
            commitment_hash=bytes.fromhex(data['commitment_hash']),
            nullifier_hash=bytes.fromhex(data['nullifier_hash'])
        )


@dataclass
class CoercionConfig:
    """Configuración de resistencia a coerción"""
    duress_key: bytes  # Clave que activa modo coerción
    decoy_wallet: str  # Dirección de billetera señuelo
    decoy_balance: int  # Balance a mostrar bajo coerción
    expected_hour_min: int  # Hora mínima esperada (0-23)
    expected_hour_max: int  # Hora máxima esperada (0-23)
    withdrawal_delay_hours: int  # Delay si se detecta anomalía


@dataclass
class WithdrawProof:
    """Prueba zk-SNARK para retiro"""
    proof: bytes  # Proof serializado (a, b, c)
    root: bytes
    nullifier_hash: bytes
    recipient: str
    relayer: str
    fee: int
    refund: int


# ═══════════════════════════════════════════════════════════════════════════
# POSEIDON HASH (Simplified - usar circomlibjs en producción)
# ═══════════════════════════════════════════════════════════════════════════

def poseidon_hash(inputs: List[int]) -> int:
    """
    Poseidon hash simplificado.
    NOTA: En producción usar py_ecc o circomlibjs
    """
    # Esta es una aproximación - usar implementación real
    combined = b''.join(i.to_bytes(32, 'big') for i in inputs)
    h = hashlib.sha256(combined).digest()
    return int.from_bytes(h, 'big') % FIELD_SIZE


# ═══════════════════════════════════════════════════════════════════════════
# ZK BANK CLIENT
# ═══════════════════════════════════════════════════════════════════════════

class ZKBankClient:
    """Cliente para interactuar con ZK Bank"""
    
    def __init__(
        self,
        rpc_url: str,
        zkbank_address: str,
        private_key: Optional[str] = None,
        circuit_dir: Optional[Path] = None
    ):
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        self.zkbank_address = Web3.to_checksum_address(zkbank_address)
        self.private_key = private_key
        self.circuit_dir = circuit_dir or Path(__file__).parent.parent / 'circuits'
        
        # Cargar ABI (simplificado)
        self.abi = self._load_abi()
        self.contract = self.w3.eth.contract(
            address=self.zkbank_address,
            abi=self.abi
        )
        
        if private_key:
            self.account = Account.from_key(private_key)
        else:
            self.account = None
    
    def _load_abi(self) -> list:
        """Carga el ABI del contrato"""
        abi_path = Path(__file__).parent.parent / 'out' / 'ZKBank.sol' / 'ZKBank.json'
        if abi_path.exists():
            with open(abi_path) as f:
                return json.load(f)['abi']
        # ABI mínimo si no existe el compilado
        return [
            {"inputs": [{"name": "_commitment", "type": "bytes32"}], "name": "deposit", "outputs": [], "stateMutability": "payable", "type": "function"},
            {"inputs": [{"name": "_proof", "type": "bytes"}, {"name": "_root", "type": "bytes32"}, {"name": "_nullifierHash", "type": "bytes32"}, {"name": "_recipient", "type": "address"}, {"name": "_relayer", "type": "address"}, {"name": "_fee", "type": "uint256"}, {"name": "_refund", "type": "uint256"}], "name": "withdraw", "outputs": [], "stateMutability": "payable", "type": "function"},
            {"inputs": [], "name": "denomination", "outputs": [{"type": "uint256"}], "stateMutability": "view", "type": "function"},
            {"inputs": [], "name": "getLastRoot", "outputs": [{"type": "bytes32"}], "stateMutability": "view", "type": "function"},
            {"inputs": [{"name": "_nullifierHash", "type": "bytes32"}], "name": "isSpent", "outputs": [{"type": "bool"}], "stateMutability": "view", "type": "function"},
        ]
    
    # ═══════════════════════════════════════════════════════════════════════
    # COMMITMENT GENERATION
    # ═══════════════════════════════════════════════════════════════════════
    
    def generate_commitment(self) -> Commitment:
        """Genera un nuevo commitment aleatorio"""
        secret = secrets.randbelow(FIELD_SIZE)
        nullifier = secrets.randbelow(FIELD_SIZE)
        
        commitment_hash = poseidon_hash([secret, nullifier])
        nullifier_hash = poseidon_hash([nullifier])
        
        return Commitment(
            secret=secret,
            nullifier=nullifier,
            commitment_hash=commitment_hash.to_bytes(32, 'big'),
            nullifier_hash=nullifier_hash.to_bytes(32, 'big')
        )
    
    def save_commitment(self, commitment: Commitment, filepath: Path) -> None:
        """Guarda un commitment en un archivo (PROTEGER ESTE ARCHIVO!)"""
        with open(filepath, 'w') as f:
            json.dump(commitment.to_dict(), f, indent=2)
        # Permisos restrictivos
        os.chmod(filepath, 0o600)
    
    def load_commitment(self, filepath: Path) -> Commitment:
        """Carga un commitment desde archivo"""
        with open(filepath) as f:
            return Commitment.from_dict(json.load(f))
    
    # ═══════════════════════════════════════════════════════════════════════
    # DEPOSIT
    # ═══════════════════════════════════════════════════════════════════════
    
    def deposit(self, commitment: Commitment) -> str:
        """Deposita ETH en el pool"""
        if not self.account:
            raise ValueError("Private key required for transactions")
        
        denomination = self.contract.functions.denomination().call()
        
        tx = self.contract.functions.deposit(
            commitment.commitment_hash
        ).build_transaction({
            'from': self.account.address,
            'value': denomination,
            'gas': 500000,
            'gasPrice': self.w3.eth.gas_price,
            'nonce': self.w3.eth.get_transaction_count(self.account.address)
        })
        
        signed = self.account.sign_transaction(tx)
        tx_hash = self.w3.eth.send_raw_transaction(signed.rawTransaction)
        
        return tx_hash.hex()
    
    # ═══════════════════════════════════════════════════════════════════════
    # PROOF GENERATION
    # ═══════════════════════════════════════════════════════════════════════
    
    def generate_proof(
        self,
        commitment: Commitment,
        merkle_path: List[bytes],
        merkle_indices: List[int],
        recipient: str,
        relayer: str = None,
        fee: int = 0,
        refund: int = 0
    ) -> WithdrawProof:
        """
        Genera una prueba zk-SNARK para retiro.
        
        Requiere:
        - snarkjs instalado
        - Circuito compilado (withdraw.wasm, withdraw_final.zkey)
        """
        root = self.contract.functions.getLastRoot().call()
        
        # Crear input para el circuito
        circuit_input = {
            'root': int.from_bytes(root, 'big'),
            'nullifierHash': int.from_bytes(commitment.nullifier_hash, 'big'),
            'recipient': int(recipient, 16) if recipient.startswith('0x') else int(recipient),
            'relayer': int(relayer, 16) if relayer and relayer.startswith('0x') else 0,
            'fee': fee,
            'refund': refund,
            'secret': commitment.secret,
            'nullifier': commitment.nullifier,
            'pathElements': [int.from_bytes(p, 'big') for p in merkle_path],
            'pathIndices': merkle_indices
        }
        
        # Guardar input
        input_path = self.circuit_dir / 'input.json'
        with open(input_path, 'w') as f:
            json.dump(circuit_input, f)
        
        # Generar witness
        witness_path = self.circuit_dir / 'witness.wtns'
        wasm_path = self.circuit_dir / 'withdraw_js' / 'withdraw.wasm'
        
        subprocess.run([
            'node',
            str(self.circuit_dir / 'withdraw_js' / 'generate_witness.js'),
            str(wasm_path),
            str(input_path),
            str(witness_path)
        ], check=True)
        
        # Generar proof
        proof_path = self.circuit_dir / 'proof.json'
        public_path = self.circuit_dir / 'public.json'
        zkey_path = self.circuit_dir / 'withdraw_final.zkey'
        
        subprocess.run([
            'snarkjs', 'groth16', 'prove',
            str(zkey_path),
            str(witness_path),
            str(proof_path),
            str(public_path)
        ], check=True)
        
        # Leer proof
        with open(proof_path) as f:
            proof_data = json.load(f)
        
        # Serializar para el contrato
        proof_bytes = self._serialize_proof(proof_data)
        
        return WithdrawProof(
            proof=proof_bytes,
            root=root,
            nullifier_hash=commitment.nullifier_hash,
            recipient=recipient,
            relayer=relayer or '0x' + '00' * 20,
            fee=fee,
            refund=refund
        )
    
    def _serialize_proof(self, proof_data: dict) -> bytes:
        """Serializa proof Groth16 para el contrato"""
        # Formato: [a0, a1, b00, b01, b10, b11, c0, c1]
        proof = [
            int(proof_data['pi_a'][0]),
            int(proof_data['pi_a'][1]),
            int(proof_data['pi_b'][0][0]),
            int(proof_data['pi_b'][0][1]),
            int(proof_data['pi_b'][1][0]),
            int(proof_data['pi_b'][1][1]),
            int(proof_data['pi_c'][0]),
            int(proof_data['pi_c'][1]),
        ]
        
        return b''.join(p.to_bytes(32, 'big') for p in proof)
    
    # ═══════════════════════════════════════════════════════════════════════
    # WITHDRAW
    # ═══════════════════════════════════════════════════════════════════════
    
    def withdraw(self, proof: WithdrawProof) -> str:
        """Ejecuta un retiro usando la prueba generada"""
        if not self.account:
            raise ValueError("Private key required for transactions")
        
        tx = self.contract.functions.withdraw(
            proof.proof,
            proof.root,
            proof.nullifier_hash,
            Web3.to_checksum_address(proof.recipient),
            Web3.to_checksum_address(proof.relayer),
            proof.fee,
            proof.refund
        ).build_transaction({
            'from': self.account.address,
            'gas': 1000000,
            'gasPrice': self.w3.eth.gas_price,
            'nonce': self.w3.eth.get_transaction_count(self.account.address)
        })
        
        signed = self.account.sign_transaction(tx)
        tx_hash = self.w3.eth.send_raw_transaction(signed.rawTransaction)
        
        return tx_hash.hex()
    
    # ═══════════════════════════════════════════════════════════════════════
    # COERCION RESISTANCE
    # ═══════════════════════════════════════════════════════════════════════
    
    def configure_coercion(
        self,
        commitment: Commitment,
        config: CoercionConfig
    ) -> str:
        """Configura la resistencia a coerción para un commitment"""
        if not self.account:
            raise ValueError("Private key required for transactions")
        
        duress_key_hash = Web3.keccak(config.duress_key)
        
        tx = self.contract.functions.configureCoercionResistance(
            commitment.commitment_hash,
            duress_key_hash,
            Web3.to_checksum_address(config.decoy_wallet),
            config.decoy_balance,
            config.expected_hour_min,
            config.expected_hour_max,
            config.withdrawal_delay_hours
        ).build_transaction({
            'from': self.account.address,
            'gas': 200000,
            'gasPrice': self.w3.eth.gas_price,
            'nonce': self.w3.eth.get_transaction_count(self.account.address)
        })
        
        signed = self.account.sign_transaction(tx)
        tx_hash = self.w3.eth.send_raw_transaction(signed.rawTransaction)
        
        return tx_hash.hex()
    
    # ═══════════════════════════════════════════════════════════════════════
    # UTILITIES
    # ═══════════════════════════════════════════════════════════════════════
    
    def is_spent(self, nullifier_hash: bytes) -> bool:
        """Verifica si un nullifier ya fue usado"""
        return self.contract.functions.isSpent(nullifier_hash).call()
    
    def get_denomination(self) -> int:
        """Obtiene la denominación del pool"""
        return self.contract.functions.denomination().call()
    
    def get_current_root(self) -> bytes:
        """Obtiene el root actual del Merkle tree"""
        return self.contract.functions.getLastRoot().call()


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='ZK Bank CLI')
    parser.add_argument('command', choices=['generate', 'deposit', 'withdraw', 'status'])
    parser.add_argument('--rpc', default='http://127.0.0.1:8545')
    parser.add_argument('--contract', required=True)
    parser.add_argument('--key', help='Private key')
    parser.add_argument('--commitment-file', help='Path to commitment JSON')
    parser.add_argument('--recipient', help='Withdrawal recipient')
    
    args = parser.parse_args()
    
    client = ZKBankClient(
        rpc_url=args.rpc,
        zkbank_address=args.contract,
        private_key=args.key
    )
    
    if args.command == 'generate':
        commitment = client.generate_commitment()
        print(f"Generated commitment:")
        print(json.dumps(commitment.to_dict(), indent=2))
        if args.commitment_file:
            client.save_commitment(commitment, Path(args.commitment_file))
            print(f"\nSaved to {args.commitment_file}")
    
    elif args.command == 'deposit':
        if not args.commitment_file:
            print("Error: --commitment-file required")
            return
        commitment = client.load_commitment(Path(args.commitment_file))
        tx_hash = client.deposit(commitment)
        print(f"Deposit tx: {tx_hash}")
    
    elif args.command == 'status':
        print(f"Denomination: {client.get_denomination() / 1e18} ETH")
        print(f"Current root: {client.get_current_root().hex()}")


if __name__ == '__main__':
    main()
