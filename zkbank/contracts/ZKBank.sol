// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IVerifier} from "./interfaces/IVerifier.sol";
import {MerkleTreeWithHistory} from "./MerkleTreeWithHistory.sol";

/**
 * @title ZK Bank - Privacy Pool with Coercion Resistance
 * @author Alejandro Jaime (Tesis Doctoral UNLP)
 * @notice Pool de privacidad basado en zk-SNARKs con resistencia a coerción
 * 
 * Características:
 * - Depósitos de monto fijo (1 ETH por defecto)
 * - Retiros anónimos vía zk-SNARK proofs
 * - Nullifiers para prevenir doble gasto
 * - Soporte para relayers (meta-transacciones)
 * - Eventos mínimos para máxima privacidad
 */
contract ZKBank is MerkleTreeWithHistory, ReentrancyGuard {
    
    // ═══════════════════════════════════════════════════════════════════════
    // CONSTANTS
    // ═══════════════════════════════════════════════════════════════════════
    
    uint256 public immutable denomination;
    IVerifier public immutable verifier;
    
    // ═══════════════════════════════════════════════════════════════════════
    // STATE
    // ═══════════════════════════════════════════════════════════════════════
    
    mapping(bytes32 => bool) public nullifierHashes;
    mapping(bytes32 => bool) public commitments;
    
    // ═══════════════════════════════════════════════════════════════════════
    // EVENTS (mínimos para privacidad)
    // ═══════════════════════════════════════════════════════════════════════
    
    event Deposit(bytes32 indexed commitment, uint32 leafIndex, uint256 timestamp);
    event Withdrawal(address to, bytes32 nullifierHash, address indexed relayer, uint256 fee);
    
    // ═══════════════════════════════════════════════════════════════════════
    // ERRORS
    // ═══════════════════════════════════════════════════════════════════════
    
    error InvalidDenomination();
    error CommitmentAlreadyExists();
    error InvalidMerkleRoot();
    error NullifierAlreadyUsed();
    error InvalidProof();
    error PaymentFailed();
    error FeeExceedsDenomination();
    
    // ═══════════════════════════════════════════════════════════════════════
    // CONSTRUCTOR
    // ═══════════════════════════════════════════════════════════════════════
    
    /**
     * @param _verifier Dirección del contrato verificador de zk-SNARKs
     * @param _hasher Dirección del contrato hasher (Poseidon)
     * @param _denomination Monto fijo de cada depósito (ej: 1 ether)
     * @param _merkleTreeHeight Altura del árbol Merkle (20 = ~1M deposits)
     */
    constructor(
        IVerifier _verifier,
        address _hasher,
        uint256 _denomination,
        uint32 _merkleTreeHeight
    ) MerkleTreeWithHistory(_merkleTreeHeight, _hasher) {
        if (_denomination == 0) revert InvalidDenomination();
        verifier = _verifier;
        denomination = _denomination;
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // DEPOSIT
    // ═══════════════════════════════════════════════════════════════════════
    
    /**
     * @notice Deposita fondos en el pool
     * @param _commitment Hash del commitment = Poseidon(secret, nullifier)
     * @dev El usuario debe generar secret y nullifier off-chain
     */
    function deposit(bytes32 _commitment) external payable virtual nonReentrant {
        if (msg.value != denomination) revert InvalidDenomination();
        if (commitments[_commitment]) revert CommitmentAlreadyExists();
        
        uint32 insertedIndex = _insert(_commitment);
        commitments[_commitment] = true;
        
        emit Deposit(_commitment, insertedIndex, block.timestamp);
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // WITHDRAW
    // ═══════════════════════════════════════════════════════════════════════
    
    /**
     * @notice Retira fondos del pool usando una prueba zk-SNARK
     * @param _proof Prueba zk-SNARK (a, b, c)
     * @param _root Merkle root usado en la prueba
     * @param _nullifierHash Hash del nullifier
     * @param _recipient Dirección que recibe los fondos
     * @param _relayer Dirección del relayer (0 si no hay)
     * @param _fee Fee para el relayer
     * @param _refund Refund de gas (para relayers)
     */
    function withdraw(
        bytes calldata _proof,
        bytes32 _root,
        bytes32 _nullifierHash,
        address payable _recipient,
        address payable _relayer,
        uint256 _fee,
        uint256 _refund
    ) external payable virtual nonReentrant {
        if (_fee > denomination) revert FeeExceedsDenomination();
        if (!isKnownRoot(_root)) revert InvalidMerkleRoot();
        if (nullifierHashes[_nullifierHash]) revert NullifierAlreadyUsed();
        
        // Verificar la prueba zk-SNARK
        if (!_verifyProof(
            _proof,
            _root,
            _nullifierHash,
            _recipient,
            _relayer,
            _fee,
            _refund
        )) revert InvalidProof();
        
        // Marcar nullifier como usado
        nullifierHashes[_nullifierHash] = true;
        
        // Procesar pagos
        _processWithdraw(_recipient, _relayer, _fee, _refund);
        
        emit Withdrawal(_recipient, _nullifierHash, _relayer, _fee);
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // INTERNAL
    // ═══════════════════════════════════════════════════════════════════════
    
    function _verifyProof(
        bytes calldata _proof,
        bytes32 _root,
        bytes32 _nullifierHash,
        address _recipient,
        address _relayer,
        uint256 _fee,
        uint256 _refund
    ) internal view returns (bool) {
        // Decodificar proof (Groth16: 8 elementos de 256 bits)
        uint256[8] memory proof = abi.decode(_proof, (uint256[8]));
        
        // Inputs públicos
        uint256[6] memory input = [
            uint256(_root),
            uint256(_nullifierHash),
            uint256(uint160(_recipient)),
            uint256(uint160(_relayer)),
            _fee,
            _refund
        ];
        
        return verifier.verifyProof(
            [proof[0], proof[1]],
            [[proof[2], proof[3]], [proof[4], proof[5]]],
            [proof[6], proof[7]],
            input
        );
    }
    
    function _processWithdraw(
        address payable _recipient,
        address payable _relayer,
        uint256 _fee,
        uint256 _refund
    ) internal {
        uint256 amount = denomination - _fee;
        
        // Pagar al recipient
        (bool success, ) = _recipient.call{value: amount}("");
        if (!success) revert PaymentFailed();
        
        // Pagar fee al relayer si aplica
        if (_fee > 0) {
            (success, ) = _relayer.call{value: _fee}("");
            if (!success) revert PaymentFailed();
        }
        
        // Refund si aplica
        if (_refund > 0) {
            (success, ) = _recipient.call{value: _refund}("");
            if (!success) revert PaymentFailed();
        }
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // VIEW FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════════
    
    /**
     * @notice Verifica si un nullifier ya fue usado
     */
    function isSpent(bytes32 _nullifierHash) public view returns (bool) {
        return nullifierHashes[_nullifierHash];
    }
    
    /**
     * @notice Verifica múltiples nullifiers
     */
    function isSpentArray(bytes32[] calldata _nullifierHashes) external view returns (bool[] memory) {
        bool[] memory result = new bool[](_nullifierHashes.length);
        for (uint256 i = 0; i < _nullifierHashes.length; i++) {
            result[i] = isSpent(_nullifierHashes[i]);
        }
        return result;
    }
}
