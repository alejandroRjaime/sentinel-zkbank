// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/**
 * @title MerkleTreeWithHistory
 * @notice Merkle tree que mantiene historial de roots para permitir
 *         pruebas usando roots anteriores (privacidad mejorada)
 * @dev Basado en Tornado Cash con optimizaciones de gas
 */

interface IHasher {
    function poseidon(bytes32[2] calldata inputs) external pure returns (bytes32);
}

contract MerkleTreeWithHistory {
    
    // ═══════════════════════════════════════════════════════════════════════
    // CONSTANTS
    // ═══════════════════════════════════════════════════════════════════════
    
    uint32 public constant ROOT_HISTORY_SIZE = 30;
    
    // ═══════════════════════════════════════════════════════════════════════
    // STATE
    // ═══════════════════════════════════════════════════════════════════════
    
    uint32 public levels;
    IHasher public hasher;
    
    // Filled subtrees para inserción eficiente
    bytes32[] public filledSubtrees;
    
    // Historial circular de roots
    bytes32[ROOT_HISTORY_SIZE] public roots;
    uint32 public currentRootIndex = 0;
    
    // Índice del próximo leaf
    uint32 public nextIndex = 0;
    
    // ═══════════════════════════════════════════════════════════════════════
    // ERRORS
    // ═══════════════════════════════════════════════════════════════════════
    
    error MerkleTreeFull();
    error LevelsTooHigh();
    error LevelsTooLow();
    
    // ═══════════════════════════════════════════════════════════════════════
    // CONSTRUCTOR
    // ═══════════════════════════════════════════════════════════════════════
    
    constructor(uint32 _levels, address _hasher) {
        if (_levels < 1) revert LevelsTooLow();
        if (_levels > 32) revert LevelsTooHigh();
        
        levels = _levels;
        hasher = IHasher(_hasher);
        
        // Inicializar con zeros
        bytes32 currentZero = bytes32(0);
        filledSubtrees = new bytes32[](_levels);
        
        for (uint32 i = 0; i < _levels; i++) {
            filledSubtrees[i] = currentZero;
            currentZero = _hashLeftRight(currentZero, currentZero);
        }
        
        roots[0] = currentZero;
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // INTERNAL
    // ═══════════════════════════════════════════════════════════════════════
    
    function _hashLeftRight(bytes32 _left, bytes32 _right) internal view returns (bytes32) {
        return hasher.poseidon([_left, _right]);
    }
    
    /**
     * @notice Inserta un nuevo leaf en el árbol
     * @param _leaf El commitment a insertar
     * @return index Índice donde se insertó el leaf
     */
    function _insert(bytes32 _leaf) internal returns (uint32 index) {
        uint32 _nextIndex = nextIndex;
        if (_nextIndex >= uint32(2) ** levels) revert MerkleTreeFull();
        
        uint32 currentIndex = _nextIndex;
        bytes32 currentLevelHash = _leaf;
        bytes32 left;
        bytes32 right;
        
        for (uint32 i = 0; i < levels; i++) {
            if (currentIndex % 2 == 0) {
                left = currentLevelHash;
                right = filledSubtrees[i];
                filledSubtrees[i] = currentLevelHash;
            } else {
                left = filledSubtrees[i];
                right = currentLevelHash;
            }
            currentLevelHash = _hashLeftRight(left, right);
            currentIndex /= 2;
        }
        
        uint32 newRootIndex = (currentRootIndex + 1) % ROOT_HISTORY_SIZE;
        currentRootIndex = newRootIndex;
        roots[newRootIndex] = currentLevelHash;
        nextIndex = _nextIndex + 1;
        
        return _nextIndex;
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // VIEW FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════════
    
    /**
     * @notice Verifica si un root es conocido (actual o histórico)
     * @param _root El root a verificar
     * @return Verdadero si el root es válido
     */
    function isKnownRoot(bytes32 _root) public view returns (bool) {
        if (_root == bytes32(0)) return false;
        
        uint32 _currentRootIndex = currentRootIndex;
        uint32 i = _currentRootIndex;
        
        do {
            if (_root == roots[i]) return true;
            if (i == 0) {
                i = ROOT_HISTORY_SIZE - 1;
            } else {
                i--;
            }
        } while (i != _currentRootIndex);
        
        return false;
    }
    
    /**
     * @notice Obtiene el root actual del árbol
     */
    function getLastRoot() public view returns (bytes32) {
        return roots[currentRootIndex];
    }
}
