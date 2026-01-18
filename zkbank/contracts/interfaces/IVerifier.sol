// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/**
 * @title IVerifier
 * @notice Interface para verificadores Groth16 generados por snarkjs
 */
interface IVerifier {
    /**
     * @notice Verifica una prueba Groth16
     * @param _pA Punto A de la prueba
     * @param _pB Punto B de la prueba (2x2)
     * @param _pC Punto C de la prueba
     * @param _pubSignals Señales públicas
     * @return Verdadero si la prueba es válida
     */
    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[6] calldata _pubSignals
    ) external view returns (bool);
}
