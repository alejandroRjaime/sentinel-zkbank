// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/// @title Interfaz común para verificadores ZK-SNARK
/// @notice Define la interfaz estándar para todos los verificadores del sistema
interface IVerifier {
    // ========== EVENTOS ==========

    /// @notice Emitido cuando una verificación es exitosa
    event VerificationSuccess(
        address indexed verifier,
        bytes32 indexed proofHash,
        uint256 timestamp
    );

    /// @notice Emitido cuando una verificación falla
    event VerificationFailure(
        address indexed verifier,
        bytes32 indexed proofHash,
        string reason,
        uint256 timestamp
    );

    /// @notice Emitido cuando se actualiza el estado del verificador
    event VerifierStateUpdated(
        address indexed verifier,
        bool paused,
        address admin,
        uint256 timestamp
    );

    // ========== FUNCIONES ==========

    /// @notice Verifica una prueba ZK-SNARK
    /// @param proof La prueba serializada
    /// @param inputs Los inputs públicos
    /// @return true si la verificación es exitosa
    function verifyProof(
        bytes calldata proof,
        bytes calldata inputs
    ) external returns (bool);

    /// @notice Verifica una prueba con datos adicionales
    /// @param proof La prueba serializada
    /// @param inputs Los inputs públicos
    /// @param extraData Datos adicionales para el contexto
    /// @return true si la verificación es exitosa
    function verifyProofWithContext(
        bytes calldata proof,
        bytes calldata inputs,
        bytes calldata extraData
    ) external returns (bool);

    /// @notice Verifica múltiples pruebas en batch
    /// @param proofs Array de pruebas
    /// @param inputs Array de inputs
    /// @return Array de resultados booleanos
    function verifyProofBatch(
        bytes[] calldata proofs,
        bytes[] calldata inputs
    ) external returns (bool[] memory);

    /// @notice Obtiene el estado del verificador
    /// @return version Versión del verificador
    /// @return isPaused Si el verificador está en pausa
    /// @return admin Dirección del administrador
    /// @return constraints Número de constraints del circuito
    function getVerifierInfo() external view returns (
        string memory version,
        bool isPaused,
        address admin,
        uint256 constraints
    );

    /// @notice Obtiene las estadísticas del verificador
    /// @return totalVerified Número total de verificaciones exitosas
    /// @return totalFailed Número total de verificaciones fallidas
    /// @return lastVerification Timestamp de la última verificación
    function getVerificationStats() external view returns (
        uint256 totalVerified,
        uint256 totalFailed,
        uint256 lastVerification
    );

    /// @notice Actualiza los parámetros del verificador
    /// @param newParams Nuevos parámetros en formato bytes
    function updateParameters(bytes calldata newParams) external;

    /// @notice Pausa o reanuda el verificador
    /// @param paused true para pausar, false para reanudar
    function setPaused(bool paused) external;
}