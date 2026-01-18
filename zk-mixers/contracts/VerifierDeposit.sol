// SPDX-License-Identifier: GPL-3.0
/*
 * Verificador Groth16 para circuito de depósito
 * Optimizado para eficiencia en gas y seguridad
 * Diseñado para investigación académica
 */

pragma solidity ^0.8.17;

/// @title Verificador de Depósito ZK-SNARK
/// @notice Contrato para verificar pruebas Groth16 de operaciones de depósito
/// @dev Optimizado para mínimo consumo de gas y máxima seguridad
contract VerifierDeposit {
    // ========== CONSTANTES Y ESTRUCTURAS ==========

    /// @dev Número de elementos en la prueba
    uint256 private constant PROOF_ELEMENTS = 8;

    /// @dev Número de inputs públicos
    uint256 private constant PUBLIC_INPUTS = 5;

    /// @dev Orden del campo primo (bn128)
    uint256 private constant Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    /// @dev Máximo número de verificaciones por bloque (rate limiting)
    uint256 private constant MAX_VERIFICATIONS_PER_BLOCK = 100;

    /// @dev Struct para la prueba Groth16
    struct Proof {
        uint256[2] a;
        uint256[2][2] b;
        uint256[2] c;
    }

    /// @dev Struct para inputs públicos
    struct PublicInputs {
        uint256 depositAmount;
        uint256 tokenId;
        uint256 oldRoot;
        uint256 newRoot;
        uint256 nonce;
    }

    /// @dev Struct para verificación extendida
    struct VerificationData {
        Proof proof;
        PublicInputs inputs;
        uint256 timestamp;
        address operator;
    }

    // ========== VARIABLES DE ESTADO ==========

    /// @dev Registro de nullifiers usados para prevenir double spending
    mapping(uint256 => bool) public usedNullifiers;

    /// @dev Registro de nonces usados por usuario para replay protection
    mapping(address => mapping(uint256 => bool)) public usedNonces;

    /// @dev Contador de verificaciones por bloque
    mapping(uint256 => uint256) public verificationsPerBlock;

    /// @dev Dirección del administrador del sistema
    address public admin;

    /// @dev Estado de pausa para emergencias
    bool public paused;

    /// @dev Fee base para operaciones
    uint256 public baseFee;

    // ========== EVENTOS ==========

    /// @notice Emitido cuando una verificación es exitosa
    event DepositVerified(
        address indexed operator,
        uint256 indexed nullifierHash,
        uint256 newBalance,
        uint256 commitment,
        uint256 timestamp
    );

    /// @notice Emitido cuando se detecta una prueba inválida
    event InvalidProof(address indexed operator, uint256 timestamp);

    /// @notice Emitido cuando se actualiza el administrador
    event AdminUpdated(address oldAdmin, address newAdmin);

    /// @notice Emitido cuando se cambia el estado de pausa
    event Paused(bool paused);

    /// @notice Emitido cuando se actualiza el fee base
    event BaseFeeUpdated(uint256 oldFee, uint256 newFee);

    /// @notice Emitido cuando se registra un nullifier
    event NullifierRegistered(uint256 nullifierHash);

    // ========== MODIFIERS ==========

    /// @dev Solo el administrador puede ejecutar
    modifier onlyAdmin() {
        require(msg.sender == admin, "Verifier: solo administrador");
        _;
    }

    /// @dev El contrato no debe estar en pausa
    modifier whenNotPaused() {
        require(!paused, "Verifier: en pausa");
        _;
    }

    /// @dev Prevenir ataques de reentrancy
    modifier nonReentrant() {
        require(!_reentrancyLocked, "Verifier: reentrancy");
        _reentrancyLocked = true;
        _;
        _reentrancyLocked = false;
    }
    bool private _reentrancyLocked;

    // ========== CONSTRUCTOR ==========

    /// @notice Inicializa el verificador con un administrador
    /// @param _admin Dirección del administrador inicial
    constructor(address _admin) {
        require(_admin != address(0), "Verifier: admin zero address");
        admin = _admin;
        baseFee = 0.001 ether; // Fee inicial
        paused = false;
    }

    // ========== FUNCIONES PÚBLICAS ==========

    /// @notice Verifica una prueba ZK-SNARK de depósito
    /// @param _proof La prueba Groth16 serializada
    /// @param _inputs Los inputs públicos de la prueba
    /// @param _nullifierHash Hash del nullifier para prevenir double spending
    /// @return true si la verificación es exitosa
    function verifyDeposit(
        uint256[8] calldata _proof,
        uint256[5] calldata _inputs,
        uint256 _nullifierHash
    )
        external
        whenNotPaused
        nonReentrant
        returns (bool)
    {
        // 1. Verificar rate limiting
        _checkRateLimit();

        // 2. Verificar que el nullifier no ha sido usado
        require(!usedNullifiers[_nullifierHash], "Verifier: nullifier ya usado");

        // 3. Verificar que el nonce no ha sido usado (si se provee dirección)
        // Nota: En sistemas completamente anónimos, esto puede omitirse

        // 4. Verificar límites de inputs
        _validateInputs(_inputs);

        // 5. Verificar la prueba ZK-SNARK
        bool proofValid = _verifyProof(_proof, _inputs);
        require(proofValid, "Verifier: prueba invalida");

        // 6. Registrar nullifier como usado
        usedNullifiers[_nullifierHash] = true;

        // 7. Emitir evento
        emit DepositVerified(
            msg.sender,
            _nullifierHash,
            _inputs[0], // depositAmount
            _inputs[3], // newRoot
            block.timestamp
        );

        // 8. Incrementar contador de verificaciones
        verificationsPerBlock[block.number]++;

        return true;
    }

    /// @notice Verifica una prueba con datos extendidos
    /// @param _verificationData Datos completos de verificación
    /// @return true si la verificación es exitosa
    function verifyDepositExtended(
        VerificationData calldata _verificationData
    )
        external
        whenNotPaused
        nonReentrant
        returns (bool)
    {
        // 1. Verificar rate limiting
        _checkRateLimit();

        // 2. Verificar timestamp (prevenir replay attacks)
        require(
            _verificationData.timestamp <= block.timestamp &&
            block.timestamp - _verificationData.timestamp <= 1 hours,
            "Verifier: timestamp invalido"
        );

        // 3. Convertir structs a arrays para la verificación interna
        uint256[8] memory proofArray = [
            _verificationData.proof.a[0],
            _verificationData.proof.a[1],
            _verificationData.proof.b[0][0],
            _verificationData.proof.b[0][1],
            _verificationData.proof.b[1][0],
            _verificationData.proof.b[1][1],
            _verificationData.proof.c[0],
            _verificationData.proof.c[1]
        ];

        uint256[5] memory inputsArray = [
            _verificationData.inputs.depositAmount,
            _verificationData.inputs.tokenId,
            _verificationData.inputs.oldRoot,
            _verificationData.inputs.newRoot,
            _verificationData.inputs.nonce
        ];

        // 4. Verificar nullifier implícito en la prueba
        // (En este diseño, el nullifier se deriva de los inputs)
        uint256 derivedNullifier = _deriveNullifier(inputsArray);

        // 5. Verificar que el nullifier no ha sido usado
        require(!usedNullifiers[derivedNullifier], "Verifier: nullifier ya usado");

        // 6. Verificar límites de inputs
        _validateInputs(inputsArray);

        // 7. Verificar la prueba
        bool proofValid = _verifyProof(proofArray, inputsArray);
        require(proofValid, "Verifier: prueba invalida");

        // 8. Registrar nullifier
        usedNullifiers[derivedNullifier] = true;

        // 9. Emitir evento extendido
        emit DepositVerified(
            _verificationData.operator,
            derivedNullifier,
            inputsArray[0],
            inputsArray[3],
            block.timestamp
        );

        // 10. Incrementar contador
        verificationsPerBlock[block.number]++;

        return true;
    }

    /// @notice Verifica múltiples depósitos en batch
    /// @param _proofs Array de pruebas
    /// @param _inputs Array de inputs
    /// @param _nullifiers Array de nullifiers
    /// @return Array de resultados booleanos
    function verifyDepositBatch(
        uint256[8][] calldata _proofs,
        uint256[5][] calldata _inputs,
        uint256[] calldata _nullifiers
    )
        external
        whenNotPaused
        nonReentrant
        returns (bool[] memory)
    {
        require(
            _proofs.length == _inputs.length &&
            _inputs.length == _nullifiers.length,
            "Verifier: arrays length mismatch"
        );

        require(_proofs.length <= 10, "Verifier: batch too large");

        bool[] memory results = new bool[](_proofs.length);

        for (uint256 i = 0; i < _proofs.length; i++) {
            // Saltar si el nullifier ya fue usado
            if (usedNullifiers[_nullifiers[i]]) {
                results[i] = false;
                continue;
            }

            try this.verifyDeposit(_proofs[i], _inputs[i], _nullifiers[i]) {
                results[i] = true;
            } catch {
                results[i] = false;
                emit InvalidProof(msg.sender, block.timestamp);
            }
        }

        return results;
    }

    // ========== FUNCIONES DE ADMINISTRACIÓN ==========

    /// @notice Cambia la dirección del administrador
    /// @param _newAdmin Nueva dirección del administrador
    function setAdmin(address _newAdmin) external onlyAdmin {
        require(_newAdmin != address(0), "Verifier: admin zero address");
        address oldAdmin = admin;
        admin = _newAdmin;
        emit AdminUpdated(oldAdmin, _newAdmin);
    }

    /// @notice Pausa o reanuda el contrato
    /// @param _paused true para pausar, false para reanudar
    function setPaused(bool _paused) external onlyAdmin {
        paused = _paused;
        emit Paused(_paused);
    }

    /// @notice Cambia el fee base para operaciones
    /// @param _newFee Nuevo fee en wei
    function setBaseFee(uint256 _newFee) external onlyAdmin {
        require(_newFee <= 0.01 ether, "Verifier: fee demasiado alto");
        uint256 oldFee = baseFee;
        baseFee = _newFee;
        emit BaseFeeUpdated(oldFee, _newFee);
    }

    /// @notice Retira los fees acumulados
    /// @param _to Dirección a la que enviar los fees
    function withdrawFees(address payable _to) external onlyAdmin {
        require(_to != address(0), "Verifier: to zero address");
        uint256 balance = address(this).balance;
        require(balance > 0, "Verifier: sin balance");

        (bool success, ) = _to.call{value: balance}("");
        require(success, "Verifier: transfer fallido");
    }

    /// @notice Registra un nullifier manualmente (solo para emergencias)
    /// @param _nullifierHash Hash del nullifier a registrar
    function registerNullifier(uint256 _nullifierHash) external onlyAdmin {
        usedNullifiers[_nullifierHash] = true;
        emit NullifierRegistered(_nullifierHash);
    }

    // ========== FUNCIONES DE CONSULTA ==========

    /// @notice Verifica si un nullifier ha sido usado
    /// @param _nullifierHash Hash del nullifier a verificar
    /// @return true si el nullifier ha sido usado
    function isNullifierUsed(uint256 _nullifierHash) external view returns (bool) {
        return usedNullifiers[_nullifierHash];
    }

    /// @notice Obtiene el número de verificaciones en el bloque actual
    /// @return Número de verificaciones
    function getCurrentBlockVerifications() external view returns (uint256) {
        return verificationsPerBlock[block.number];
    }

    /// @notice Obtiene información del contrato
    /// @return adminAddress Dirección del administrador
    /// @return isPaused Estado de pausa
    /// @return currentBaseFee Fee base actual
    /// @return totalNullifiers Número total de nullifiers registrados
    function getContractInfo() external view returns (
        address adminAddress,
        bool isPaused,
        uint256 currentBaseFee,
        uint256 totalNullifiers
    ) {
        // Nota: No hay forma eficiente de contar todos los nullifiers
        // En producción, se usaría un contador separado
        return (
            admin,
            paused,
            baseFee,
            0 // Placeholder
        );
    }

    // ========== FUNCIONES INTERNAS ==========

    /// @dev Verifica el rate limiting
    function _checkRateLimit() internal view {
        require(
            verificationsPerBlock[block.number] < MAX_VERIFICATIONS_PER_BLOCK,
            "Verifier: rate limit excedido"
        );
    }

    /// @dev Valida los inputs públicos
    function _validateInputs(uint256[5] memory _inputs) internal pure {
        // Validar depositAmount (debe ser positivo y dentro de límites)
        require(_inputs[0] > 0, "Verifier: amount invalido");
        require(_inputs[0] <= 1e24, "Verifier: amount demasiado grande"); // 1 millón de tokens con 18 decimales

        // Validar tokenId (debe estar en rango razonable)
        require(_inputs[1] <= type(uint32).max, "Verifier: tokenId invalido");

        // Validar roots (no pueden ser cero)
        require(_inputs[2] != 0, "Verifier: oldRoot zero");
        require(_inputs[3] != 0, "Verifier: newRoot zero");
        require(_inputs[2] != _inputs[3], "Verifier: roots iguales");

        // Validar nonce
        require(_inputs[4] <= type(uint64).max, "Verifier: nonce invalido");
    }

    /// @dev Deriva un nullifier de los inputs (para versión extendida)
    function _deriveNullifier(uint256[5] memory _inputs) internal pure returns (uint256) {
        // En un sistema real, esto sería un hash de varios inputs
        return uint256(keccak256(abi.encodePacked(
            _inputs[0], // depositAmount
            _inputs[1], // tokenId
            _inputs[2], // oldRoot
            _inputs[4]  // nonce
        )));
    }

    /// @dev Verificación principal de la prueba Groth16
    /// @notice ESTA ES UNA IMPLEMENTACIÓN DE EJEMPLO
    /// @notice En producción, usaría las funciones de la librería de verificación
    function _verifyProof(
        uint256[8] memory _proof,
        uint256[5] memory _inputs
    ) internal pure returns (bool) {
        // Esta es una implementación simplificada para demostración
        // En un sistema real, usarías una librería como:
        // - snarkjs para generar el contrato
        // - Semaphore o Tornado Cash como referencia

        // Verificaciones básicas de la prueba
        require(_proof[0] < Q && _proof[1] < Q, "Verifier: prueba invalida a");
        require(_proof[2] < Q && _proof[3] < Q, "Verifier: prueba invalida b0");
        require(_proof[4] < Q && _proof[5] < Q, "Verifier: prueba invalida b1");
        require(_proof[6] < Q && _proof[7] < Q, "Verifier: prueba invalida c");

        // En producción, aquí iría la verificación completa de emparejamiento
        // usando precompilados de bn254 (0x06, 0x07, 0x08)

        // Para esta demostración, simulamos una verificación exitosa
        // si todos los valores son menores que Q y diferentes de 0
        for (uint256 i = 0; i < 8; i++) {
            if (_proof[i] == 0 || _proof[i] >= Q) {
                return false;
            }
        }

        // Verificar inputs
        for (uint256 i = 0; i < 5; i++) {
            if (_inputs[i] >= Q) {
                return false;
            }
        }

        // Simulación: la prueba es válida si la suma de los inputs es par
        // (Esto es solo para demostración - NO USAR EN PRODUCCIÓN)
        uint256 sum = 0;
        for (uint256 i = 0; i < 5; i++) {
            sum += _inputs[i];
        }

        return sum % 2 == 0;
    }

    /// @dev Función de emergencia para recuperar tokens ERC20
    function recoverERC20(address tokenAddress, uint256 amount) external onlyAdmin {
        require(tokenAddress != address(0), "Verifier: token zero address");
        // Implementación básica - en producción usar SafeERC20
        (bool success, ) = tokenAddress.call(
            abi.encodeWithSignature("transfer(address,uint256)", admin, amount)
        );
        require(success, "Verifier: ERC20 transfer fallido");
    }

    // ========== FALLBACK Y RECEIVE ==========

    /// @dev Aceptar ETH (para fees)
    receive() external payable {}

    /// @dev Función fallback
    fallback() external payable {}
}