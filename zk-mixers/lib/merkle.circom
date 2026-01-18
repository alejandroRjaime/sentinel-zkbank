pragma circom 2.1.5;

include "../constants/constants.circom";

/*
 * Implementación eficiente de Sparse Merkle Tree para zkSNARKs
 * Usa Poseidon hash y está optimizado para circuitos Circom
 */
template SparseMerkleVerifier(height) {
    signal input root;
    signal input leaf;
    signal input leafIndex;
    signal input path[height];
    signal input pathIndices[height];
    signal output isValid;

    // Componentes de hash
    component hashers[height];

    // Hash intermedios
    signal computedHash[height + 1];

    // Inicializar con la hoja
    computedHash[0] <== leaf;

    // Calcular camino hacia la raíz
    for (var i = 0; i < height; i++) {
        hashers[i] = PoseidonHash(2);

        // El bit i-ésimo del índice determina el orden
        if (pathIndices[i] == 0) {
            // Hoja está a la izquierda
            hashers[i].in[0] <== computedHash[i];
            hashers[i].in[1] <== path[i];
        } else {
            // Hoja está a la derecha
            hashers[i].in[0] <== path[i];
            hashers[i].in[1] <== computedHash[i];
        }

        computedHash[i + 1] <== hashers[i].out;
    }

    // Verificar que coincide con la raíz
    isValid <== (computedHash[height] == root) ? 1 : 0;
}

/*
 * Verificador batch para múltiples hojas
 * Eficiente para procesar varios updates a la vez
 */
template BatchMerkleVerifier(height, batchSize) {
    signal input oldRoot;
    signal input newRoot;
    signal input leaves[batchSize];
    signal input leafIndices[batchSize];
    signal input oldPaths[height][batchSize];
    signal input newPaths[height][batchSize];
    signal input pathIndices[height][batchSize];

    signal output isValid;

    // Verificar cada hoja individualmente
    component verifiers[batchSize];

    for (var i = 0; i < batchSize; i++) {
        verifiers[i] = SparseMerkleVerifier(height);

        verifiers[i].root <== oldRoot;
        verifiers[i].leaf <== leaves[i];
        verifiers[i].leafIndex <== leafIndices[i];

        for (var j = 0; j < height; j++) {
            verifiers[i].path[j] <== oldPaths[j][i];
            verifiers[i].pathIndices[j] <== pathIndices[j][i];
        }
    }

    // Todos deben ser válidos
    signal allValid <== 1;
    for (var i = 0; i < batchSize; i++) {
        allValid *= verifiers[i].isValid;
    }

    isValid <== allValid;
}

/*
 * Constructor de Merkle Tree para testing
 */
template MerkleTreeConstructor(height) {
    signal input leaves[2**height];
    signal output root;

    component hashers[2**height - 1];

    // Construir árbol desde las hojas
    var currentLevel = leaves;
    var nextLevelSize = 2**(height-1);

    for (var level = 0; level < height; level++) {
        var nextLevel[nextLevelSize];

        for (var i = 0; i < nextLevelSize; i++) {
            hashers[level * nextLevelSize + i] = PoseidonHash(2);

            hashers[level * nextLevelSize + i].in[0] <== currentLevel[2*i];
            hashers[level * nextLevelSize + i].in[1] <== currentLevel[2*i + 1];

            nextLevel[i] <== hashers[level * nextLevelSize + i].out;
        }

        currentLevel = nextLevel;
        nextLevelSize = nextLevelSize / 2;
    }

    root <== currentLevel[0];
}