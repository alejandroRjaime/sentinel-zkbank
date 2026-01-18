#!/bin/bash

# Script para generar claves criptográficas para los circuitos

echo "🔑 Generando claves para circuitos de tesis..."

# Configuración
BUILD_DIR="build"
PTAU_FILE="$BUILD_DIR/powersOfTau28_hez_final_20.ptau"
DEPOSIT_R1CS="$BUILD_DIR/artifacts/r1cs/deposit.r1cs"
WITHDRAWAL_R1CS="$BUILD_DIR/artifacts/r1cs/withdrawal.r1cs"

# Descargar powersOfTau si no existe
if [ ! -f "$PTAU_FILE" ]; then
    echo "📥 Descargando powersOfTau..."
    wget https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_20.ptau \
        -O "$PTAU_FILE"
fi

# Función para generar claves de un circuito
generate_keys() {
    local circuit_name=$1
    local r1cs_file=$2
    local protocol=$3

    echo -e "\n🔧 Generando claves para $circuit_name..."

    # Crear directorio para las claves
    mkdir -p "$BUILD_DIR/keys/$circuit_name"

    # Fase 1: Generar .zkey
    echo "📝 Generando .zkey file..."
    snarkjs $protocol setup \
        "$r1cs_file" \
        "$PTAU_FILE" \
        "$BUILD_DIR/keys/$circuit_name/${circuit_name}_0000.zkey"

    # Contribuir a la ceremonia (entropía aleatoria)
    echo "🎲 Añadiendo contribución..."
    snarkjs zkey contribute \
        "$BUILD_DIR/keys/$circuit_name/${circuit_name}_0000.zkey" \
        "$BUILD_DIR/keys/$circuit_name/${circuit_name}_final.zkey" \
        --name="Tesista" \
        -v

    # Exportar clave de verificación
    echo "📤 Exportando verification key..."
    snarkjs zkey export verificationkey \
        "$BUILD_DIR/keys/$circuit_name/${circuit_name}_final.zkey" \
        "$BUILD_DIR/keys/$circuit_name/verification_key.json"

    # Generar verificador Solidity
    echo "📄 Generando contrato verificador..."
    snarkjs zkey export solidityverifier \
        "$BUILD_DIR/keys/$circuit_name/${circuit_name}_final.zkey" \
        "$BUILD_DIR/keys/$circuit_name/Verifier_${circuit_name}.sol"

    echo "✅ Claves para $circuit_name generadas exitosamente"
}

# Generar claves para depósito (Groth16)
if [ -f "$DEPOSIT_R1CS" ]; then
    generate_keys "deposit" "$DEPOSIT_R1CS" "groth16"
else
    echo "❌ deposit.r1cs no encontrado. Compila primero los circuitos."
fi

# Generar claves para retiro (PLONK)
if [ -f "$WITHDRAWAL_R1CS" ]; then
    generate_keys "withdrawal" "$WITHDRAWAL_R1CS" "plonk"
else
    echo "❌ withdrawal.r1cs no encontrado. Compila primero los circuitos."
fi

echo -e "\n🎉 Proceso de generación de claves completado!"