#!/bin/bash

# ============================================
# ZK-Sentinel: Trusted Setup Script
# ============================================

set -e

echo "=== ZK-Sentinel Trusted Setup ==="

cd "$(dirname "$0")/.."

PTAU_PATH="build/pot20_final.ptau"

# Download Powers of Tau if not exists
if [ ! -f "$PTAU_PATH" ]; then
    echo "Downloading Powers of Tau (pot20)..."
    mkdir -p build
    curl -L -o "$PTAU_PATH" \
        "https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_20.ptau"
fi

# Setup for withdraw_dual
echo ""
echo "=== Setup for withdraw_dual ==="
npx snarkjs groth16 setup \
    build/withdraw_dual.r1cs \
    "$PTAU_PATH" \
    build/withdraw_dual_0000.zkey

# Contribute to ceremony (for production, use multiple contributors)
echo "Contributing to ceremony..."
npx snarkjs zkey contribute \
    build/withdraw_dual_0000.zkey \
    build/withdraw_dual_final.zkey \
    --name="ZK-Sentinel Dev" \
    -v -e="random entropy for dev"

# Export verification key
echo "Exporting verification key..."
npx snarkjs zkey export verificationkey \
    build/withdraw_dual_final.zkey \
    build/withdraw_dual_vkey.json

# Generate Solidity verifier
echo "Generating Solidity verifier..."
npx snarkjs zkey export solidityverifier \
    build/withdraw_dual_final.zkey \
    contracts/Verifier.sol

# Setup for deposit (simpler circuit)
echo ""
echo "=== Setup for deposit ==="
npx snarkjs groth16 setup \
    build/deposit.r1cs \
    "$PTAU_PATH" \
    build/deposit_0000.zkey

npx snarkjs zkey contribute \
    build/deposit_0000.zkey \
    build/deposit_final.zkey \
    --name="ZK-Sentinel Dev" \
    -v -e="random entropy for deposit"

npx snarkjs zkey export verificationkey \
    build/deposit_final.zkey \
    build/deposit_vkey.json

echo ""
echo "=== Trusted Setup Complete ==="
echo ""
echo "Generated files:"
ls -la build/*.zkey build/*.json
echo ""
echo "Verifier contract: contracts/Verifier.sol"
