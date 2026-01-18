#!/bin/bash

# ============================================
# ZK-Sentinel: Circuit Compilation Script
# ============================================

set -e

echo "=== ZK-Sentinel Circuit Compilation ==="

cd "$(dirname "$0")/.."

# Create build directory
mkdir -p build

# Install dependencies if needed
if [ ! -d "node_modules" ]; then
    echo "Installing dependencies..."
    npm install
fi

# Compile withdraw_dual circuit
echo ""
echo "=== Compiling withdraw_dual.circom ==="
circom circuits/withdraw_dual.circom \
    --r1cs \
    --wasm \
    --sym \
    --output build/ \
    -l node_modules \
    -l circuits

echo "Constraints: $(grep -o 'constraints:.*' build/withdraw_dual.r1cs.info 2>/dev/null || echo 'Check build/withdraw_dual.r1cs')"

# Compile deposit circuit
echo ""
echo "=== Compiling deposit.circom ==="
circom circuits/deposit.circom \
    --r1cs \
    --wasm \
    --sym \
    --output build/ \
    -l node_modules \
    -l circuits

echo ""
echo "=== Compilation Complete ==="
echo ""
echo "Generated files:"
ls -la build/

echo ""
echo "Next step: Run trusted setup with './scripts/trusted_setup.sh'"
