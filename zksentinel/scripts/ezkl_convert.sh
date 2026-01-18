#!/bin/bash

# ============================================
# ZK-Sentinel: EZKL Conversion Script
# ============================================
#
# Converts PyTorch model to ZK circuit using EZKL
# https://github.com/zkonduit/ezkl

set -e

echo "=== ZK-Sentinel ZKML Conversion ==="

cd "$(dirname "$0")/.."

# Check if EZKL is installed
if ! command -v ezkl &> /dev/null; then
    echo "EZKL not found. Installing..."
    pip install ezkl
fi

# Use simplified MLP (smaller circuit)
MODEL="build/coercion_mlp.onnx"
INPUT="models/sample_input.json"
SETTINGS="build/zkml_settings.json"
CIRCUIT="build/zkml_circuit"

# Create sample input
echo "Creating sample input..."
cat > "$INPUT" << 'EOF'
{
    "input_data": [[0.5, 0.3, 0.1, 0.2, 0.4, 0.6, 0.3, 0.2, 0.5, 0.1]]
}
EOF

# Generate settings
echo "Generating EZKL settings..."
ezkl gen-settings \
    --model "$MODEL" \
    --output "$SETTINGS"

# Calibrate settings
echo "Calibrating..."
ezkl calibrate-settings \
    --model "$MODEL" \
    --settings "$SETTINGS" \
    --data "$INPUT"

# Compile circuit
echo "Compiling to ZK circuit..."
ezkl compile-circuit \
    --model "$MODEL" \
    --compiled-circuit "$CIRCUIT.compiled" \
    --settings "$SETTINGS"

# Setup (generate proving/verifying keys)
echo "Running setup..."
ezkl setup \
    --compiled-circuit "$CIRCUIT.compiled" \
    --vk-path "$CIRCUIT.vk" \
    --pk-path "$CIRCUIT.pk"

# Generate proof (test)
echo "Generating test proof..."
ezkl gen-witness \
    --compiled-circuit "$CIRCUIT.compiled" \
    --data "$INPUT" \
    --output "$CIRCUIT.witness"

ezkl prove \
    --compiled-circuit "$CIRCUIT.compiled" \
    --witness "$CIRCUIT.witness" \
    --pk-path "$CIRCUIT.pk" \
    --proof-path "$CIRCUIT.proof"

# Verify
echo "Verifying proof..."
ezkl verify \
    --proof-path "$CIRCUIT.proof" \
    --settings "$SETTINGS" \
    --vk-path "$CIRCUIT.vk"

# Export Solidity verifier
echo "Exporting Solidity verifier..."
ezkl create-evm-verifier \
    --vk-path "$CIRCUIT.vk" \
    --settings "$SETTINGS" \
    --sol-code-path "contracts/ZKMLVerifier.sol"

echo ""
echo "=== ZKML Conversion Complete ==="
echo ""
echo "Generated files:"
echo "  - $CIRCUIT.compiled (compiled circuit)"
echo "  - $CIRCUIT.pk (proving key)"
echo "  - $CIRCUIT.vk (verification key)"
echo "  - contracts/ZKMLVerifier.sol (Solidity verifier)"
