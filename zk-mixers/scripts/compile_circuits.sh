#!/bin/bash

# ============================================
# SCRIPT DE COMPILACIÓN PARA TESIS DE INVESTIGACIÓN
# Compila circuitos Circom con configuraciones académicas
# ============================================

set -e  # Exit on error

echo "============================================"
echo "🔬 COMPILADOR DE CIRCUITOS - TESIS DE INVESTIGACIÓN"
echo "============================================"

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuración
BUILD_DIR="build"
CIRCUITS_DIR="circuits"
LIB_DIR="lib"
CONSTANTS_DIR="constants"

# Crear directorios necesarios
mkdir -p $BUILD_DIR/{deposit,withdrawal,lib,artifacts}
mkdir -p $BUILD_DIR/artifacts/{r1cs,wasm,sym,json}

# Función para compilar un circuito
compile_circuit() {
    local circuit_name=$1
    local circuit_file=$2
    local template_name=$3
    local optimization_level=$4

    echo -e "\n${BLUE}📦 Compilando $circuit_name...${NC}"
    echo "Archivo: $circuit_file"
    echo "Template: $template_name"
    echo "Optimización: -O$optimization_level"

    # Compilar circuito
    echo -e "${YELLOW}Ejecutando circom...${NC}"

    circom $circuit_file \
        --r1cs --wasm --sym \
        -o $BUILD_DIR/$circuit_name \
        -l $LIB_DIR \
        -l node_modules/circomlib/circuits \
        --O$optimization_level \
        --verbose

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ $circuit_name compilado exitosamente${NC}"

        # Mover archivos a directorios organizados
        mv $BUILD_DIR/$circuit_name/*.r1cs $BUILD_DIR/artifacts/r1cs/${circuit_name}.r1cs 2>/dev/null || true
        mv $BUILD_DIR/$circuit_name/*.wasm $BUILD_DIR/artifacts/wasm/${circuit_name}.wasm 2>/dev/null || true
        mv $BUILD_DIR/$circuit_name/*.sym $BUILD_DIR/artifacts/sym/${circuit_name}.sym 2>/dev/null || true

        # Generar información del circuito
        echo -e "\n${YELLOW}📊 Información del circuito:${NC}"
        snarkjs r1cs info $BUILD_DIR/artifacts/r1cs/${circuit_name}.r1cs

        # Calcular número de constraints
        local constraints=$(snarkjs r1cs info $BUILD_DIR/artifacts/r1cs/${circuit_name}.r1cs 2>/dev/null | grep "Constraints" | awk '{print $3}' | tr -d ',')

        # Guardar metadata
        cat > $BUILD_DIR/artifacts/json/${circuit_name}_info.json << EOF
{
    "circuit_name": "$circuit_name",
    "template": "$template_name",
    "file": "$circuit_file",
    "optimization_level": "$optimization_level",
    "constraints": "$constraints",
    "compilation_date": "$(date -Iseconds)",
    "circom_version": "$(circom --version)"
}
EOF

        return 0
    else
        echo -e "${RED}❌ Error compilando $circuit_name${NC}"
        return 1
    fi
}

# Función para compilar librerías
compile_libraries() {
    echo -e "\n${BLUE}📚 Compilando librerías...${NC}"

    # Lista de librerías a compilar
    local libraries=("merkle" "hashes" "utils" "security")

    for lib in "${libraries[@]}"; do
        echo -e "${YELLOW}Compilando $lib.circom...${NC}"

        # Verificar que el archivo existe
        if [ -f "$LIB_DIR/$lib.circom" ]; then
            circom $LIB_DIR/$lib.circom \
                --r1cs \
                -o $BUILD_DIR/lib \
                -l node_modules/circomlib/circuits \
                --O1

            if [ $? -eq 0 ]; then
                echo -e "${GREEN}✅ $lib.circom compilado${NC}"
            else
                echo -e "${YELLOW}⚠️  Advertencia compilando $lib.circom${NC}"
            fi
        else
            echo -e "${YELLOW}⚠️  $lib.circom no encontrado${NC}"
        fi
    done
}

# Función para generar reporte
generate_report() {
    echo -e "\n${BLUE}📄 Generando reporte de compilación...${NC}"

    cat > $BUILD_DIR/compilation_report.md << 'EOF'
# Reporte de Compilación - Circuitos ZK-SNARK

## Información del Sistema
- Fecha: $(date)
- Circom Version: $(circom --version)
- Directorio: $(pwd)

## Circuitos Compilados
EOF

    # Agregar información de cada circuito
    for circuit in deposit withdrawal; do
        if [ -f "$BUILD_DIR/artifacts/json/${circuit}_info.json" ]; then
            cat >> $BUILD_DIR/compilation_report.md << EOF

### ${circuit^}
\`\`\`json
$(cat $BUILD_DIR/artifacts/json/${circuit}_info.json)
\`\`\`
EOF
        fi
    done

    # Agregar resumen
    cat >> $BUILD_DIR/compilation_report.md << 'EOF'

## Resumen de Constraints

| Circuito | Constraints | Estado |
|----------|-------------|--------|
EOF

    for circuit in deposit withdrawal; do
        if [ -f "$BUILD_DIR/artifacts/json/${circuit}_info.json" ]; then
            constraints=$(grep '"constraints"' $BUILD_DIR/artifacts/json/${circuit}_info.json | cut -d'"' -f4)
            echo "| $circuit | $constraints | ✅ |" >> $BUILD_DIR/compilation_report.md
        else
            echo "| $circuit | N/A | ❌ |" >> $BUILD_DIR/compilation_report.md
        fi
    done

    echo -e "\n${GREEN}✅ Reporte generado: $BUILD_DIR/compilation_report.md${NC}"
}

# ========== PROGRAMA PRINCIPAL ==========

echo -e "${YELLOW}🔍 Verificando dependencias...${NC}"

# Verificar que circom está instalado
if ! command -v circom &> /dev/null; then
    echo -e "${RED}❌ Error: circom no encontrado${NC}"
    echo "Instala circom con: npm install -g circom"
    exit 1
fi

# Verificar que snarkjs está instalado
if ! command -v snarkjs &> /dev/null; then
    echo -e "${YELLOW}⚠️  Advertencia: snarkjs no encontrado${NC}"
    echo "Algunas funcionalidades pueden estar limitadas"
fi

# Verificar archivos de circuito
echo -e "\n${YELLOW}📁 Verificando estructura de archivos...${NC}"

required_files=(
    "$CIRCUITS_DIR/deposit_test.circom"
    "$CIRCUITS_DIR/withdrawal_test.circom"
    "$CONSTANTS_DIR/constants.circom"
)

for file in "${required_files[@]}"; do
    if [ -f "$file" ]; then
        echo -e "${GREEN}✅ $file encontrado${NC}"
    else
        echo -e "${RED}❌ $file no encontrado${NC}"
        exit 1
    fi
done

# Compilar librerías primero
compile_libraries

# Compilar circuitos principales
echo -e "\n${BLUE}🚀 Compilando circuitos principales...${NC}"

# Compilar depósito con optimización O1 (balance velocidad/constraints)
compile_circuit "deposit" \
    "$CIRCUITS_DIR/deposit_test.circom" \
    "MainDeposit" \
    "1"

# Compilar retiro con optimización O2 (más optimización)
compile_circuit "withdrawal" \
    "$CIRCUITS_DIR/withdrawal_test.circom" \
    "MainWithdrawal" \
    "2"

# Generar reporte
generate_report

# Información final
echo -e "\n${GREEN}============================================${NC}"
echo -e "${GREEN}🎉 COMPILACIÓN COMPLETADA EXITOSAMENTE${NC}"
echo -e "${GREEN}============================================${NC}"
echo -e "\n${YELLOW}📁 Directorios creados:${NC}"
echo "  $BUILD_DIR/artifacts/r1cs/    # Archivos .r1cs"
echo "  $BUILD_DIR/artifacts/wasm/    # Archivos .wasm"
echo "  $BUILD_DIR/artifacts/sym/     # Archivos .sym"
echo "  $BUILD_DIR/artifacts/json/    # Metadatos JSON"
echo -e "\n${YELLOW}📄 Reporte generado:${NC}"
echo "  $BUILD_DIR/compilation_report.md"
echo -e "\n${YELLOW}🚀 Siguientes pasos:${NC}"
echo "  1. Generar claves: bash scripts/generate_keys.sh"
echo "  2. Ejecutar tests: npm test"
echo "  3. Benchmark: node scripts/benchmark.js"

# Tiempo total
echo -e "\n${BLUE}⏱️  Tiempo total: $SECONDS segundos${NC}"