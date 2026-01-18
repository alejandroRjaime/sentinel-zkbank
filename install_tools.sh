#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# SENTINEL ENGINE - Instalador de Herramientas
# ═══════════════════════════════════════════════════════════════════════════════

set -e

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║         SENTINEL ENGINE - Instalador de Herramientas         ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

install_tool() {
    local name=$1
    local cmd=$2
    echo -e "${YELLOW}▶ Instalando $name...${NC}"
    if eval "$cmd"; then
        echo -e "${GREEN}✓ $name instalado${NC}"
    else
        echo -e "${RED}✗ Error instalando $name${NC}"
    fi
    echo ""
}

# ═══════════════════════════════════════════════════════════════════════════════
# Dependencias Python
# ═══════════════════════════════════════════════════════════════════════════════

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🐍 DEPENDENCIAS PYTHON"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

pip install --upgrade pip

# Requerimientos base
pip install aiohttp pyyaml

# ═══════════════════════════════════════════════════════════════════════════════
# Source World
# ═══════════════════════════════════════════════════════════════════════════════

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔷 SOURCE WORLD"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Slither
install_tool "Slither" "pip install slither-analyzer"

# Echidna (requiere binario)
echo -e "${YELLOW}▶ Instalando Echidna...${NC}"
if command -v echidna &> /dev/null; then
    echo -e "${GREEN}✓ Echidna ya instalado${NC}"
else
    echo "  Descargando Echidna..."
    # Linux x86_64
    ECHIDNA_VERSION="2.2.3"
    wget -q "https://github.com/crytic/echidna/releases/download/v${ECHIDNA_VERSION}/echidna-${ECHIDNA_VERSION}-Linux.zip" -O /tmp/echidna.zip
    unzip -q /tmp/echidna.zip -d /tmp/echidna
    sudo mv /tmp/echidna/echidna /usr/local/bin/
    rm -rf /tmp/echidna /tmp/echidna.zip
    echo -e "${GREEN}✓ Echidna instalado${NC}"
fi
echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# Bytecode World
# ═══════════════════════════════════════════════════════════════════════════════

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔶 BYTECODE WORLD"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Mythril
install_tool "Mythril" "pip install mythril"

# Manticore
install_tool "Manticore" "pip install 'manticore[native]'"

# Hevm (requiere binario o nix)
echo -e "${YELLOW}▶ Instalando Hevm...${NC}"
if command -v hevm &> /dev/null; then
    echo -e "${GREEN}✓ Hevm ya instalado${NC}"
else
    echo "  Hevm requiere Nix o instalación manual."
    echo "  Opciones:"
    echo "    1. Usar Nix: nix-env -i hevm"
    echo "    2. Descargar binario de: https://github.com/ethereum/hevm/releases"
    echo -e "${YELLOW}⚠ Hevm no instalado automáticamente${NC}"
fi
echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# Human Bridge
# ═══════════════════════════════════════════════════════════════════════════════

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔍 HUMAN BRIDGE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Panoramix
install_tool "Panoramix" "pip install panoramix-decompiler"

# ═══════════════════════════════════════════════════════════════════════════════
# Solidity Compiler
# ═══════════════════════════════════════════════════════════════════════════════

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "⚙️ COMPILADOR SOLIDITY"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# solc-select para múltiples versiones
install_tool "solc-select" "pip install solc-select"

# Instalar versiones comunes de solc
echo -e "${YELLOW}▶ Instalando versiones de Solidity...${NC}"
solc-select install 0.8.20 || true
solc-select install 0.8.19 || true
solc-select install 0.7.6 || true
solc-select install 0.6.12 || true
solc-select use 0.8.20 || true
echo -e "${GREEN}✓ Versiones de Solidity instaladas${NC}"
echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# Verificación final
# ═══════════════════════════════════════════════════════════════════════════════

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ VERIFICACIÓN FINAL"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

check_tool() {
    local name=$1
    local cmd=$2
    if command -v $cmd &> /dev/null; then
        echo -e "  ${GREEN}✓${NC} $name"
    else
        echo -e "  ${RED}✗${NC} $name"
    fi
}

echo ""
echo "Herramientas instaladas:"
check_tool "Slither" "slither"
check_tool "Echidna" "echidna"
check_tool "Mythril" "myth"
check_tool "Manticore" "manticore"
check_tool "Hevm" "hevm"
check_tool "Panoramix" "panoramix"
check_tool "Solc" "solc"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🎉 Instalación completada!"
echo ""
echo "Ejecuta 'python sentinel.py check-tools' para verificar."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
