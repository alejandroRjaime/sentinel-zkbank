# 🛠️ **Guía de Instalación para Laboratorio de Investigación**

## 📋 **Requisitos del Sistema**

### **Mínimos:**
- **CPU**: 4+ núcleos (Intel i5/Ryzen 5 o superior)
- **RAM**: 16 GB mínimo (32 GB recomendado)
- **Disco**: 100 GB SSD libre
- **SO**: Ubuntu 20.04+ / macOS 11+ / WSL2 en Windows

### **Recomendados para Tesis:**
- **CPU**: 8+ núcleos
- **RAM**: 32 GB
- **Disco**: 500 GB NVMe SSD
- **GPU**: No requerida (los circuitos son CPU-bound)
- **Red**: Conexión estable (para descargar trusted setups)

---

## 🚀 **Instalación Paso a Paso**

### **1. Instalar Sistema Base**

#### **Ubuntu/Debian:**
```bash
# Actualizar sistema
sudo apt update && sudo apt upgrade -y

# Instalar herramientas esenciales
sudo apt install -y \
    build-essential \
    curl \
    git \
    wget \
    libgmp-dev \
    libssl-dev \
    pkg-config \
    libusb-1.0-0-dev \
    libpq-dev \
    libsqlite3-dev
```

#### **macOS:**
```bash
# Instalar Homebrew si no está
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Instalar dependencias
brew install \
    gmp \
    openssl \
    pkg-config \
    libusb
```

#### **Windows (WSL2):**
```powershell
# En PowerShell como Administrador
wsl --install -d Ubuntu

# Luego dentro de WSL, seguir instrucciones de Ubuntu
```

### **2. Instalar Node.js y NPM**

```bash
# Instalar Node Version Manager (NVM)
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash

# Recargar shell
source ~/.bashrc  # o ~/.zshrc

# Instalar Node.js LTS
nvm install 18
nvm use 18
nvm alias default 18

# Verificar instalación
node --version  # Debe mostrar v18.x.x
npm --version   # Debe mostrar 9.x.x o superior
```

### **3. Instalar Rust (requerido para Circom)**

```bash
# Instalar Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Seleccionar opción 1 (instalación por defecto)
source $HOME/.cargo/env

# Verificar instalación
rustc --version
cargo --version

# Configurar para nightly (algunas herramientas lo requieren)
rustup toolchain install nightly
rustup default nightly
```

### **4. Instalar Circom y SnarkJS**

```bash
# Instalar circom desde source
git clone https://github.com/iden3/circom.git
cd circom
cargo build --release
cargo install --path circom

# Verificar instalación
circom --version  # Debe mostrar 2.1.5+

# Instalar snarkjs globalmente
npm install -g snarkjs

# Verificar instalación
snarkjs --version

# Instalar circomlib (biblioteca estándar)
git clone https://github.com/iden3/circomlib.git
cd circomlib
npm install
```

### **5. Instalar Ethereum Development Tools**

```bash
# Instalar Foundry (para testing Solidity)
curl -L https://foundry.paradigm.xyz | bash
source ~/.bashrc
foundryup

# Verificar
forge --version
cast --version
anvil --version

# Instalar Hardhat (alternativa)
npm install -g hardhat

# Instalar Ganache (para blockchain local)
npm install -g ganache

# Instalar ethers.js y web3.js
npm install -g ethers web3
```

### **6. Instalar Python y Herramientas de Análisis**

```bash
# Instalar Python 3.10+
sudo apt install -y python3.10 python3-pip python3-venv

# Crear entorno virtual para análisis
python3 -m venv ~/zk-venv
source ~/zk-venv/bin/activate

# Instalar bibliotecas de análisis
pip install numpy pandas matplotlib seaborn jupyter notebook
pip install z3-solver  # Para verificación formal

# Para análisis de constraints
pip install networkx sympy
```

### **7. Instalar Docker (opcional pero recomendado)**

```bash
# Para Ubuntu
sudo apt install -y docker.io docker-compose
sudo systemctl enable docker
sudo systemctl start docker
sudo usermod -aG docker $USER

# Para macOS: descargar Docker Desktop desde docker.com
# Para Windows: usar Docker Desktop con WSL2 backend

# Verificar
docker --version
docker-compose --version
```

---

## 📦 **Configurar el Proyecto de Tesis**

### **1. Clonar y Configurar**

```bash
# Crear directorio de trabajo
mkdir ~/zk-thesis-lab
cd ~/zk-thesis-lab

# Clonar el proyecto (o copiar los archivos que te di)
git clone <tu-repositorio> zk-banking-system
cd zk-banking-system

# Instalar dependencias Node.js del proyecto
npm install

# Instalar dependencias adicionales
npm install --save-dev \
    @types/node \
    typescript \
    ts-node \
    chai \
    mocha \
    eslint \
    prettier \
    @types/chai \
    @types/mocha
```

### **2. Configurar Variables de Entorno**

```bash
# Crear archivo .env
cat > .env << 'EOF'
# Configuración del Proyecto
NODE_ENV=development
LOG_LEVEL=debug

# Rutas de Circuitos
CIRCUITS_DIR=./circuits
BUILD_DIR=./build
CONTRACTS_DIR=./contracts

# Configuración de Blockchain
ETHEREUM_RPC_URL=https://eth-goerli.g.alchemy.com/v2/YOUR_KEY
ETHERSCAN_API_KEY=YOUR_KEY

# Trusted Setup (puedes usar públicos)
POWERS_OF_TAU_URL=https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_20.ptau

# Testing
TEST_PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
EOF

# Crear archivo .env.local para configuraciones personales
cp .env .env.local
```

### **3. Estructura de Directorios Final**

```bash
# Verificar que tienes esta estructura
tree -L 3 -I 'node_modules|build'

# Deberías ver:
zk-banking-system/
├── circuits/
├── contracts/
├── lib/
├── scripts/
├── test/
├── docs/
├── benchmarks/
├── package.json
├── circuit.config.json
└── .env
```

---

## 🧪 **Script de Verificación de Instalación**

Crea este archivo para verificar que todo está correctamente instalado:

```bash
cat > verify_installation.sh << 'EOF'
#!/bin/bash

echo "🔍 Verificando instalación para tesis ZK-SNARK..."
echo "================================================"

# Colores
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

check_tool() {
    if command -v $1 &> /dev/null; then
        echo -e "${GREEN}✅ $1 instalado${NC} ($($1 --version 2>/dev/null | head -n 1))"
        return 0
    else
        echo -e "${RED}❌ $1 NO instalado${NC}"
        return 1
    fi
}

echo -e "\n${YELLOW}1. Herramientas Base:${NC}"
check_tool node
check_tool npm
check_tool git
check_tool curl

echo -e "\n${YELLOW}2. Herramientas ZK-SNARK:${NC}"
check_tool circom
check_tool snarkjs
check_tool rustc
check_tool cargo

echo -e "\n${YELLOW}3. Herramientas Blockchain:${NC}"
check_tool forge
check_tool hardhat || echo -e "${YELLOW}⚠️  Hardhat opcional${NC}"
check_tool ganache || echo -e "${YELLOW}⚠️  Ganache opcional${NC}"

echo -e "\n${YELLOW}4. Dependencias del Proyecto:${NC}"
if [ -d "node_modules" ]; then
    echo -e "${GREEN}✅ node_modules encontrado${NC}"
else
    echo -e "${YELLOW}⚠️  node_modules no encontrado, ejecuta: npm install${NC}"
fi

echo -e "\n${YELLOW}5. Espacio en Disco:${NC}"
df -h . | tail -1 | awk '{print "Disponible: " $4 " en " $1}'

echo -e "\n${YELLOW}6. Memoria RAM:${NC}"
free -h | awk 'NR==2{print "Disponible: " $7 " de " $2}'

echo -e "\n${YELLOW}7. CPU:${NC}"
lscpu | grep "Model name" | cut -d: -f2 | xargs

echo -e "\n================================================"
echo "Si ves ${RED}❌${NC}, instala esas herramientas primero."
echo "Si todo es ${GREEN}✅${NC}, estás listo para comenzar!"
EOF

chmod +x verify_installation.sh
./verify_installation.sh
```

---

## 🚦 **Primeros Pasos - Demostración Rápida**

### **1. Test Básico de Circuito Simple**

```bash
# Crear un circuito de prueba simple
cat > test_circuit.circom << 'EOF'
pragma circom 2.1.5;

template Multiplier() {
    signal input a;
    signal input b;
    signal output c;
    
    c <== a * b;
}

component main = Multiplier();
EOF

# Compilar
circom test_circuit.circom --r1cs --wasm --sym

# Verificar que se crearon los archivos
ls -la multiplier.*

# Ver información del circuito
snarkjs r1cs info multiplier.r1cs
```

### **2. Test de Instalación Completa**

```bash
# Ejecutar script de test completo
cat > test_full_installation.sh << 'EOF'
#!/bin/bash

echo "🧪 Test Completo de Instalación"
echo "================================"

set -e

# 1. Crear circuito de prueba
echo "1. Creando circuito de prueba..."
cat > test.circom << 'CIRCUIT'
pragma circom 2.1.5;

include "../node_modules/circomlib/circuits/comparators.circom";

template SimpleTest() {
    signal input a;
    signal input b;
    signal output isEqual;
    
    component eq = IsEqual();
    eq.in[0] <== a;
    eq.in[1] <== b;
    
    isEqual <== eq.out;
}

component main = SimpleTest();
CIRCUIT

# 2. Compilar
echo "2. Compilando circuito..."
circom test.circom --r1cs --wasm --sym --O1

# 3. Generar inputs de prueba
echo "3. Generando inputs..."
cat > input.json << 'INPUT'
{
    "a": "5",
    "b": "5"
}
INPUT

# 4. Generar witness
echo "4. Generando witness..."
node test_js/generate_witness.js test_js/test.wasm input.json witness.wtns

# 5. Verificar witness
echo "5. Verificando witness..."
snarkjs wtns check test.r1cs witness.wtns

echo "✅ Todos los tests pasaron!"
echo "================================"
echo "Instalación completa y funcional."
EOF

chmod +x test_full_installation.sh
./test_full_installation.sh
```

---

## 📚 **Entorno de Desarrollo Configurado**

### **Visual Studio Code (Recomendado)**

```bash
# Instalar VS Code
# Ubuntu: sudo snap install code --classic
# macOS: brew install --cask visual-studio-code
# Windows: descargar desde code.visualstudio.com

# Extensiones esenciales:
code --install-extension dbaeumer.vscode-eslint
code --install-extension esbenp.prettier-vscode
code --install-extension rust-lang.rust-analyzer
code --install-extension juanblanco.solidity
code --install-extension circlesystems.circom
code --install-extension ms-python.python
code --install-extension eg2.vscode-npm-script
```

### **Configuración de VS Code (.vscode/settings.json)**

```json
{
    "editor.formatOnSave": true,
    "editor.codeActionsOnSave": {
        "source.fixAll.eslint": true
    },
    "files.exclude": {
        "**/node_modules": true,
        "**/build": false,
        "**/.git": true
    },
    "solidity.packageDefaultDependenciesDirectory": "node_modules",
    "solidity.packageDefaultDependenciesContractsDirectory": "src",
    "[circom]": {
        "editor.formatOnSave": true
    },
    "circom.compilerPath": "circom",
    "circom.snarkjsPath": "snarkjs"
}
```

---

## 🐳 **Opción: Usar Docker (Recomendado para Consistencia)**

Si quieres un entorno completamente reproducible:

### **Dockerfile para Tesis:**

```dockerfile
FROM ubuntu:22.04

# Evitar prompts durante la instalación
ENV DEBIAN_FRONTEND=noninteractive

# Instalar dependencias del sistema
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    wget \
    libgmp-dev \
    libssl-dev \
    pkg-config \
    libusb-1.0-0-dev \
    software-properties-common \
    python3.10 \
    python3-pip \
    python3-venv \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

# Instalar Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Instalar Foundry
RUN curl -L https://foundry.paradigm.xyz | bash
ENV PATH="/root/.foundry/bin:${PATH}"
RUN foundryup

# Instalar circom
RUN cargo install circom --version 2.1.5

# Instalar snarkjs
RUN npm install -g snarkjs

# Crear usuario no-root
RUN useradd -m -s /bin/bash researcher
USER researcher
WORKDIR /home/researcher/workspace

# Copiar proyecto
COPY --chown=researcher:researcher . .

# Instalar dependencias del proyecto
RUN npm install

CMD ["/bin/bash"]
```

### **docker-compose.yml:**

```yaml
version: '3.8'

services:
  zk-lab:
    build: .
    container_name: zk-thesis-lab
    volumes:
      - ./:/home/researcher/workspace
      - ./data:/home/researcher/data
    ports:
      - "3000:3000"  # Para frontend
      - "8545:8545"  # Para Ganache
      - "8888:8888"  # Para Jupyter
    stdin_open: true
    tty: true
    command: /bin/bash
```

### **Uso:**
```bash
# Construir imagen
docker-compose build

# Iniciar contenedor
docker-compose up -d

# Entrar al contenedor
docker-compose exec zk-lab bash

# Dentro del contenedor, todo está instalado
circom --version
snarkjs --version
forge --version
```

---

## 🔧 **Troubleshooting Común**

### **Problema 1: Circom no se instala**
```bash
# Si falla la instalación de Circom:
rustup update
cargo clean
cargo install circom --version 2.1.5 --force
```

### **Problema 2: Errores de memoria**
```bash
# Aumentar memoria para Node.js
export NODE_OPTIONS="--max-old-space-size=8192"

# Para compilaciones grandes
export RUSTFLAGS="-C target-cpu=native"
```

### **Problema 3: Trusted setup grande**
```bash
# Usar powersOfTau más pequeño para testing
wget https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_12.ptau

# O usar PLONK que no necesita trusted setup grande
snarkjs plonk setup circuit.r1cs powersOfTau.ptau circuit.zkey
```

---

## 📊 **Checklist de Instalación para Tesis**

```markdown
# ✅ CHECKLIST DE INSTALACIÓN COMPLETA

## Herramientas Base
- [ ] Node.js v18+ y NPM
- [ ] Git
- [ ] Rust y Cargo
- [ ] Python 3.10+

## Herramientas ZK-SNARK
- [ ] Circom 2.1.5+
- [ ] SnarkJS 0.6+
- [ ] circomlib

## Herramientas Blockchain
- [ ] Foundry (forge, cast, anvil)
- [ ] Hardhat (opcional)
- [ ] Ganache (opcional)

## Entorno de Desarrollo
- [ ] VS Code con extensiones
- [ ] Docker (opcional pero recomendado)
- [ ] Jupyter Notebook para análisis

## Verificación
- [ ] Circuito simple compila
- [ ] Generación de witness funciona
- [ ] Prueba de contrato básica
- [ ] Scripts de testing ejecutan

## Optimización
- [ ] Variables de entorno configuradas
- [ ] Aliases útiles en .bashrc
- [ ] Espacio en disco suficiente (> 50GB)
```

---

## 🎯 **Comandos Aliases Útiles**

Agrega a tu `~/.bashrc` o `~/.zshrc`:

```bash
# Aliases para tesis ZK
alias zk-compile='npm run compile'
alias zk-test='npm test'
alias zk-bench='npm run benchmark'
alias zk-deploy='npm run deploy:local'
alias zk-clean='rm -rf build/* && npm run clean'
alias zk-docker='docker-compose up -d && docker-compose logs -f'
alias zk-circuit-info='snarkjs r1cs info'
alias zk-ptau-dl='wget https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_20.ptau'

# Función para compilar y probar rápido
zk-quick-test() {
    circom $1 --r1cs --wasm --sym --O1
    echo "✅ Circuito compilado"
    snarkjs r1cs info ${1%.circom}.r1cs
}
```

---

## 📈 **Recursos Adicionales para la Tesis**

### **Datasets para Testing:**
```bash
# Crear dataset de prueba
python3 -c "
import json
import random

data = {
    'deposits': [random.randint(100, 10000) for _ in range(100)],
    'withdrawals': [random.randint(10, 5000) for _ in range(50)],
    'fees': [random.uniform(0.001, 0.1) for _ in range(50)]
}

with open('test_dataset.json', 'w') as f:
    json.dump(data, f, indent=2)
print('Dataset creado: test_dataset.json')
"
```

### **Plantilla de Jupyter Notebook para Análisis:**

```python
# analysis.ipynb
import json
import matplotlib.pyplot as plt
import pandas as pd

# Cargar resultados de benchmarks
with open('build/benchmark_results.json') as f:
    data = json.load(f)

# Crear análisis comparativo
df = pd.DataFrame(data['circuits'])
print(df.describe())

# Gráficos para tesis
fig, axes = plt.subplots(2, 2, figsize=(12, 10))
df.plot(kind='bar', ax=axes[0,0], title='Comparación de Constraints')
# ... más análisis
```

---

## 🚨 **Si Tienes Problemas de Instalación**

### **Solución Nuclear: Script de Instalación Automática**

```bash
cat > install_everything.sh << 'EOF'
#!/bin/bash
# Script de instalación completa - USAR CON CUIDADO

set -e
echo "🚀 Instalación automática completa para tesis ZK"

# Función para verificar e instalar
install_if_missing() {
    if ! command -v $1 &> /dev/null; then
        echo "Instalando $1..."
        eval "$2"
    else
        echo "✅ $1 ya instalado"
    fi
}

# 1. Actualizar sistema
sudo apt update && sudo apt upgrade -y

# 2. Instalar herramientas base
install_if_missing node "curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash && source ~/.bashrc && nvm install 18"

# 3. Instalar Rust y Circom
install_if_missing rustc "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"
source $HOME/.cargo/env
install_if_missing circom "cargo install circom --version 2.1.5"

# 4. Instalar Foundry
install_if_missing forge "curl -L https://foundry.paradigm.xyz | bash && source ~/.bashrc && foundryup"

# 5. Instalar snarkjs
npm install -g snarkjs

echo "🎉 Instalación completa! Por favor reinicia tu terminal."
EOF

chmod +x install_everything.sh
# ./install_everything.sh  # Solo si es necesario
```

---

## ✅ **Verificación Final**

Ejecuta este comando para verificar que todo está listo:

```bash
echo "🧪 VERIFICACIÓN FINAL DEL LABORATORIO"

# Test 1: Compilar circuito de depósito
cd ~/zk-thesis-lab/zk-banking-system
npm run compile 2>&1 | grep -i "error" || echo "✅ Compilación OK"

# Test 2: Ejecutar tests básicos
npm test -- --grep "basic" 2>&1 | tail -5

# Test 3: Verificar herramientas
echo "Herramientas instaladas:"
echo "- Node: $(node --version)"
echo "- Circom: $(circom --version)"
echo "- SnarkJS: $(snarkjs --version)"
echo "- Forge: $(forge --version)"

echo ""
echo "🎓 ¡Laboratorio listo para investigación!"
echo "Puedes comenzar con:"
echo "1. npm run compile    # Compilar circuitos"
echo "2. npm test           # Ejecutar tests"
echo "3. npm run benchmark  # Medir performance"
echo "4. npm run deploy:local # Desplegar localmente"
```

---

**Con esto tendrás un laboratorio completo para trabajar en tu tesis.** ¿Te gustaría que detalle algún aspecto específico de la instalación o que cree algún script adicional?