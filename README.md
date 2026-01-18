# 🛡️ Sentinel Engine v2.0

**Smart Contract Security Analyzer - Stack Híbrido de Dos Mundos**

> *"El .sol explica la intención. El bytecode prueba la realidad."*

---

## 📋 Índice

- [Filosofía](#-filosofía)
- [Stack Híbrido](#-stack-híbrido)
- [Instalación](#-instalación)
- [Uso Rápido](#-uso-rápido)
- [Modos de Análisis](#-modos-de-análisis)
- [Arquitectura](#-arquitectura)
- [Reportes](#-reportes)

---

## 🧠 Filosofía

El código fuente (.sol) y el bytecode representan **dos verdades diferentes**:

| Mundo | Representa | Herramientas |
|-------|------------|--------------|
| **Source** | Lo que el desarrollador *quiso* escribir | Slither, Echidna |
| **Bytecode** | Lo que *realmente* se ejecuta | Mythril, Manticore, Hevm |

Un bug puede existir en uno y no en el otro. Un auditor serio usa ambos, pero **confía en el bytecode**.

---

## ✅ Stack Híbrido

```
┌─────────────────────────────────────────────────────────────────┐
│                      CONTRATO A ANALIZAR                        │
└─────────────────────────────┬───────────────────────────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  ¿Tiene .sol verificado?                                        │
│     SÍ  → 🔷 Slither + Echidna (paralelo)                       │
│     NO  → Skip                                                  │
├─────────────────────────────────────────────────────────────────┤
│  SIEMPRE → 🔶 Mythril + Manticore + Hevm (paralelo)             │
├─────────────────────────────────────────────────────────────────┤
│  Validación → ✅ Erigon traces (ground truth histórico)         │
├─────────────────────────────────────────────────────────────────┤
│  LLM Pipeline → 🤖 Filtrar FP + Análisis + PoCs + Fixes         │
├─────────────────────────────────────────────────────────────────┤
│  Si necesita review → 🔍 Panoramix (decompile)                  │
└─────────────────────────────────────────────────────────────────┘
```

### 🤖 LLM Pipeline (Nuevo)

El pipeline de LLM agrega inteligencia artificial al análisis:

| Agente | Función |
|--------|---------|
| **TriageAgent** | Filtra falsos positivos de Slither/Mythril |
| **AnalysisAgent** | Análisis profundo de cada vulnerabilidad |
| **PoCAgent** | Genera Proof of Concepts ejecutables |
| **RemediationAgent** | Sugiere fixes con código |
| **SummaryAgent** | Genera resumen ejecutivo |

**Proveedores soportados:**
- Claude (Anthropic) - Recomendado
- GPT-4 (OpenAI)
- Ollama (Local)

Para activar:
```bash
# Configurar API key
export ANTHROPIC_API_KEY="sk-..."

# Activar en config/tools.yaml
llm:
  enabled: true
  provider: "claude"
```

### ❌ Qué NO incluye (y por qué)

| Herramienta | Razón |
|-------------|-------|
| Z3 | Ya viene embebido en Mythril/Manticore |
| Oyente | Redundante con Mythril |
| Securify | Redundante con Slither |
| Heimdall/Dedaub | Panoramix es suficiente |

---

## 🚀 Instalación

```bash
# 1. Clonar repositorio
git clone <repo>
cd sentinel-engine

# 2. Instalar herramientas
chmod +x install_tools.sh
./install_tools.sh

# 3. Verificar instalación
python sentinel.py check-tools
```

### Requisitos

- Python 3.9+
- Node.js (para algunas herramientas)
- Nodo Ethereum (Erigon recomendado para validación)

---

## 💻 Uso Rápido

```bash
# Análisis normal (recomendado)
python sentinel.py analyze 0x1234...

# Análisis rápido (solo Mythril)
python sentinel.py quick 0x1234...

# Análisis profundo (todo + decompilación)
python sentinel.py deep 0x1234... --txs 0xabc...,0xdef...

# Solo descargar contrato
python sentinel.py fetch 0x1234...

# Verificar herramientas
python sentinel.py check-tools
```

---

## 🎯 Modos de Análisis

| Modo | Herramientas | Tiempo | Uso |
|------|--------------|--------|-----|
| `quick` | Mythril | ~5 min | Escaneo rápido |
| `normal` | Slither + Echidna + Mythril + Hevm | ~15 min | Análisis estándar |
| `deep` | Todo + Manticore + Erigon + Panoramix | ~30+ min | Auditoría completa |

### Opciones

```bash
python sentinel.py analyze 0x... [opciones]

Opciones:
  --skip-fetch      Usar contrato cacheado
  --no-validate     Omitir validación con Erigon
  --decompile       Generar código decompilado
  --txs TX1,TX2     Transacciones específicas para validar
```

---

## 🏗️ Arquitectura

```
sentinel-engine/
├── sentinel.py              # CLI principal
├── config/
│   ├── tools.yaml           # Configuración de herramientas
│   └── ethereum.yaml        # Configuración de nodo
├── src/
│   ├── engine.py            # Motor híbrido principal
│   ├── analyzers/
│   │   ├── slither_analyzer.py    # 🔷 Source: bugs estructurales
│   │   ├── echidna_analyzer.py    # 🔷 Source: fuzzing
│   │   ├── mythril_analyzer.py    # 🔶 Bytecode: ejecución simbólica
│   │   ├── manticore_analyzer.py  # 🔶 Bytecode: paths profundos
│   │   └── hevm_analyzer.py       # 🔶 Bytecode: EVM exacto
│   ├── validators/
│   │   └── erigon_validator.py    # ✅ Ground truth
│   ├── decompilers/
│   │   └── panoramix_decompiler.py # 🔍 Puente humano
│   └── fetchers/
│       └── contract_fetcher.py    # Descarga contratos
├── contracts/               # Contratos descargados
├── reports/                 # Reportes generados
└── install_tools.sh         # Instalador
```

---

## 📊 Reportes

Los reportes se generan en `reports/{address}/`:

### JSON (`report.json`)

```json
{
  "address": "0x1234...",
  "has_source": true,
  "summary": {
    "risk_level": "HIGH",
    "risk_score": 15,
    "total_findings": 8,
    "severity_breakdown": {
      "critical": 1,
      "high": 2,
      "medium": 3,
      "low": 2
    }
  },
  "findings": [...]
}
```

### Markdown (`summary.md`)

Resumen legible con todos los findings detallados.

---

## 🔧 Configuración

### config/tools.yaml

```yaml
source_world:
  slither:
    enabled: true
    timeout: 300
  echidna:
    enabled: true
    timeout: 600

bytecode_world:
  mythril:
    enabled: true
    timeout: 900
  manticore:
    enabled: true
    timeout: 3600
  hevm:
    enabled: true
    timeout: 600

validation:
  erigon:
    enabled: true
    rpc_url: "http://localhost:8545"
```

### config/ethereum.yaml

```yaml
node:
  rpc_url: "http://localhost:8545"
  chain_id: 1

sources:
  sourcify:
    enabled: true
  etherscan:
    enabled: true
    api_key: "${ETHERSCAN_API_KEY}"
```

---

## 🧪 Flujo Mental Correcto

```python
if has_source:
    run_parallel(slither, echidna)  # Intención

run_parallel(mythril, manticore, hevm)  # Realidad (siempre)

validate_with(erigon_traces)  # Ground truth

if needs_human_review:
    panoramix_decompile()
```

---

## 📜 Licencia

MIT

---

<p align="center">
  <i>"El .sol explica la intención. El bytecode prueba la realidad."</i>
</p>
