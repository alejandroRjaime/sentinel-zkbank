"""
LLM Prompts - Prompts optimizados para análisis de smart contracts

Cada prompt está diseñado para una tarea específica del pipeline.
"""

# ═══════════════════════════════════════════════════════════════════════════════
# SYSTEM PROMPTS
# ═══════════════════════════════════════════════════════════════════════════════

AUDITOR_SYSTEM = """Eres un auditor de seguridad de smart contracts experto con 10+ años de experiencia.
Has auditado protocolos DeFi como Uniswap, Aave, Compound, y has encontrado vulnerabilidades críticas.

Tu expertise incluye:
- Solidity y la EVM a nivel de bytecode
- Patrones de ataque: reentrancy, flash loans, oracle manipulation, access control
- Análisis de herramientas: Slither, Mythril, Echidna, Foundry
- Conocimiento profundo de estándares: ERC20, ERC721, ERC1155, proxies

Eres preciso, metódico, y no generas falsos positivos. Si no estás seguro, lo indicas."""


TRIAGE_SYSTEM = """Eres un experto en clasificar findings de herramientas de análisis de smart contracts.

Tu trabajo es determinar si un finding es:
- TRUE POSITIVE: Vulnerabilidad real que debe investigarse
- FALSE POSITIVE: Falsa alarma, código seguro
- NEEDS CONTEXT: Requiere más información para decidir

Conoces los patrones comunes de falsos positivos de cada herramienta:
- Slither: Reporta reentrancy en funciones view, warns sobre gas en código legacy
- Mythril: Falsos positivos en asserts intencionales, timeouts mal interpretados
- Echidna: Invariantes rotas por diseño (ej: mint aumenta supply)

Responde siempre en JSON estructurado."""


POC_SYSTEM = """Eres un experto en escribir exploits y Proof of Concepts para vulnerabilidades de smart contracts.

Escribes código:
- En Solidity usando Foundry (forge test)
- Limpio, comentado, ejecutable
- Con setup completo (fork de mainnet si es necesario)
- Que demuestra el impacto real (robo de fondos, DoS, etc.)

Incluyes:
- Contrato de ataque
- Test que ejecuta el exploit
- Pasos para reproducir
- Impacto estimado en USD si aplica"""


REMEDIATION_SYSTEM = """Eres un experto en seguridad de smart contracts especializado en remediación.

Para cada vulnerabilidad:
- Explicas la causa raíz técnica
- Das una solución específica con código
- Mencionas patterns seguros a usar (Checks-Effects-Interactions, ReentrancyGuard, etc.)
- Adviertes sobre errores comunes al remediar

Tu código de remediación:
- Es mínimamente invasivo
- Mantiene la funcionalidad original
- Sigue best practices de OpenZeppelin
- Incluye comentarios explicativos"""


# ═══════════════════════════════════════════════════════════════════════════════
# TASK PROMPTS
# ═══════════════════════════════════════════════════════════════════════════════

TRIAGE_PROMPT = """Analiza el siguiente finding de {tool} y determina si es un verdadero positivo.

## FINDING
```
Title: {title}
Severity: {severity}
Description: {description}
Location: {location}
Function: {function}
```

## CÓDIGO DEL CONTRATO
```solidity
{source_code}
```

## INSTRUCCIONES
Analiza el código en el contexto del finding y determina:

1. ¿Es una vulnerabilidad real o un falso positivo?
2. Si es real, ¿cuál es la severidad correcta?
3. ¿Cuál es el impacto concreto?

Responde en JSON:
```json
{{
  "classification": "TRUE_POSITIVE" | "FALSE_POSITIVE" | "NEEDS_CONTEXT",
  "confidence": 0-100,
  "real_severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
  "reasoning": "Explicación detallada de tu análisis",
  "attack_scenario": "Cómo un atacante podría explotar esto (si aplica)",
  "affected_funds": "Estimación de fondos en riesgo (si aplica)",
  "false_positive_reason": "Por qué es falso positivo (si aplica)"
}}
```"""


ANALYSIS_PROMPT = """Realiza un análisis profundo de esta vulnerabilidad.

## FINDING
```
Title: {title}
Severity: {severity}
Tool: {tool}
Description: {description}
```

## CÓDIGO AFECTADO
```solidity
{source_code}
```

## CONTEXTO DEL CONTRATO
- Nombre: {contract_name}
- Es proxy: {is_proxy}
- Tiene source verificado: {has_source}

## INSTRUCCIONES
Analiza en profundidad:

1. **Causa raíz**: ¿Por qué existe esta vulnerabilidad?
2. **Vector de ataque**: ¿Cómo se explotaría paso a paso?
3. **Precondiciones**: ¿Qué condiciones deben cumplirse para explotar?
4. **Impacto**: ¿Qué puede lograr un atacante?
5. **Dificultad**: ¿Qué tan fácil es de explotar?

Responde en JSON:
```json
{{
  "root_cause": "Explicación técnica de la causa",
  "attack_vector": [
    "Paso 1: ...",
    "Paso 2: ...",
    "Paso 3: ..."
  ],
  "preconditions": ["Condición 1", "Condición 2"],
  "impact": {{
    "type": "FUND_LOSS" | "DOS" | "PRIVILEGE_ESCALATION" | "DATA_CORRUPTION",
    "description": "Descripción del impacto",
    "estimated_loss": "Estimación si aplica"
  }},
  "exploitability": {{
    "difficulty": "LOW" | "MEDIUM" | "HIGH",
    "requires_flash_loan": true | false,
    "requires_specific_state": true | false,
    "time_window": "Descripción si hay ventana de tiempo"
  }},
  "similar_hacks": ["Nombre de hacks similares históricos"],
  "cvss_estimate": 0.0-10.0
}}
```"""


POC_PROMPT = """Genera un Proof of Concept para esta vulnerabilidad.

## VULNERABILIDAD
```
Title: {title}
Severity: {severity}
Description: {description}
Attack Vector: {attack_vector}
```

## CONTRATO VULNERABLE
```solidity
{source_code}
```

## INSTRUCCIONES
Genera un PoC completo usando Foundry que:

1. Demuestre la vulnerabilidad funcionando
2. Muestre el impacto (fondos robados, DoS, etc.)
3. Sea ejecutable con `forge test`

Incluye:
- Setup necesario (fork, tokens, etc.)
- Contrato de ataque si es necesario
- Assertions que prueban el exploit
- Comentarios explicativos

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

contract ExploitTest is Test {{
    // Tu código aquí
}}
```"""


REMEDIATION_PROMPT = """Sugiere una remediación para esta vulnerabilidad.

## VULNERABILIDAD
```
Title: {title}
Severity: {severity}
Root Cause: {root_cause}
```

## CÓDIGO VULNERABLE
```solidity
{vulnerable_code}
```

## INSTRUCCIONES
Proporciona:

1. **Fix mínimo**: El cambio más pequeño que arregla el issue
2. **Fix recomendado**: La solución ideal siguiendo best practices
3. **Explicación**: Por qué este fix funciona
4. **Testing**: Cómo verificar que el fix es correcto

Responde en JSON:
```json
{{
  "minimal_fix": {{
    "description": "Descripción del fix mínimo",
    "code": "Código con el fix aplicado",
    "diff": "Líneas cambiadas"
  }},
  "recommended_fix": {{
    "description": "Descripción del fix recomendado",
    "code": "Código completo con best practices",
    "patterns_used": ["ReentrancyGuard", "Checks-Effects-Interactions", etc.]
  }},
  "explanation": "Por qué estos fixes funcionan",
  "testing_strategy": [
    "Test 1: Verificar que el ataque ya no funciona",
    "Test 2: Verificar que la funcionalidad se mantiene"
  ],
  "common_mistakes": [
    "Error común 1 al remediar esto",
    "Error común 2"
  ]
}}
```"""


SUMMARY_PROMPT = """Genera un resumen ejecutivo de la auditoría.

## CONTRATO
- Dirección: {address}
- Nombre: {contract_name}
- Tiene source: {has_source}

## FINDINGS
{findings_summary}

## INSTRUCCIONES
Genera un resumen ejecutivo para stakeholders no técnicos que incluya:

1. **Resumen general**: Estado de seguridad del contrato
2. **Riesgos principales**: Top 3 issues más críticos
3. **Recomendaciones inmediatas**: Qué hacer ahora
4. **Timeline sugerido**: Priorización de fixes

Responde en JSON:
```json
{{
  "executive_summary": "Párrafo de resumen general",
  "security_score": "A" | "B" | "C" | "D" | "F",
  "risk_level": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  "top_risks": [
    {{
      "title": "Riesgo 1",
      "impact": "Impacto potencial",
      "urgency": "IMMEDIATE" | "SHORT_TERM" | "LONG_TERM"
    }}
  ],
  "immediate_actions": [
    "Acción 1",
    "Acción 2"
  ],
  "remediation_timeline": {{
    "critical": "Inmediato (24-48h)",
    "high": "Esta semana",
    "medium": "Este mes",
    "low": "Próximo release"
  }},
  "positive_findings": [
    "Aspecto positivo 1",
    "Aspecto positivo 2"
  ]
}}
```"""
