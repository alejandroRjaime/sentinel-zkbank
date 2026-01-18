"""
LLM Attack Chain Agent - Detección de vulnerabilidades compuestas
Identifica cuando múltiples vulnerabilidades forman attack chains

ACTUALIZADO: Usa Finding, Severity, World de analyzers.base
"""

from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import hashlib

from .base import BaseLLMClient
from ..analyzers.base import Finding, Severity, World


class ChainType(Enum):
    """Tipos conocidos de attack chains"""
    CLASSIC_DAO = "classic_dao"
    FLASH_LOAN_ATTACK = "flash_loan_attack"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    PRICE_MANIPULATION = "price_manipulation"
    RUG_PULL = "rug_pull"
    GOVERNANCE_ATTACK = "governance_attack"
    ORACLE_MANIPULATION = "oracle_manipulation"
    UNKNOWN = "unknown"


@dataclass
class AttackChain:
    """Cadena de ataque detectada"""
    chain_type: ChainType
    name: str
    description: str
    components: List[Finding]  # Vulnerabilidades que forman la chain
    severity: Severity  # Severidad del chain completo (usualmente CRITICAL)
    exploitability: str  # "easy", "medium", "hard"
    attack_scenario: List[str]  # Pasos del ataque
    estimated_impact: str
    mitigation_priority: str  # "immediate", "high", "medium"
    real_world_examples: List[str] = field(default_factory=list)
    

@dataclass
class ChainDetectionResult:
    """Resultado de detección de attack chains"""
    chains_found: List[AttackChain]
    enhanced_findings: List[Finding]  # Findings marcados como parte de chains
    risk_score: float  # 0.0-10.0


ATTACK_CHAIN_SYSTEM = """Eres un experto en ataques a smart contracts y DeFi con conocimiento profundo de:

1. Ataques históricos famosos:
   - The DAO (2016) - Reentrancy + unchecked returns
   - Poly Network (2021) - Access control + cross-chain
   - Wormhole (2022) - Signature verification + bridge exploit
   - Cream Finance (2021) - Flash loan + reentrancy

2. Patrones de attack chains comunes:
   - Flash loan attacks (capital-free attacks)
   - Oracle manipulation chains
   - Governance attacks multi-paso
   - Cross-function reentrancy chains

3. Vectores de ataque compuestos:
   - Precondiciones necesarias
   - Orden de ejecución
   - Interdependencias entre vulnerabilidades

Tu tarea es identificar cuando múltiples vulnerabilidades pueden combinarse
para crear un ataque más severo que la suma de sus partes."""


CHAIN_DETECTION_PROMPT = """Analiza estas vulnerabilidades y determina si forman un ATTACK CHAIN.

## VULNERABILIDADES DETECTADAS

{findings_summary}

## CÓDIGO DEL CONTRATO

```solidity
{code_snippet}
```

## INSTRUCCIONES

Un attack chain existe cuando:
1. Múltiples vulnerabilidades pueden combinarse en un ataque multi-paso
2. El impacto combinado es mayor que vulnerabilidades individuales
3. Existe un orden lógico de explotación

Patrones conocidos a buscar:
- Reentrancy + Unchecked return → Classic DAO
- Flash loan capability + Price manipulation → Flash loan attack
- Access control flaw + Delegatecall → Privilege escalation
- Oracle dependency + Market manipulation → Oracle attack
- Multiple admin functions + Ownership transfer → Rug pull

Responde en JSON:
```json
{{
  "chain_detected": true/false,
  "chain_type": "classic_dao" | "flash_loan_attack" | "privilege_escalation" | "unknown",
  "chain_name": "Nombre descriptivo del chain",
  "confidence": 0-100,
  "reasoning": "Por qué estas vulnerabilidades forman un chain",
  "attack_scenario": [
    "Paso 1: Atacante hace X",
    "Paso 2: Aprovecha Y para Z",
    "Paso 3: Resultado final"
  ],
  "estimated_impact": "Descripción del impacto (ej: robo total de fondos)",
  "exploitability": "easy" | "medium" | "hard",
  "mitigation_priority": "immediate" | "high" | "medium",
  "requires_flash_loan": true/false,
  "capital_required": "Estimación de capital necesario",
  "real_world_example": "Nombre de ataque similar histórico (si aplica)"
}}
```"""


class AttackChainAgent:
    """
    Agente de Attack Chains - Detecta vulnerabilidades compuestas
    
    Identifica cuando múltiples findings pueden combinarse en ataques multi-paso.
    """
    
    def __init__(self, client: BaseLLMClient):
        self.client = client
        
        # Patrones conocidos de chains (heurísticas rápidas)
        self.known_patterns = {
            ChainType.CLASSIC_DAO: {
                "keywords": ["reentrancy", "unchecked", "external call"],
                "min_components": 2
            },
            ChainType.FLASH_LOAN_ATTACK: {
                "keywords": ["flash", "oracle", "price", "manipulation"],
                "min_components": 2
            },
            ChainType.PRIVILEGE_ESCALATION: {
                "keywords": ["access control", "delegatecall", "authorization", "admin"],
                "min_components": 2
            },
            ChainType.PRICE_MANIPULATION: {
                "keywords": ["oracle", "amm", "price", "swap"],
                "min_components": 2
            },
            ChainType.RUG_PULL: {
                "keywords": ["ownership", "pausable", "admin", "withdrawal"],
                "min_components": 2
            }
        }
    
    def _generate_finding_id(self, tool: str, title: str, location: str = "") -> str:
        """Genera un ID único para un finding"""
        content = f"{tool}:{title}:{location}"
        return hashlib.sha256(content.encode()).hexdigest()[:12]
    
    async def detect_chains(
        self,
        findings: List[Finding],
        source_code: Optional[str] = None
    ) -> ChainDetectionResult:
        """
        Detecta attack chains en los findings
        
        Args:
            findings: Lista de vulnerabilidades detectadas
            source_code: Código del contrato (opcional)
        
        Returns:
            ChainDetectionResult con chains detectados
        """
        
        if len(findings) < 2:
            # No puede haber chains con menos de 2 vulnerabilidades
            return ChainDetectionResult(
                chains_found=[],
                enhanced_findings=findings,
                risk_score=0.0
            )
        
        print(f"\n🔗 Attack Chain Detection: Analizando {len(findings)} findings...")
        
        # Paso 1: Heurísticas rápidas
        potential_chains = self._quick_pattern_match(findings)
        print(f"  → {len(potential_chains)} potential chains (heurística)")
        
        # Paso 2: Análisis profundo con LLM
        confirmed_chains = []
        for chain_type, component_findings in potential_chains:
            chain = await self._analyze_chain_with_llm(
                chain_type,
                component_findings,
                source_code
            )
            if chain:
                confirmed_chains.append(chain)
                print(f"  ✓ Chain detectado: {chain.name}")
        
        # Paso 3: Marcar findings como parte de chains
        enhanced_findings = self._enhance_findings_with_chain_info(
            findings,
            confirmed_chains
        )
        
        # Paso 4: Calcular risk score general
        risk_score = self._calculate_risk_score(confirmed_chains)
        
        if confirmed_chains:
            print(f"  ⚠️ CRITICAL: {len(confirmed_chains)} attack chains confirmados")
            print(f"  📊 Risk Score: {risk_score:.1f}/10.0")
        else:
            print(f"  ✓ No se detectaron attack chains")
        
        return ChainDetectionResult(
            chains_found=confirmed_chains,
            enhanced_findings=enhanced_findings,
            risk_score=risk_score
        )
    
    def _quick_pattern_match(
        self,
        findings: List[Finding]
    ) -> List[Tuple[ChainType, List[Finding]]]:
        """Búsqueda rápida de patrones conocidos usando heurísticas"""
        
        potential_chains = []
        
        for chain_type, pattern in self.known_patterns.items():
            # Buscar findings que matcheen keywords del pattern
            matching_findings = []
            
            for finding in findings:
                text = f"{finding.title} {finding.description}".lower()
                if any(keyword in text for keyword in pattern["keywords"]):
                    matching_findings.append(finding)
            
            # Si tenemos suficientes componentes, es un potential chain
            if len(matching_findings) >= pattern["min_components"]:
                potential_chains.append((chain_type, matching_findings))
        
        # Siempre analizar todas las vulnerabilidades juntas por si hay un chain desconocido
        if len(findings) >= 2 and not potential_chains:
            potential_chains.append((ChainType.UNKNOWN, findings))
        
        return potential_chains
    
    async def _analyze_chain_with_llm(
        self,
        chain_type: ChainType,
        component_findings: List[Finding],
        source_code: Optional[str]
    ) -> Optional[AttackChain]:
        """Analiza potential chain con LLM para confirmación"""
        
        # Formatear findings para el LLM
        findings_summary = "\n\n".join([
            f"Finding {i+1}: {f.title}\n"
            f"  Tool: {f.tool}\n"
            f"  Severity: {f.severity.value}\n"
            f"  Description: {f.description}\n"
            f"  Location: {f.location or 'N/A'}\n"
            f"  Function: {f.function or 'N/A'}"
            for i, f in enumerate(component_findings)
        ])
        
        code_snippet = source_code[:2000] if source_code else "No disponible"
        
        prompt = CHAIN_DETECTION_PROMPT.format(
            findings_summary=findings_summary,
            code_snippet=code_snippet
        )
        
        try:
            result = await self.client.complete_json(prompt, ATTACK_CHAIN_SYSTEM)
            
            # Si no se detectó chain, retornar None
            if not result.get("chain_detected", False):
                return None
            
            # Si confidence es bajo, retornar None
            if result.get("confidence", 0) < 60:
                return None
            
            # Determinar chain type
            try:
                detected_type = ChainType(result.get("chain_type", "unknown"))
            except ValueError:
                detected_type = ChainType.UNKNOWN
            
            # Crear AttackChain
            chain = AttackChain(
                chain_type=detected_type,
                name=result.get("chain_name", "Unknown Chain"),
                description=result.get("reasoning", ""),
                components=component_findings,
                severity=Severity.CRITICAL,  # Chains son típicamente críticos
                exploitability=result.get("exploitability", "medium"),
                attack_scenario=result.get("attack_scenario", []),
                estimated_impact=result.get("estimated_impact", "Unknown"),
                mitigation_priority=result.get("mitigation_priority", "high"),
                real_world_examples=[result.get("real_world_example", "")] if result.get("real_world_example") else []
            )
            
            return chain
            
        except Exception as e:
            print(f"  ⚠️ Error analizando chain: {e}")
            return None
    
    def _enhance_findings_with_chain_info(
        self,
        findings: List[Finding],
        chains: List[AttackChain]
    ) -> List[Finding]:
        """Marca findings que son parte de attack chains"""
        
        # Crear copias de findings para no modificar originales
        enhanced = []
        
        for finding in findings:
            # Verificar si este finding es parte de algún chain
            in_chain = False
            chain_names = []
            
            for chain in chains:
                if any(cf.id == finding.id for cf in chain.components):
                    in_chain = True
                    chain_names.append(chain.name)
            
            if in_chain:
                # Crear copia con información de chain
                enhanced_finding = Finding(
                    id=finding.id,
                    title=finding.title,
                    description=finding.description + f"\n\n⚠️ PART OF ATTACK CHAIN: {', '.join(chain_names)}",
                    severity=Severity.CRITICAL,  # Upgrade a CRITICAL
                    world=finding.world,
                    tool=finding.tool,
                    confidence=finding.confidence,
                    location=finding.location,
                    line_number=finding.line_number,
                    function=finding.function,
                    raw_output=finding.raw_output,
                    validated=finding.validated,
                    validation_tx=finding.validation_tx
                )
                enhanced.append(enhanced_finding)
            else:
                enhanced.append(finding)
        
        return enhanced
    
    def _calculate_risk_score(self, chains: List[AttackChain]) -> float:
        """Calcula risk score basado en chains detectados"""
        
        if not chains:
            return 0.0
        
        # Base score por cada chain
        base_score = len(chains) * 7.0  # 7 puntos por chain
        
        # Bonus por chains críticos
        critical_chains = sum(1 for c in chains if c.severity == Severity.CRITICAL)
        bonus = critical_chains * 1.0
        
        # Bonus por chains fáciles de explotar
        easy_chains = sum(1 for c in chains if c.exploitability == "easy")
        bonus += easy_chains * 0.5
        
        total = min(base_score + bonus, 10.0)
        return round(total, 1)
    
    def get_high_priority_chains(
        self,
        chains: List[AttackChain]
    ) -> List[AttackChain]:
        """Retorna chains que requieren atención inmediata"""
        
        return [
            c for c in chains
            if c.mitigation_priority == "immediate" and c.severity == Severity.CRITICAL
        ]
