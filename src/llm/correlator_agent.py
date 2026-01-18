"""
LLM Correlator Agent - Correlación inteligente de vulnerabilidades
Agrupa findings, detecta attack chains, y asigna confidence scores

ACTUALIZADO: Usa Finding, Severity, World de analyzers.base
"""

from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
import hashlib

from .base import BaseLLMClient
from ..analyzers.base import Finding, Severity, World


@dataclass
class CorrelatedFinding:
    """Finding correlacionado de múltiples herramientas"""
    findings: List[Finding]  # Findings originales que se fusionaron
    primary_finding: Finding  # Finding principal (mayor severidad)
    tools_agreement: int  # Número de herramientas que coinciden
    confidence_score: float  # 0.0-1.0
    consolidated_description: str
    locations: List[str]  # Todas las ubicaciones mencionadas
    is_duplicate: bool = False
    duplicate_of: Optional[str] = None


@dataclass
class CorrelationResult:
    """Resultado del proceso de correlación"""
    original_count: int
    correlated_findings: List[CorrelatedFinding]
    duplicates_removed: int
    confidence_increased: int  # Findings con confidence mejorado


CORRELATION_SYSTEM = """Eres un experto en análisis de herramientas de seguridad de smart contracts.

Tu tarea es identificar si diferentes findings de distintas herramientas describen 
la MISMA vulnerabilidad o son vulnerabilidades DIFERENTES.

Herramientas y sus características:
- Slither: Análisis estático rápido, a veces genera falsos positivos
- Mythril: Ejecución simbólica, preciso pero lento
- Echidna: Fuzzing, encuentra edge cases
- Manticore: Ejecución simbólica completa
- Hevm: Verificación formal EVM

Patrones comunes de duplicados:
- "Reentrancy in withdraw()" == "SWC-107 in withdraw()"
- "Unprotected function" == "Missing access control"
- "Integer overflow" == "Arithmetic issue"

Responde siempre en JSON estructurado."""


DEDUPLICATION_PROMPT = """Analiza estos findings y determina si describen la MISMA vulnerabilidad o son DIFERENTES.

## FINDINGS

{findings_text}

## INSTRUCCIONES

Para cada par de findings, determina:
1. ¿Describen la misma vulnerabilidad? (misma ubicación + mismo tipo de issue)
2. ¿O son vulnerabilidades diferentes?

Responde en JSON:
```json
{{
  "groups": [
    {{
      "indices": [0, 2],
      "reason": "Ambos describen reentrancy en withdraw() línea 45",
      "same_vulnerability": true
    }},
    {{
      "indices": [1],
      "reason": "Access control issue diferente, función setupAdmin()",
      "same_vulnerability": false
    }}
  ]
}}
```

Reglas:
- MISMO location + MISMO tipo → same_vulnerability: true
- DIFERENTE location → same_vulnerability: false
- Mismo tipo pero diferente función → same_vulnerability: false"""


CONSOLIDATION_PROMPT = """Consolida estas descripciones de la misma vulnerabilidad en una descripción clara.

## DESCRIPCIONES ORIGINALES

{descriptions}

## CÓDIGO AFECTADO

```solidity
{code_snippet}
```

## INSTRUCCIONES

Genera una descripción consolidada que:
1. Sea técnicamente precisa
2. Incluya el impacto real
3. No repita información
4. Sea concisa (2-3 oraciones)

Responde en JSON:
```json
{{
  "consolidated_description": "Descripción consolidada aquí",
  "key_points": ["Punto 1", "Punto 2"],
  "confidence_adjustment": 0.0-0.3
}}
```"""


class CorrelatorAgent:
    """
    Agente de Correlación - Fusiona findings de múltiples herramientas
    
    Reduce duplicados y aumenta confidence cuando múltiples tools coinciden.
    """
    
    def __init__(self, client: BaseLLMClient):
        self.client = client
    
    def _generate_finding_id(self, tool: str, title: str, location: str = "") -> str:
        """Genera un ID único para un finding"""
        content = f"{tool}:{title}:{location}"
        return hashlib.sha256(content.encode()).hexdigest()[:12]
    
    async def correlate(
        self,
        findings: List[Finding],
        source_code: Optional[str] = None
    ) -> CorrelationResult:
        """
        Correlaciona findings de múltiples herramientas
        
        Args:
            findings: Lista de findings de todas las herramientas
            source_code: Código fuente del contrato (opcional, mejora análisis)
        
        Returns:
            CorrelationResult con findings consolidados
        """
        
        if not findings:
            return CorrelationResult(
                original_count=0,
                correlated_findings=[],
                duplicates_removed=0,
                confidence_increased=0
            )
        
        print(f"\n🔗 Correlación: Procesando {len(findings)} findings...")
        
        # Paso 1: Agrupar por ubicación similar
        grouped = self._group_by_location(findings)
        print(f"  → Agrupados en {len(grouped)} ubicaciones")
        
        # Paso 2: Deduplicar usando LLM
        correlated = []
        duplicates_removed = 0
        
        for location, group in grouped.items():
            if len(group) == 1:
                # Un solo finding, no hay duplicados
                correlated.append(self._create_correlated_finding(group, source_code))
            else:
                # Múltiples findings, deduplicar
                deduplicated = await self._deduplicate_group(group, source_code)
                correlated.extend(deduplicated)
                duplicates_removed += len(group) - len(deduplicated)
        
        # Paso 3: Calcular estadísticas
        confidence_increased = sum(
            1 for cf in correlated 
            if cf.tools_agreement > 1 and cf.confidence_score > 0.7
        )
        
        print(f"  ✓ Duplicados eliminados: {duplicates_removed}")
        print(f"  ✓ Confidence mejorado: {confidence_increased} findings")
        print(f"  ✓ Total final: {len(correlated)} findings")
        
        return CorrelationResult(
            original_count=len(findings),
            correlated_findings=correlated,
            duplicates_removed=duplicates_removed,
            confidence_increased=confidence_increased
        )
    
    def _group_by_location(self, findings: List[Finding]) -> Dict[str, List[Finding]]:
        """Agrupa findings por ubicación en el código"""
        
        grouped = defaultdict(list)
        
        for finding in findings:
            # Crear key normalizada de ubicación
            if finding.location:
                # Normalizar: "Contract.sol:45" o "Contract.sol:45-50"
                location_key = finding.location.split(":")[0]  # Solo archivo
                if ":" in finding.location:
                    line = finding.location.split(":")[1].split("-")[0]
                    location_key = f"{location_key}:{line}"
            else:
                # Sin ubicación, usar función + título
                location_key = f"{finding.function or 'unknown'}_{finding.title[:30]}"
            
            grouped[location_key].append(finding)
        
        return dict(grouped)
    
    async def _deduplicate_group(
        self,
        group: List[Finding],
        source_code: Optional[str]
    ) -> List[CorrelatedFinding]:
        """Deduplica un grupo de findings usando LLM"""
        
        # Formatear findings para el LLM
        findings_text = "\n\n".join([
            f"Finding {i} (from {f.tool}):\n"
            f"  Title: {f.title}\n"
            f"  Severity: {f.severity.value}\n"
            f"  Description: {f.description}\n"
            f"  Location: {f.location or 'N/A'}\n"
            f"  Function: {f.function or 'N/A'}"
            for i, f in enumerate(group)
        ])
        
        prompt = DEDUPLICATION_PROMPT.format(findings_text=findings_text)
        
        try:
            result = await self.client.complete_json(prompt, CORRELATION_SYSTEM)
            
            # Procesar grupos
            correlated = []
            for group_info in result.get("groups", []):
                indices = group_info["indices"]
                same_vuln = group_info.get("same_vulnerability", True)
                
                if same_vuln and len(indices) > 1:
                    # Múltiples findings de la misma vuln
                    finding_group = [group[i] for i in indices if i < len(group)]
                    correlated_finding = await self._merge_findings(
                        finding_group, 
                        source_code
                    )
                    correlated.append(correlated_finding)
                else:
                    # Finding único
                    for idx in indices:
                        if idx < len(group):
                            cf = self._create_correlated_finding([group[idx]], source_code)
                            correlated.append(cf)
            
            return correlated
            
        except Exception as e:
            print(f"  ⚠️ Error en deduplicación: {e}")
            # Fallback: tratar cada finding como único
            return [self._create_correlated_finding([f], source_code) for f in group]
    
    async def _merge_findings(
        self,
        findings: List[Finding],
        source_code: Optional[str]
    ) -> CorrelatedFinding:
        """Fusiona múltiples findings de la misma vulnerabilidad"""
        
        # Seleccionar finding principal (mayor severidad)
        primary = max(findings, key=lambda f: self._severity_score(f.severity))
        
        # Generar descripción consolidada con LLM
        descriptions = "\n\n".join([
            f"[{f.tool}]: {f.description}"
            for f in findings
        ])
        
        code_snippet = ""
        if source_code and primary.location:
            # Extraer snippet relevante (simplificado)
            code_snippet = source_code[:500]  # Primeras líneas
        
        prompt = CONSOLIDATION_PROMPT.format(
            descriptions=descriptions,
            code_snippet=code_snippet or "No disponible"
        )
        
        try:
            result = await self.client.complete_json(prompt, CORRELATION_SYSTEM)
            consolidated_desc = result.get("consolidated_description", primary.description)
            confidence_adj = result.get("confidence_adjustment", 0.2)
        except:
            consolidated_desc = primary.description
            confidence_adj = 0.2
        
        # Calcular confidence score
        tools_count = len(set(f.tool for f in findings))
        confidence = self._calculate_confidence(findings, tools_count, confidence_adj)
        
        # Recopilar todas las ubicaciones
        locations = list(set(f.location for f in findings if f.location))
        
        return CorrelatedFinding(
            findings=findings,
            primary_finding=primary,
            tools_agreement=tools_count,
            confidence_score=confidence,
            consolidated_description=consolidated_desc,
            locations=locations
        )
    
    def _create_correlated_finding(
        self,
        findings: List[Finding],
        source_code: Optional[str]
    ) -> CorrelatedFinding:
        """Crea un CorrelatedFinding para un finding único"""
        
        finding = findings[0]
        
        return CorrelatedFinding(
            findings=findings,
            primary_finding=finding,
            tools_agreement=1,
            confidence_score=0.6,  # Base confidence para finding único
            consolidated_description=finding.description,
            locations=[finding.location] if finding.location else []
        )
    
    def _calculate_confidence(
        self,
        findings: List[Finding],
        tools_count: int,
        llm_adjustment: float
    ) -> float:
        """
        Calcula confidence score basado en:
        - Número de herramientas que coinciden
        - Severidad
        - Ajuste del LLM
        """
        
        # Base: más herramientas = más confianza
        base_conf = 0.4 + (tools_count * 0.2)  # 0.6 para 1 tool, 0.8 para 2, 1.0 para 3+
        
        # Ajuste por severidad (findings críticos son más importantes)
        max_severity_score = max(self._severity_score(f.severity) for f in findings)
        severity_boost = max_severity_score * 0.05
        
        # Aplicar ajuste del LLM
        final_conf = min(base_conf + severity_boost + llm_adjustment, 1.0)
        
        return round(final_conf, 2)
    
    def _severity_score(self, severity: Severity) -> int:
        """Convierte Severity a score numérico"""
        scores = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1
        }
        return scores.get(severity, 0)
    
    def get_consolidated_findings(
        self,
        correlated: List[CorrelatedFinding],
        min_confidence: float = 0.6
    ) -> List[Finding]:
        """
        Retorna lista de findings consolidados (primary findings)
        filtrados por confidence mínimo
        """
        
        consolidated = []
        for cf in correlated:
            if cf.confidence_score >= min_confidence:
                # Actualizar descripción en el finding principal
                # Crear una copia para no modificar el original
                updated_finding = Finding(
                    id=cf.primary_finding.id,
                    title=cf.primary_finding.title,
                    description=cf.consolidated_description,
                    severity=cf.primary_finding.severity,
                    world=cf.primary_finding.world,
                    tool=cf.primary_finding.tool,
                    confidence=cf.primary_finding.confidence,
                    location=cf.primary_finding.location,
                    line_number=cf.primary_finding.line_number,
                    function=cf.primary_finding.function,
                    raw_output=cf.primary_finding.raw_output,
                    validated=cf.primary_finding.validated,
                    validation_tx=cf.primary_finding.validation_tx
                )
                consolidated.append(updated_finding)
        
        return consolidated
