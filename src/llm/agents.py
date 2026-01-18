"""
LLM Agents - Agentes especializados para análisis de smart contracts

Cada agente tiene una responsabilidad específica en el pipeline:
- TriageAgent: Filtrar falsos positivos
- AnalysisAgent: Análisis profundo de findings
- PoCAgent: Generar Proof of Concepts
- RemediationAgent: Sugerir fixes
- SummaryAgent: Generar reportes ejecutivos
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from pathlib import Path
import json
import asyncio

from .base import BaseLLMClient, create_llm_client
from .prompts import (
    AUDITOR_SYSTEM, TRIAGE_SYSTEM, POC_SYSTEM, REMEDIATION_SYSTEM,
    TRIAGE_PROMPT, ANALYSIS_PROMPT, POC_PROMPT, REMEDIATION_PROMPT, SUMMARY_PROMPT
)
from ..analyzers.base import Finding, Severity, World


@dataclass
class TriageResult:
    """Resultado del triage de un finding"""
    finding: Finding
    classification: str  # TRUE_POSITIVE, FALSE_POSITIVE, NEEDS_CONTEXT
    confidence: int
    real_severity: Severity
    reasoning: str
    attack_scenario: Optional[str] = None
    false_positive_reason: Optional[str] = None


@dataclass
class AnalysisResult:
    """Resultado del análisis profundo"""
    finding: Finding
    root_cause: str
    attack_vector: List[str]
    preconditions: List[str]
    impact: Dict[str, Any]
    exploitability: Dict[str, Any]
    cvss_estimate: float
    similar_hacks: List[str] = field(default_factory=list)


@dataclass
class PoCResult:
    """Proof of Concept generado"""
    finding: Finding
    poc_code: str
    setup_instructions: str
    expected_result: str


@dataclass
class RemediationResult:
    """Remediación sugerida"""
    finding: Finding
    minimal_fix: Dict[str, str]
    recommended_fix: Dict[str, Any]
    explanation: str
    testing_strategy: List[str]


class TriageAgent:
    """
    Agente de Triage - Filtra falsos positivos
    
    Analiza cada finding y determina si es real o no,
    ajustando la severidad si es necesario.
    """
    
    def __init__(self, client: BaseLLMClient):
        self.client = client
    
    async def triage(
        self,
        finding: Finding,
        source_code: str
    ) -> TriageResult:
        """Evalúa un finding individual"""
        
        prompt = TRIAGE_PROMPT.format(
            tool=finding.tool,
            title=finding.title,
            severity=finding.severity.value,
            description=finding.description,
            location=finding.location or "N/A",
            function=finding.function or "N/A",
            source_code=source_code[:8000]  # Limitar tamaño
        )
        
        try:
            result = await self.client.complete_json(prompt, TRIAGE_SYSTEM)
            
            # Mapear severidad
            severity_map = {
                "CRITICAL": Severity.CRITICAL,
                "HIGH": Severity.HIGH,
                "MEDIUM": Severity.MEDIUM,
                "LOW": Severity.LOW,
                "INFO": Severity.INFO
            }
            
            return TriageResult(
                finding=finding,
                classification=result.get("classification", "NEEDS_CONTEXT"),
                confidence=result.get("confidence", 50),
                real_severity=severity_map.get(
                    result.get("real_severity", "MEDIUM"),
                    Severity.MEDIUM
                ),
                reasoning=result.get("reasoning", ""),
                attack_scenario=result.get("attack_scenario"),
                false_positive_reason=result.get("false_positive_reason")
            )
            
        except Exception as e:
            # En caso de error, mantener el finding original
            return TriageResult(
                finding=finding,
                classification="NEEDS_CONTEXT",
                confidence=0,
                real_severity=finding.severity,
                reasoning=f"Error en triage: {e}"
            )
    
    async def triage_batch(
        self,
        findings: List[Finding],
        source_code: str,
        concurrency: int = 3
    ) -> List[TriageResult]:
        """Evalúa múltiples findings en paralelo"""
        
        semaphore = asyncio.Semaphore(concurrency)
        
        async def triage_with_limit(finding):
            async with semaphore:
                return await self.triage(finding, source_code)
        
        tasks = [triage_with_limit(f) for f in findings]
        return await asyncio.gather(*tasks)
    
    def filter_false_positives(
        self,
        results: List[TriageResult],
        min_confidence: int = 70
    ) -> List[Finding]:
        """Retorna solo los true positives con alta confianza"""
        
        filtered = []
        for r in results:
            if r.classification == "TRUE_POSITIVE" and r.confidence >= min_confidence:
                # Actualizar severidad si cambió
                r.finding.severity = r.real_severity
                filtered.append(r.finding)
            elif r.classification == "NEEDS_CONTEXT":
                # Mantener para review manual
                filtered.append(r.finding)
        
        return filtered


class AnalysisAgent:
    """
    Agente de Análisis - Análisis profundo de vulnerabilidades
    
    Examina cada finding en detalle para entender:
    - Causa raíz
    - Vector de ataque
    - Impacto real
    - Dificultad de explotación
    """
    
    def __init__(self, client: BaseLLMClient):
        self.client = client
    
    async def analyze(
        self,
        finding: Finding,
        source_code: str,
        contract_name: str = "Unknown",
        is_proxy: bool = False,
        has_source: bool = True
    ) -> AnalysisResult:
        """Analiza un finding en profundidad"""
        
        prompt = ANALYSIS_PROMPT.format(
            title=finding.title,
            severity=finding.severity.value,
            tool=finding.tool,
            description=finding.description,
            source_code=source_code[:8000],
            contract_name=contract_name,
            is_proxy=is_proxy,
            has_source=has_source
        )
        
        try:
            result = await self.client.complete_json(prompt, AUDITOR_SYSTEM)
            
            return AnalysisResult(
                finding=finding,
                root_cause=result.get("root_cause", ""),
                attack_vector=result.get("attack_vector", []),
                preconditions=result.get("preconditions", []),
                impact=result.get("impact", {}),
                exploitability=result.get("exploitability", {}),
                cvss_estimate=result.get("cvss_estimate", 0.0),
                similar_hacks=result.get("similar_hacks", [])
            )
            
        except Exception as e:
            return AnalysisResult(
                finding=finding,
                root_cause=f"Error en análisis: {e}",
                attack_vector=[],
                preconditions=[],
                impact={},
                exploitability={},
                cvss_estimate=0.0
            )


class PoCAgent:
    """
    Agente de PoC - Genera Proof of Concepts
    
    Crea código ejecutable que demuestra la vulnerabilidad.
    """
    
    def __init__(self, client: BaseLLMClient):
        self.client = client
    
    async def generate(
        self,
        finding: Finding,
        source_code: str,
        analysis: Optional[AnalysisResult] = None
    ) -> PoCResult:
        """Genera un PoC para el finding"""
        
        attack_vector = ""
        if analysis:
            attack_vector = "\n".join(analysis.attack_vector)
        
        prompt = POC_PROMPT.format(
            title=finding.title,
            severity=finding.severity.value,
            description=finding.description,
            attack_vector=attack_vector or finding.description,
            source_code=source_code[:8000]
        )
        
        try:
            response = await self.client.complete(prompt, POC_SYSTEM)
            
            # Extraer código del response
            poc_code = self._extract_code(response.content)
            
            return PoCResult(
                finding=finding,
                poc_code=poc_code,
                setup_instructions="forge test -vvv --match-test testExploit",
                expected_result="El test debe pasar demostrando la vulnerabilidad"
            )
            
        except Exception as e:
            return PoCResult(
                finding=finding,
                poc_code=f"// Error generando PoC: {e}",
                setup_instructions="",
                expected_result=""
            )
    
    def _extract_code(self, content: str) -> str:
        """Extrae bloques de código Solidity del contenido"""
        
        if "```solidity" in content:
            parts = content.split("```solidity")
            if len(parts) > 1:
                code = parts[1].split("```")[0]
                return code.strip()
        
        if "```" in content:
            parts = content.split("```")
            if len(parts) > 1:
                return parts[1].strip()
        
        return content


class RemediationAgent:
    """
    Agente de Remediación - Sugiere fixes
    
    Proporciona soluciones concretas con código.
    """
    
    def __init__(self, client: BaseLLMClient):
        self.client = client
    
    async def suggest(
        self,
        finding: Finding,
        source_code: str,
        analysis: Optional[AnalysisResult] = None
    ) -> RemediationResult:
        """Sugiere remediación para el finding"""
        
        root_cause = ""
        if analysis:
            root_cause = analysis.root_cause
        
        prompt = REMEDIATION_PROMPT.format(
            title=finding.title,
            severity=finding.severity.value,
            root_cause=root_cause or finding.description,
            vulnerable_code=source_code[:6000]
        )
        
        try:
            result = await self.client.complete_json(prompt, REMEDIATION_SYSTEM)
            
            return RemediationResult(
                finding=finding,
                minimal_fix=result.get("minimal_fix", {}),
                recommended_fix=result.get("recommended_fix", {}),
                explanation=result.get("explanation", ""),
                testing_strategy=result.get("testing_strategy", [])
            )
            
        except Exception as e:
            return RemediationResult(
                finding=finding,
                minimal_fix={"description": f"Error: {e}"},
                recommended_fix={},
                explanation="",
                testing_strategy=[]
            )


class SummaryAgent:
    """
    Agente de Resumen - Genera reportes ejecutivos
    """
    
    def __init__(self, client: BaseLLMClient):
        self.client = client
    
    async def generate_summary(
        self,
        address: str,
        contract_name: str,
        has_source: bool,
        findings: List[Finding]
    ) -> Dict[str, Any]:
        """Genera resumen ejecutivo"""
        
        # Formatear findings para el prompt
        findings_summary = "\n".join([
            f"- [{f.severity.value.upper()}] {f.title}: {f.description[:100]}..."
            for f in findings
        ])
        
        prompt = SUMMARY_PROMPT.format(
            address=address,
            contract_name=contract_name,
            has_source=has_source,
            findings_summary=findings_summary or "No se encontraron vulnerabilidades"
        )
        
        try:
            return await self.client.complete_json(prompt, AUDITOR_SYSTEM)
        except Exception as e:
            return {
                "executive_summary": f"Error generando resumen: {e}",
                "security_score": "N/A",
                "risk_level": "UNKNOWN"
            }


class LLMPipeline:
    """
    Pipeline completo de LLM
    
    Orquesta todos los agentes en secuencia:
    1. Triage → filtrar falsos positivos
    2. Analysis → análisis profundo
    3. PoC → generar exploits (solo críticos)
    4. Remediation → sugerir fixes
    5. Summary → reporte ejecutivo
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled = config.get("enabled", False)
        
        if self.enabled:
            self.client = create_llm_client(config)
            self.triage = TriageAgent(self.client)
            self.analysis = AnalysisAgent(self.client)
            self.poc = PoCAgent(self.client)
            self.remediation = RemediationAgent(self.client)
            self.summary = SummaryAgent(self.client)
    
    async def process(
        self,
        findings: List[Finding],
        source_code: str,
        address: str = "",
        contract_name: str = "Unknown",
        is_proxy: bool = False,
        has_source: bool = True,
        generate_pocs: bool = True,
        generate_remediations: bool = True
    ) -> Dict[str, Any]:
        """
        Procesa todos los findings a través del pipeline.
        
        Returns:
            {
                "filtered_findings": List[Finding],
                "analyses": List[AnalysisResult],
                "pocs": List[PoCResult],
                "remediations": List[RemediationResult],
                "summary": Dict
            }
        """
        
        if not self.enabled:
            return {
                "filtered_findings": findings,
                "analyses": [],
                "pocs": [],
                "remediations": [],
                "summary": {"note": "LLM pipeline disabled"}
            }
        
        print("\n🤖 LLM PIPELINE")
        print("="*50)
        
        # 1. Triage
        print(f"\n📋 Triage: Evaluando {len(findings)} findings...")
        triage_results = await self.triage.triage_batch(findings, source_code)
        filtered = self.triage.filter_false_positives(triage_results)
        
        true_positives = sum(1 for r in triage_results if r.classification == "TRUE_POSITIVE")
        false_positives = sum(1 for r in triage_results if r.classification == "FALSE_POSITIVE")
        print(f"  ✓ True positives: {true_positives}")
        print(f"  ✗ False positives: {false_positives}")
        
        # 2. Análisis profundo (solo true positives)
        print(f"\n🔍 Análisis profundo de {len(filtered)} findings...")
        analyses = []
        for f in filtered:
            analysis = await self.analysis.analyze(
                f, source_code, contract_name, is_proxy, has_source
            )
            analyses.append(analysis)
            print(f"  ✓ {f.title}")
        
        # 3. PoCs (solo críticos y high)
        pocs = []
        if generate_pocs:
            critical_high = [
                (f, a) for f, a in zip(filtered, analyses)
                if f.severity in [Severity.CRITICAL, Severity.HIGH]
            ]
            
            if critical_high:
                print(f"\n⚔️ Generando PoCs para {len(critical_high)} findings críticos...")
                for finding, analysis in critical_high:
                    poc = await self.poc.generate(finding, source_code, analysis)
                    pocs.append(poc)
                    print(f"  ✓ PoC: {finding.title}")
        
        # 4. Remediaciones
        remediations = []
        if generate_remediations:
            print(f"\n🔧 Generando remediaciones...")
            for finding, analysis in zip(filtered, analyses):
                remediation = await self.remediation.suggest(finding, source_code, analysis)
                remediations.append(remediation)
                print(f"  ✓ Fix: {finding.title}")
        
        # 5. Resumen ejecutivo
        print(f"\n📊 Generando resumen ejecutivo...")
        summary = await self.summary.generate_summary(
            address, contract_name, has_source, filtered
        )
        print(f"  ✓ Security Score: {summary.get('security_score', 'N/A')}")
        
        return {
            "triage_results": triage_results,
            "filtered_findings": filtered,
            "analyses": analyses,
            "pocs": pocs,
            "remediations": remediations,
            "summary": summary
        }
