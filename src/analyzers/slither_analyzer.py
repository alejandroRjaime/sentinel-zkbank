"""
Slither Analyzer - Análisis estático de Solidity

Mundo: SOURCE
Detecta: Bugs estructurales, patrones peligrosos, malas prácticas
Requiere: Código fuente .sol
"""

from pathlib import Path
from typing import List, Dict, Any, Optional
import json
import re

from .base import BaseAnalyzer, Finding, AnalysisResult, World, Severity


class SlitherAnalyzer(BaseAnalyzer):
    """
    Slither - Analizador estático de Trail of Bits
    
    Detecta:
    - Reentrancy
    - Access control issues
    - Unchecked return values
    - Integer overflow/underflow (pre-0.8)
    - Dangerous delegatecall
    - tx.origin usage
    - Y 80+ detectores más
    """
    
    SEVERITY_MAP = {
        "High": Severity.HIGH,
        "Medium": Severity.MEDIUM,
        "Low": Severity.LOW,
        "Informational": Severity.INFO,
        "Optimization": Severity.INFO
    }
    
    # Detectores críticos que casi siempre son verdaderos positivos
    CRITICAL_DETECTORS = {
        "reentrancy-eth",
        "reentrancy-no-eth", 
        "arbitrary-send-eth",
        "arbitrary-send-erc20",
        "suicidal",
        "controlled-delegatecall",
        "msg-value-loop",
        "delegatecall-loop"
    }
    
    @property
    def name(self) -> str:
        return "slither"
    
    @property
    def world(self) -> World:
        return World.SOURCE
    
    def is_available(self) -> bool:
        return self._check_tool("slither")
    
    async def analyze(
        self,
        contract_path: Path,
        bytecode: Optional[str] = None,
        address: Optional[str] = None
    ) -> AnalysisResult:
        """Ejecuta Slither sobre el código fuente"""
        
        if not self.is_available():
            return AnalysisResult(
                tool=self.name,
                world=self.world,
                success=False,
                error="Slither not installed"
            )
        
        if not contract_path.exists():
            return AnalysisResult(
                tool=self.name,
                world=self.world,
                success=False,
                error=f"Contract path not found: {contract_path}"
            )
        
        import time
        start = time.time()
        
        # Construir comando
        cmd = [
            "slither",
            str(contract_path),
            "--json", "-"
        ]
        
        # Agregar exclusiones si están configuradas
        config = self.config.get("config", {})
        if config.get("exclude_informational"):
            cmd.extend(["--exclude-informational"])
        if config.get("exclude_optimization"):
            cmd.extend(["--exclude-optimization"])
        
        # Ejecutar
        returncode, stdout, stderr = await self._run_command(cmd)
        
        execution_time = time.time() - start
        
        # Slither retorna 0 si no hay findings, 1+ si hay findings
        # Parsear JSON de stdout
        try:
            findings = self.parse_output(stdout)
            return AnalysisResult(
                tool=self.name,
                world=self.world,
                success=True,
                findings=findings,
                execution_time=execution_time,
                raw_output=stdout
            )
        except Exception as e:
            return AnalysisResult(
                tool=self.name,
                world=self.world,
                success=False,
                error=f"Failed to parse output: {e}",
                execution_time=execution_time,
                raw_output=stdout
            )
    
    def parse_output(self, output: str) -> List[Finding]:
        """Parsea la salida JSON de Slither"""
        findings = []
        
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            # Intentar extraer JSON del output
            match = re.search(r'\{.*\}', output, re.DOTALL)
            if match:
                data = json.loads(match.group())
            else:
                return findings
        
        detectors = data.get("results", {}).get("detectors", [])
        
        for detector in detectors:
            check = detector.get("check", "unknown")
            impact = detector.get("impact", "Low")
            confidence = detector.get("confidence", "Medium")
            description = detector.get("description", "")
            
            # Mapear severidad
            severity = self.SEVERITY_MAP.get(impact, Severity.LOW)
            
            # Elevar a CRITICAL si es un detector crítico
            if check in self.CRITICAL_DETECTORS and severity == Severity.HIGH:
                severity = Severity.CRITICAL
            
            # Extraer ubicación
            elements = detector.get("elements", [])
            location = None
            line_number = None
            function = None
            
            if elements:
                first = elements[0]
                location = first.get("source_mapping", {}).get("filename_relative")
                lines = first.get("source_mapping", {}).get("lines", [])
                if lines:
                    line_number = lines[0]
                if first.get("type") == "function":
                    function = first.get("name")
            
            finding_id = self._generate_finding_id(
                self.name, 
                check, 
                f"{location}:{line_number}" if location else ""
            )
            
            findings.append(Finding(
                id=finding_id,
                title=check.replace("-", " ").title(),
                description=description,
                severity=severity,
                world=self.world,
                tool=self.name,
                confidence=confidence.lower(),
                location=location,
                line_number=line_number,
                function=function,
                raw_output=detector
            ))
        
        return findings
