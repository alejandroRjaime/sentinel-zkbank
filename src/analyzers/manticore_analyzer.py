"""
Manticore Analyzer - Ejecución simbólica profunda

Mundo: BYTECODE
Detecta: Paths profundos, lógica compleja, estados inalcanzables
Trabaja con: Bytecode o source (pero confía en bytecode)
"""

from pathlib import Path
from typing import List, Dict, Any, Optional
import json
import tempfile
import shutil
import os
import re

from .base import BaseAnalyzer, Finding, AnalysisResult, World, Severity


class ManticoreAnalyzer(BaseAnalyzer):
    """
    Manticore - Ejecución simbólica de Trail of Bits
    
    Detecta:
    - Reentrancy
    - Uninitialized storage
    - Integer overflows
    - Suicidal contracts
    - Unprotected selfdestruct
    - Arbitrary jumps
    
    Más lento que Mythril pero explora paths más profundos.
    Ideal para contratos con lógica compleja.
    """
    
    @property
    def name(self) -> str:
        return "manticore"
    
    @property
    def world(self) -> World:
        return World.BYTECODE
    
    def is_available(self) -> bool:
        return self._check_tool("manticore")
    
    async def analyze(
        self,
        contract_path: Path,
        bytecode: Optional[str] = None,
        address: Optional[str] = None
    ) -> AnalysisResult:
        """
        Ejecuta Manticore sobre el contrato.
        
        Manticore genera un workspace con resultados.
        """
        
        if not self.is_available():
            return AnalysisResult(
                tool=self.name,
                world=self.world,
                success=False,
                error="Manticore not installed (pip install manticore[native])"
            )
        
        import time
        start = time.time()
        
        # Configuración
        config = self.config.get("config", {})
        thorough_mode = config.get("thorough_mode", True)
        timeout_per_path = config.get("timeout_per_path", 300)
        
        # Crear workspace temporal
        workspace = tempfile.mkdtemp(prefix="manticore_")
        
        try:
            # Construir comando
            cmd = [
                "manticore",
                "--workspace", workspace,
                "--timeout", str(self.timeout),
            ]
            
            if thorough_mode:
                cmd.append("--thorough-mode")
            
            # Determinar input
            if bytecode:
                # Crear archivo con bytecode
                bytecode_file = Path(workspace) / "contract.bin"
                clean_bytecode = bytecode.replace("0x", "")
                bytecode_file.write_text(clean_bytecode)
                cmd.extend(["--bin", str(bytecode_file)])
                
            elif contract_path and contract_path.exists():
                cmd.append(str(contract_path))
                
            else:
                return AnalysisResult(
                    tool=self.name,
                    world=self.world,
                    success=False,
                    error="No valid input provided"
                )
            
            # Ejecutar
            returncode, stdout, stderr = await self._run_command(cmd)
            
            execution_time = time.time() - start
            
            # Parsear resultados del workspace
            findings = self._parse_workspace(workspace)
            
            return AnalysisResult(
                tool=self.name,
                world=self.world,
                success=returncode == 0,
                findings=findings,
                execution_time=execution_time,
                raw_output=stdout + "\n" + stderr
            )
            
        finally:
            # Limpiar workspace
            try:
                shutil.rmtree(workspace)
            except:
                pass
    
    def _parse_workspace(self, workspace: str) -> List[Finding]:
        """Parsea los resultados del workspace de Manticore"""
        findings = []
        workspace_path = Path(workspace)
        
        # Manticore genera varios archivos:
        # - global.findings: JSON con findings
        # - *.findings: findings por test case
        # - mcore_*: archivos de estado
        
        # Buscar archivo de findings global
        global_findings = workspace_path / "global.findings"
        if global_findings.exists():
            findings.extend(self._parse_findings_file(global_findings))
        
        # Buscar findings individuales
        for findings_file in workspace_path.glob("*.findings"):
            if findings_file != global_findings:
                findings.extend(self._parse_findings_file(findings_file))
        
        # También revisar el summary
        summary_file = workspace_path / "manticore.yml"
        if summary_file.exists():
            findings.extend(self._parse_summary(summary_file))
        
        return findings
    
    def _parse_findings_file(self, filepath: Path) -> List[Finding]:
        """Parsea un archivo .findings de Manticore"""
        findings = []
        
        try:
            content = filepath.read_text()
            
            # Formato puede ser JSON o texto
            try:
                data = json.loads(content)
                if isinstance(data, list):
                    for item in data:
                        finding = self._finding_from_dict(item)
                        if finding:
                            findings.append(finding)
            except json.JSONDecodeError:
                # Parsear formato texto
                findings.extend(self._parse_text_findings(content))
                
        except Exception as e:
            pass
        
        return findings
    
    def _parse_text_findings(self, content: str) -> List[Finding]:
        """Parsea findings en formato texto"""
        findings = []
        
        # Patrones comunes de Manticore
        patterns = [
            (r"Reentrancy vulnerability at (.+)", "Reentrancy", Severity.CRITICAL),
            (r"Integer overflow at (.+)", "Integer Overflow", Severity.HIGH),
            (r"Integer underflow at (.+)", "Integer Underflow", Severity.HIGH),
            (r"Uninitialized storage at (.+)", "Uninitialized Storage", Severity.HIGH),
            (r"Suicidal contract at (.+)", "Suicidal Contract", Severity.CRITICAL),
            (r"Unprotected selfdestruct at (.+)", "Unprotected Selfdestruct", Severity.CRITICAL),
            (r"Arbitrary JUMP at (.+)", "Arbitrary Jump", Severity.HIGH),
        ]
        
        for pattern, title, severity in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                finding_id = self._generate_finding_id(self.name, title, match)
                findings.append(Finding(
                    id=finding_id,
                    title=title,
                    description=f"Manticore detected {title.lower()} at {match}",
                    severity=severity,
                    world=self.world,
                    tool=self.name,
                    confidence="high",
                    location=match
                ))
        
        return findings
    
    def _parse_summary(self, filepath: Path) -> List[Finding]:
        """Parsea el archivo summary YAML"""
        findings = []
        
        try:
            import yaml
            content = filepath.read_text()
            data = yaml.safe_load(content)
            
            if isinstance(data, dict):
                # Extraer findings del summary
                for key, value in data.items():
                    if "vulnerability" in key.lower() or "finding" in key.lower():
                        if isinstance(value, list):
                            for item in value:
                                finding = self._finding_from_dict(item)
                                if finding:
                                    findings.append(finding)
        except:
            pass
        
        return findings
    
    def _finding_from_dict(self, data: Dict) -> Optional[Finding]:
        """Crea un Finding desde un diccionario"""
        if not isinstance(data, dict):
            return None
        
        title = data.get("name", data.get("title", "Unknown"))
        description = data.get("description", "")
        
        # Determinar severidad
        severity_str = data.get("severity", "medium").lower()
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO
        }
        severity = severity_map.get(severity_str, Severity.MEDIUM)
        
        finding_id = self._generate_finding_id(
            self.name,
            title,
            data.get("address", "")
        )
        
        return Finding(
            id=finding_id,
            title=title,
            description=description,
            severity=severity,
            world=self.world,
            tool=self.name,
            confidence="high",
            location=data.get("filename"),
            line_number=data.get("line"),
            function=data.get("function"),
            raw_output=data
        )
    
    def parse_output(self, output: str) -> List[Finding]:
        """Parsea la salida de texto de Manticore"""
        return self._parse_text_findings(output)
