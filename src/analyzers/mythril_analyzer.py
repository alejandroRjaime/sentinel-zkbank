"""
Mythril Analyzer - Ejecución simbólica sobre bytecode

Mundo: BYTECODE
Detecta: Bugs explotables reales sobre lo que corre en la EVM
Trabaja con: Bytecode compilado (no necesita source)
"""

from pathlib import Path
from typing import List, Dict, Any, Optional
import json
import tempfile
import os

from .base import BaseAnalyzer, Finding, AnalysisResult, World, Severity


class MythrilAnalyzer(BaseAnalyzer):
    """
    Mythril - Ejecución simbólica de ConsenSys
    
    Detecta:
    - Reentrancy
    - Integer overflow/underflow
    - Unprotected self-destruct
    - Delegatecall to user-controlled address
    - Ether theft
    - Arbitrary write
    
    Usa Z3 internamente para resolver constraints.
    """
    
    SEVERITY_MAP = {
        "High": Severity.HIGH,
        "Medium": Severity.MEDIUM,
        "Low": Severity.LOW,
        "Informational": Severity.INFO
    }
    
    # SWC IDs críticos
    CRITICAL_SWC = {
        "SWC-107",  # Reentrancy
        "SWC-106",  # Unprotected SELFDESTRUCT
        "SWC-105",  # Unprotected Ether Withdrawal
        "SWC-112",  # Delegatecall to Untrusted Callee
        "SWC-124",  # Write to Arbitrary Storage Location
    }
    
    @property
    def name(self) -> str:
        return "mythril"
    
    @property
    def world(self) -> World:
        return World.BYTECODE
    
    def is_available(self) -> bool:
        return self._check_tool("myth")
    
    async def analyze(
        self,
        contract_path: Path,
        bytecode: Optional[str] = None,
        address: Optional[str] = None
    ) -> AnalysisResult:
        """
        Ejecuta Mythril sobre bytecode.
        
        Puede recibir:
        - contract_path: archivo .sol (lo compila)
        - bytecode: bytecode hex directamente
        - address: dirección para analizar on-chain (requiere RPC)
        """
        
        if not self.is_available():
            return AnalysisResult(
                tool=self.name,
                world=self.world,
                success=False,
                error="Mythril not installed (pip install mythril)"
            )
        
        import time
        start = time.time()
        
        # Configuración
        config = self.config.get("config", {})
        max_depth = config.get("max_depth", 50)
        execution_timeout = config.get("execution_timeout", 300)
        solver_timeout = config.get("solver_timeout", 25000)
        strategy = config.get("strategy", "bfs")
        
        # Construir comando base
        cmd = [
            "myth", "analyze",
            "--execution-timeout", str(execution_timeout),
            "--solver-timeout", str(solver_timeout),
            "--max-depth", str(max_depth),
            "--strategy", strategy,
            "-o", "json"
        ]
        
        # Determinar input
        if bytecode:
            # Crear archivo temporal con bytecode
            with tempfile.NamedTemporaryFile(
                mode='w', 
                suffix='.bin', 
                delete=False
            ) as f:
                # Asegurar que es hex limpio
                clean_bytecode = bytecode.replace("0x", "")
                f.write(clean_bytecode)
                temp_file = f.name
            
            cmd.extend(["--bin-runtime", "-f", temp_file])
            
        elif address:
            # Analizar on-chain
            cmd.extend(["-a", address])
            
            # RPC si está configurado
            rpc_url = os.environ.get("ETH_RPC_URL")
            if rpc_url:
                cmd.extend(["--rpc", rpc_url])
        
        elif contract_path and contract_path.exists():
            # Analizar desde source
            cmd.append(str(contract_path))
        
        else:
            return AnalysisResult(
                tool=self.name,
                world=self.world,
                success=False,
                error="No valid input provided (bytecode, address, or contract_path)"
            )
        
        # Ejecutar
        returncode, stdout, stderr = await self._run_command(cmd)
        
        # Limpiar archivo temporal
        if bytecode and 'temp_file' in locals():
            try:
                os.unlink(temp_file)
            except:
                pass
        
        execution_time = time.time() - start
        
        # Mythril retorna 0 si no hay issues, pero siempre parsear output
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
                error=f"Failed to parse output: {e}\nStderr: {stderr}",
                execution_time=execution_time,
                raw_output=stdout
            )
    
    def parse_output(self, output: str) -> List[Finding]:
        """Parsea la salida JSON de Mythril"""
        findings = []
        
        if not output.strip():
            return findings
        
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return findings
        
        # Mythril puede devolver success=True pero sin issues
        if not data.get("success", True):
            return findings
        
        issues = data.get("issues", [])
        
        for issue in issues:
            swc_id = issue.get("swc-id", "unknown")
            title = issue.get("title", "Unknown Issue")
            description = issue.get("description", "")
            severity_str = issue.get("severity", "Low")
            
            # Mapear severidad
            severity = self.SEVERITY_MAP.get(severity_str, Severity.LOW)
            
            # Elevar a CRITICAL si es SWC crítico
            if swc_id in self.CRITICAL_SWC and severity == Severity.HIGH:
                severity = Severity.CRITICAL
            
            # Extraer ubicación
            location = issue.get("filename")
            line_number = issue.get("lineno")
            function = issue.get("function")
            
            # Código afectado
            code = issue.get("code", "")
            
            finding_id = self._generate_finding_id(
                self.name,
                f"{swc_id}:{title}",
                f"{line_number}" if line_number else ""
            )
            
            full_description = f"{description}"
            if code:
                full_description += f"\n\nAffected code:\n```\n{code}\n```"
            
            # Agregar referencia SWC
            full_description += f"\n\nReference: https://swcregistry.io/{swc_id}"
            
            findings.append(Finding(
                id=finding_id,
                title=f"[{swc_id}] {title}",
                description=full_description,
                severity=severity,
                world=self.world,
                tool=self.name,
                confidence="high",  # Mythril tiene baja tasa de falsos positivos
                location=location,
                line_number=line_number,
                function=function,
                raw_output=issue
            ))
        
        return findings
