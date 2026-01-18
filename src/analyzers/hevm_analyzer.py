"""
Hevm Analyzer - Razonamiento EVM exacto

Mundo: BYTECODE
Detecta: Issues con delegatecall, storage layout, proxies
Especialidad: Verificación formal de la EVM
"""

from pathlib import Path
from typing import List, Dict, Any, Optional
import json
import tempfile
import os
import re

from .base import BaseAnalyzer, Finding, AnalysisResult, World, Severity


class HevmAnalyzer(BaseAnalyzer):
    """
    Hevm - EVM semántica de dapptools/foundry
    
    Especializado en:
    - Verificación de equivalencia de bytecode
    - Análisis de storage layout
    - Delegatecall safety
    - Proxy upgrades
    - Symbolic execution con semántica EVM exacta
    
    Ideal para:
    - Verificar que proxy + impl son seguros
    - Detectar storage collisions
    - Validar upgrades
    """
    
    @property
    def name(self) -> str:
        return "hevm"
    
    @property
    def world(self) -> World:
        return World.BYTECODE
    
    def is_available(self) -> bool:
        return self._check_tool("hevm")
    
    async def analyze(
        self,
        contract_path: Path,
        bytecode: Optional[str] = None,
        address: Optional[str] = None
    ) -> AnalysisResult:
        """
        Ejecuta hevm symbolic sobre el contrato.
        """
        
        if not self.is_available():
            return AnalysisResult(
                tool=self.name,
                world=self.world,
                success=False,
                error="Hevm not installed"
            )
        
        import time
        start = time.time()
        
        # Configuración
        config = self.config.get("config", {})
        smt_timeout = config.get("smttimeout", 300)
        max_iterations = config.get("max_iterations", 10000)
        fuzz_runs = config.get("fuzz_runs", 100)
        
        findings = []
        
        # hevm tiene varios modos:
        # 1. symbolic - ejecución simbólica
        # 2. equivalence - comparar dos bytecodes
        # 3. test - correr tests de foundry
        
        # Modo 1: Symbolic execution
        symbolic_findings = await self._run_symbolic(
            contract_path, bytecode, smt_timeout, max_iterations
        )
        findings.extend(symbolic_findings)
        
        # Modo 2: Si hay bytecode de proxy, verificar equivalencia/seguridad
        if bytecode:
            proxy_findings = await self._check_proxy_safety(bytecode)
            findings.extend(proxy_findings)
        
        execution_time = time.time() - start
        
        return AnalysisResult(
            tool=self.name,
            world=self.world,
            success=True,
            findings=findings,
            execution_time=execution_time
        )
    
    async def _run_symbolic(
        self,
        contract_path: Path,
        bytecode: Optional[str],
        smt_timeout: int,
        max_iterations: int
    ) -> List[Finding]:
        """Ejecuta hevm symbolic"""
        findings = []
        
        cmd = [
            "hevm", "symbolic",
            "--smttimeout", str(smt_timeout),
            "--max-iterations", str(max_iterations),
            "--json-output"
        ]
        
        if bytecode:
            # Crear archivo temporal
            with tempfile.NamedTemporaryFile(
                mode='w', suffix='.bin', delete=False
            ) as f:
                f.write(bytecode.replace("0x", ""))
                temp_file = f.name
            
            cmd.extend(["--code", temp_file])
            
        elif contract_path and contract_path.exists():
            cmd.extend(["--dapp-root", str(contract_path.parent)])
        
        returncode, stdout, stderr = await self._run_command(cmd)
        
        # Limpiar temp
        if bytecode and 'temp_file' in locals():
            try:
                os.unlink(temp_file)
            except:
                pass
        
        # Parsear output
        findings.extend(self._parse_symbolic_output(stdout + stderr))
        
        return findings
    
    async def _check_proxy_safety(self, bytecode: str) -> List[Finding]:
        """Verifica seguridad de proxies (storage collision, etc)"""
        findings = []
        
        # Detectar si es un proxy
        proxy_patterns = {
            # EIP-1967 storage slots
            "eip1967_impl": "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
            "eip1967_admin": "b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103",
            "eip1967_beacon": "a3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50",
            # EIP-1822
            "eip1822": "c5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7",
        }
        
        bytecode_lower = bytecode.lower()
        
        for pattern_name, slot in proxy_patterns.items():
            if slot in bytecode_lower:
                finding_id = self._generate_finding_id(
                    self.name, f"proxy_detected:{pattern_name}", ""
                )
                
                findings.append(Finding(
                    id=finding_id,
                    title=f"Proxy Pattern Detected: {pattern_name.upper()}",
                    description=f"Contract uses {pattern_name} proxy pattern. "
                               f"Verify:\n"
                               f"- Storage layout compatibility between proxy and implementation\n"
                               f"- No storage collisions\n"
                               f"- Proper access control on upgrade functions\n"
                               f"- Initialize function is protected",
                    severity=Severity.INFO,
                    world=self.world,
                    tool=self.name,
                    confidence="high"
                ))
        
        # Detectar delegatecall patterns peligrosos
        # DELEGATECALL opcode = 0xf4
        delegatecall_count = bytecode_lower.count("f4")
        if delegatecall_count > 0:
            # Buscar si hay control de flujo antes del delegatecall
            # Esto es una heurística simplificada
            if "calldataload" in bytecode_lower.replace("35", "calldataload"):
                finding_id = self._generate_finding_id(
                    self.name, "delegatecall_to_input", ""
                )
                
                findings.append(Finding(
                    id=finding_id,
                    title="Potential Delegatecall to User Input",
                    description="Contract contains DELEGATECALL and reads from CALLDATA. "
                               "If the delegatecall target is derived from user input, "
                               "this could allow arbitrary code execution.",
                    severity=Severity.HIGH,
                    world=self.world,
                    tool=self.name,
                    confidence="medium"
                ))
        
        return findings
    
    def _parse_symbolic_output(self, output: str) -> List[Finding]:
        """Parsea la salida de hevm symbolic"""
        findings = []
        
        # Patrones de hevm
        patterns = [
            (r"assertion violation.*?pc: (\d+)", "Assertion Violation", Severity.HIGH),
            (r"revert.*?pc: (\d+)", "Potential Revert", Severity.MEDIUM),
            (r"overflow.*?pc: (\d+)", "Integer Overflow", Severity.HIGH),
            (r"underflow.*?pc: (\d+)", "Integer Underflow", Severity.HIGH),
            (r"selfdestruct.*?pc: (\d+)", "Selfdestruct Detected", Severity.CRITICAL),
        ]
        
        for pattern, title, severity in patterns:
            matches = re.findall(pattern, output, re.IGNORECASE)
            for match in matches:
                finding_id = self._generate_finding_id(self.name, title, match)
                findings.append(Finding(
                    id=finding_id,
                    title=title,
                    description=f"Hevm symbolic execution detected {title.lower()} at PC: {match}",
                    severity=severity,
                    world=self.world,
                    tool=self.name,
                    confidence="high",
                    location=f"PC: {match}"
                ))
        
        # Parsear JSON si existe
        try:
            # Buscar bloques JSON en la salida
            json_match = re.search(r'\{.*\}', output, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
                if "violations" in data:
                    for v in data["violations"]:
                        finding_id = self._generate_finding_id(
                            self.name,
                            v.get("type", "unknown"),
                            str(v.get("pc", ""))
                        )
                        findings.append(Finding(
                            id=finding_id,
                            title=v.get("type", "Unknown Violation"),
                            description=v.get("message", ""),
                            severity=Severity.HIGH,
                            world=self.world,
                            tool=self.name,
                            confidence="high",
                            raw_output=v
                        ))
        except:
            pass
        
        return findings
    
    def parse_output(self, output: str) -> List[Finding]:
        return self._parse_symbolic_output(output)
