"""
Echidna Analyzer - Fuzzing de smart contracts

Mundo: SOURCE
Detecta: Violaciones de invariantes, edge cases, estados corruptos
Requiere: Código fuente .sol con propiedades echidna_*
"""

from pathlib import Path
from typing import List, Dict, Any, Optional
import json
import re

from .base import BaseAnalyzer, Finding, AnalysisResult, World, Severity


class EchidnaAnalyzer(BaseAnalyzer):
    """
    Echidna - Fuzzer de contratos de Trail of Bits
    
    Detecta:
    - Violación de invariantes económicas
    - Edge cases en combinaciones de inputs
    - Secuencias de transacciones que corrompen estado
    - Unexpected reverts
    
    Requiere que el contrato tenga funciones:
    - echidna_* que retornen bool (invariantes)
    - O usar modo assertion para detectar asserts
    """
    
    @property
    def name(self) -> str:
        return "echidna"
    
    @property
    def world(self) -> World:
        return World.SOURCE
    
    def is_available(self) -> bool:
        return self._check_tool("echidna")
    
    def has_echidna_tests(self, contract_path: Path) -> bool:
        """Verifica si el contrato tiene tests de Echidna"""
        try:
            content = contract_path.read_text()
            # Buscar funciones echidna_* o assert statements
            has_echidna = bool(re.search(r'function\s+echidna_\w+', content))
            has_asserts = bool(re.search(r'\bassert\s*\(', content))
            return has_echidna or has_asserts
        except:
            return False
    
    async def analyze(
        self,
        contract_path: Path,
        bytecode: Optional[str] = None,
        address: Optional[str] = None
    ) -> AnalysisResult:
        """Ejecuta Echidna sobre el código fuente"""
        
        if not self.is_available():
            return AnalysisResult(
                tool=self.name,
                world=self.world,
                success=False,
                error="Echidna not installed"
            )
        
        if not contract_path.exists():
            return AnalysisResult(
                tool=self.name,
                world=self.world,
                success=False,
                error=f"Contract path not found: {contract_path}"
            )
        
        # Verificar si tiene tests
        if not self.has_echidna_tests(contract_path):
            return AnalysisResult(
                tool=self.name,
                world=self.world,
                success=True,
                findings=[],
                error="No echidna_* tests or assert statements found"
            )
        
        import time
        start = time.time()
        
        # Configuración
        config = self.config.get("config", {})
        test_limit = config.get("test_limit", 50000)
        seq_len = config.get("seq_len", 100)
        
        # Construir comando
        cmd = [
            "echidna",
            str(contract_path),
            "--format", "json",
            "--test-limit", str(test_limit),
            "--seq-len", str(seq_len)
        ]
        
        # Corpus para fuzzing guiado
        corpus_dir = config.get("corpus_dir")
        if corpus_dir:
            cmd.extend(["--corpus-dir", corpus_dir])
        
        # Ejecutar
        returncode, stdout, stderr = await self._run_command(cmd)
        
        execution_time = time.time() - start
        
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
        """Parsea la salida JSON de Echidna"""
        findings = []
        
        # Echidna puede emitir múltiples líneas JSON
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
                
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            
            # Procesar resultados de tests
            if isinstance(data, dict):
                tests = data.get("tests", [])
                
                for test in tests:
                    status = test.get("status", "")
                    name = test.get("name", "unknown")
                    
                    # Solo reportar tests fallidos
                    if status.lower() in ["failed", "false"]:
                        call_sequence = test.get("reproducer", [])
                        
                        # Determinar severidad basada en el tipo de test
                        if "echidna_" in name:
                            # Invariante rota = HIGH o CRITICAL
                            if any(x in name.lower() for x in ["balance", "supply", "owner", "admin"]):
                                severity = Severity.CRITICAL
                            else:
                                severity = Severity.HIGH
                        else:
                            # Assertion failure
                            severity = Severity.HIGH
                        
                        finding_id = self._generate_finding_id(
                            self.name,
                            f"invariant_violation:{name}",
                            ""
                        )
                        
                        # Formatear secuencia de llamadas
                        sequence_desc = self._format_call_sequence(call_sequence)
                        
                        findings.append(Finding(
                            id=finding_id,
                            title=f"Invariant Violation: {name}",
                            description=f"Echidna found a sequence of calls that breaks the invariant `{name}`.\n\nCall sequence:\n{sequence_desc}",
                            severity=severity,
                            world=self.world,
                            tool=self.name,
                            confidence="high",
                            function=name,
                            raw_output=test
                        ))
        
        return findings
    
    def _format_call_sequence(self, sequence: List) -> str:
        """Formatea la secuencia de llamadas para el reporte"""
        if not sequence:
            return "No sequence available"
        
        lines = []
        for i, call in enumerate(sequence, 1):
            if isinstance(call, dict):
                func = call.get("call", {})
                name = func.get("function", "unknown")
                args = func.get("arguments", [])
                sender = call.get("sender", "unknown")
                lines.append(f"{i}. {sender}: {name}({', '.join(map(str, args))})")
            else:
                lines.append(f"{i}. {call}")
        
        return '\n'.join(lines[:10])  # Limitar a 10 calls
