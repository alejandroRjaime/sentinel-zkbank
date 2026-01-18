"""
ArbitraryCallAnalyzer - Detecta vulnerabilidades de llamadas externas arbitrarias.

Vulnerabilidades detectadas:
- Usuario controla address target en external call
- Usuario controla data/calldata en call
- Falta de whitelist en target addresses
- Flash loan callbacks con ejecución arbitraria
- functionCall sin validación de destino

Ejemplo vulnerable (TrusterLenderPool):
    function flashLoan(uint256 amount, address borrower, address target, bytes calldata data)
        external nonReentrant returns (bool) {
        ...
        target.functionCall(data);  // VULNERABLE: usuario controla target y data
        ...
    }
"""

from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional
import re
import json
import asyncio
import time

try:
    from .base import BaseAnalyzer, AnalysisResult, Finding, Severity, World
except ImportError:
    from base import BaseAnalyzer, AnalysisResult, Finding, Severity, World

try:
    import openai
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False


class ArbitraryCallAnalyzer(BaseAnalyzer):
    """
    Detecta llamadas externas con parámetros controlados por usuario.
    """
    
    # Patterns de llamadas externas peligrosas
    DANGEROUS_CALL_PATTERNS = [
        (r'(\w+)\.call\s*\{?\s*(?:value\s*:\s*[^}]+)?\}?\s*\(([^)]*)\)', 'call'),
        (r'(\w+)\.functionCall\s*\(([^)]*)\)', 'functionCall'),
        (r'(\w+)\.functionCallWithValue\s*\(([^)]*)\)', 'functionCallWithValue'),
        (r'(\w+)\.delegatecall\s*\(([^)]*)\)', 'delegatecall'),
        (r'(\w+)\.staticcall\s*\(([^)]*)\)', 'staticcall'),
    ]
    
    INDICATORS = [
        '.call(', '.call{', 'functionCall(', 'functionCallWithValue(',
        'delegatecall(', 'target.', 'receiver.', '_to.call',
        'Address.', 'calldata data', 'bytes calldata', 'bytes memory data'
    ]
    
    PROTECTION_PATTERNS = [
        r'require\s*\([^)]*target[^)]*(?:==|!=)',
        r'whitelist\[',
        r'allowedTargets\[',
        r'isWhitelisted\(',
        r'onlyOwner|onlyAdmin',
        r'target\s*==\s*address\(this\)',
    ]
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.provider = config.get('provider', 'openai')
        self.model = config.get('model', 'gpt-4o')
        self.api_key = config.get('api_key', '')
        self.min_indicators = config.get('min_indicators', 1)
        
        if HAS_OPENAI and self.api_key:
            self.client = openai.AsyncOpenAI(api_key=self.api_key)
        else:
            self.client = None
    
    @property
    def name(self) -> str:
        return "arbitrary_call"
    
    @property
    def world(self) -> World:
        return World.SOURCE
    
    def is_available(self) -> bool:
        return HAS_OPENAI and bool(self.api_key)
    
    def parse_output(self, output: str) -> List[Finding]:
        """Parsea salida JSON del LLM a Findings."""
        try:
            if output.startswith('```'):
                output = re.sub(r'^```(?:json)?\n?', '', output)
                output = re.sub(r'\n?```$', '', output)
            data = json.loads(output)
            return self._parse_findings(data.get('findings', []))
        except:
            return []
    
    def _count_indicators(self, source: str) -> int:
        count = 0
        source_lower = source.lower()
        for indicator in self.INDICATORS:
            if indicator.lower() in source_lower:
                count += 1
        return count
    
    def _find_dangerous_calls(self, source: str) -> List[Tuple[int, str, str, str]]:
        dangerous = []
        lines = source.split('\n')
        for i, line in enumerate(lines, 1):
            for pattern, call_type in self.DANGEROUS_CALL_PATTERNS:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    target = match.group(1) if match.lastindex >= 1 else 'unknown'
                    dangerous.append((i, line.strip(), target, call_type))
        return dangerous
    
    def _has_protections(self, source: str, target_name: str) -> bool:
        for pattern in self.PROTECTION_PATTERNS:
            if re.search(pattern, source, re.IGNORECASE):
                return True
        return False
    
    def _extract_function_name(self, source: str, line_num: int) -> str:
        lines = source.split('\n')
        for i in range(line_num - 1, -1, -1):
            func_match = re.match(r'\s*function\s+(\w+)', lines[i])
            if func_match:
                return func_match.group(1)
        return ""
    
    async def analyze(
        self, 
        contract_path: Path,
        bytecode: Optional[str] = None,
        address: Optional[str] = None
    ) -> AnalysisResult:
        start_time = time.time()
        
        if not self.enabled:
            return AnalysisResult(tool=self.name, world=self.world, success=True, 
                                  findings=[], execution_time=0)
        
        try:
            source = contract_path.read_text(encoding='utf-8')
        except Exception as e:
            return AnalysisResult(tool=self.name, world=self.world, success=False,
                                  error=str(e), execution_time=time.time() - start_time)
        
        # Pre-filtro
        if self._count_indicators(source) < self.min_indicators:
            return AnalysisResult(tool=self.name, world=self.world, success=True,
                                  findings=[], execution_time=time.time() - start_time)
        
        dangerous_calls = self._find_dangerous_calls(source)
        if not dangerous_calls:
            return AnalysisResult(tool=self.name, world=self.world, success=True,
                                  findings=[], execution_time=time.time() - start_time)
        
        # Filtrar protegidas
        unprotected = [(ln, code, tgt, ct) for ln, code, tgt, ct in dangerous_calls 
                       if not self._has_protections(source, tgt)]
        
        if not unprotected:
            return AnalysisResult(tool=self.name, world=self.world, success=True,
                                  findings=[], execution_time=time.time() - start_time)
        
        # Análisis
        if self.client:
            findings = await self._llm_analyze(source, unprotected, contract_path.name)
        else:
            findings = self._basic_findings(unprotected, contract_path.name, source)
        
        return AnalysisResult(tool=self.name, world=self.world, success=True,
                              findings=findings, execution_time=time.time() - start_time)
    
    def _basic_findings(self, calls: List[Tuple], contract_name: str, source: str) -> List[Finding]:
        findings = []
        for line_num, code, target, call_type in calls:
            severity = Severity.CRITICAL if call_type == 'delegatecall' else Severity.HIGH
            func_name = self._extract_function_name(source, line_num)
            
            finding = Finding(
                id=self._generate_finding_id(self.name, f"arbitrary_{call_type}", str(line_num)),
                title=f"Arbitrary {call_type} to user-controlled address",
                description=f"The function performs {call_type} where target '{target}' may be user-controlled.",
                severity=severity,
                world=self.world,
                tool=self.name,
                confidence="medium",
                location=contract_name,
                line_number=line_num,
                function=func_name,
                raw_output={"code": code, "target": target, "call_type": call_type}
            )
            findings.append(finding)
        return findings
    
    async def _llm_analyze(self, source: str, calls: List[Tuple], contract_name: str) -> List[Finding]:
        contexts = []
        for line_num, code, target, call_type in calls[:5]:
            func_name = self._extract_function_name(source, line_num)
            contexts.append({
                'line': line_num, 'code': code, 'target': target,
                'call_type': call_type, 'function': func_name
            })
        
        prompt = f"""Analyze for ARBITRARY CALL vulnerabilities.
Contract: {contract_name}
Dangerous calls: {json.dumps(contexts, indent=2)}

Check: user controls target/data, no whitelist, delegatecall to user address.
Source:
```solidity
{source[:10000]}
```

JSON only:
{{"findings": [{{"title": "...", "severity": "critical|high|medium|low", "line": N, "function": "...", "description": "...", "confidence": "high|medium|low"}}]}}
Empty if safe: {{"findings": []}}"""

        try:
            client = openai.AsyncOpenAI(api_key=self.api_key)
            try:
                response = await asyncio.wait_for(
                    client.chat.completions.create(
                        model=self.model,
                        messages=[{"role": "system", "content": "Smart contract auditor. JSON only."},
                                  {"role": "user", "content": prompt}],
                        temperature=0.1, max_tokens=2000
                    ),
                    timeout=self.timeout
                )
            finally:
                await client.close()
            return self.parse_output(response.choices[0].message.content.strip())
        except Exception as e:
            print(f"[{self.name}] LLM error: {e}")
            return self._basic_findings(calls, contract_name, source)
    
    def _parse_findings(self, raw: List[Dict]) -> List[Finding]:
        findings = []
        sev_map = {'critical': Severity.CRITICAL, 'high': Severity.HIGH, 
                   'medium': Severity.MEDIUM, 'low': Severity.LOW, 'info': Severity.INFO}
        
        for f in raw:
            try:
                findings.append(Finding(
                    id=self._generate_finding_id(self.name, f.get('title', ''), str(f.get('line', 0))),
                    title=f.get('title', 'Arbitrary Call'),
                    description=f.get('description', ''),
                    severity=sev_map.get(f.get('severity', 'medium').lower(), Severity.MEDIUM),
                    world=self.world,
                    tool=self.name,
                    confidence=f.get('confidence', 'medium'),
                    line_number=f.get('line'),
                    function=f.get('function'),
                    raw_output=f
                ))
            except:
                continue
        return findings
