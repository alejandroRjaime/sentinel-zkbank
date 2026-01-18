"""
DelegatecallLoopAnalyzer - Detecta delegatecall dentro de loops.

Vulnerabilidades detectadas:
- delegatecall dentro de for/while loop
- Multicall con delegatecall (msg.value reuse)
- Batch execution sin aislamiento
- msg.value reutilizado en múltiples llamadas

Ejemplo vulnerable (Multicall):
    function multicall(bytes[] calldata data) external payable returns (bytes[] memory) {
        for (uint256 i = 0; i < data.length; i++) {
            (bool success, bytes memory result) = address(this).delegatecall(data[i]);
            // VULNERABLE: msg.value se puede usar múltiples veces!
            require(success);
        }
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


class DelegatecallLoopAnalyzer(BaseAnalyzer):
    """
    Detecta delegatecall dentro de loops (Multicall exploit).
    msg.value persiste en todas las iteraciones del loop.
    """
    
    DELEGATECALL_PATTERNS = [
        r'\.delegatecall\s*\(',
        r'functionDelegateCall\s*\(',
    ]
    
    LOOP_PATTERNS = [
        (r'for\s*\([^)]*\)\s*\{', 'for'),
        (r'while\s*\([^)]*\)\s*\{', 'while'),
        (r'do\s*\{', 'do-while'),
    ]
    
    MULTICALL_INDICATORS = ['multicall', 'Multicall', 'batchCall', 'aggregate',
                           'bytes[] calldata', 'bytes[] memory', 'Call[]']
    
    PROTECTION_PATTERNS = [
        r'_msgValueUsed', r'valueUsed\s*\+=', r'msg\.value\s*-=',
        r'require\s*\([^)]*msg\.value\s*=='
    ]
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.provider = config.get('provider', 'openai')
        self.model = config.get('model', 'gpt-4o')
        self.api_key = config.get('api_key', '')
        
        if HAS_OPENAI and self.api_key:
            self.client = openai.AsyncOpenAI(api_key=self.api_key)
        else:
            self.client = None
    
    @property
    def name(self) -> str:
        return "delegatecall_loop"
    
    @property
    def world(self) -> World:
        return World.SOURCE
    
    def is_available(self) -> bool:
        return HAS_OPENAI and bool(self.api_key)
    
    def parse_output(self, output: str) -> List[Finding]:
        try:
            if output.startswith('```'):
                output = re.sub(r'^```(?:json)?\n?', '', output)
                output = re.sub(r'\n?```$', '', output)
            data = json.loads(output)
            return self._parse_findings(data.get('findings', []))
        except:
            return []
    
    def _has_delegatecall(self, source: str) -> bool:
        return any(re.search(p, source, re.I) for p in self.DELEGATECALL_PATTERNS)
    
    def _has_loops(self, source: str) -> bool:
        return any(re.search(p, source) for p, _ in self.LOOP_PATTERNS)
    
    def _has_multicall(self, source: str) -> bool:
        return any(ind.lower() in source.lower() for ind in self.MULTICALL_INDICATORS)
    
    def _has_msgvalue(self, source: str) -> bool:
        return 'msg.value' in source
    
    def _has_protections(self, source: str) -> bool:
        return any(re.search(p, source, re.I) for p in self.PROTECTION_PATTERNS)
    
    def _find_delegatecall_in_loop(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        
        in_loop = False
        loop_start = 0
        brace_count = 0
        current_func = ""
        
        for i, line in enumerate(lines, 1):
            func_match = re.match(r'\s*function\s+(\w+)', line)
            if func_match:
                current_func = func_match.group(1)
            
            for pattern, loop_type in self.LOOP_PATTERNS:
                if re.search(pattern, line):
                    in_loop = True
                    loop_start = i
                    brace_count = line.count('{') - line.count('}')
                    break
            
            if in_loop:
                brace_count += line.count('{') - line.count('}')
                
                for dc_pattern in self.DELEGATECALL_PATTERNS:
                    if re.search(dc_pattern, line):
                        findings.append({
                            'loop_line': loop_start,
                            'dc_line': i,
                            'function': current_func,
                            'code': line.strip()
                        })
                
                if brace_count <= 0:
                    in_loop = False
        
        return findings
    
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
        
        # Pre-filtro: necesita delegatecall
        if not self._has_delegatecall(source):
            return AnalysisResult(tool=self.name, world=self.world, success=True,
                                  findings=[], execution_time=time.time() - start_time)
        
        has_loops = self._has_loops(source)
        has_multicall = self._has_multicall(source)
        
        if not has_loops and not has_multicall:
            return AnalysisResult(tool=self.name, world=self.world, success=True,
                                  findings=[], execution_time=time.time() - start_time)
        
        dc_in_loops = self._find_delegatecall_in_loop(source)
        
        # Si no hay dc directo en loop pero hay multicall pattern
        if not dc_in_loops and has_multicall:
            dc_in_loops = [{'function': 'multicall', 'dc_line': 0, 'loop_line': 0, 'code': ''}]
        
        if not dc_in_loops:
            return AnalysisResult(tool=self.name, world=self.world, success=True,
                                  findings=[], execution_time=time.time() - start_time)
        
        # Verificar protecciones
        if self._has_protections(source):
            return AnalysisResult(tool=self.name, world=self.world, success=True,
                                  findings=[], execution_time=time.time() - start_time)
        
        has_msgvalue = self._has_msgvalue(source)
        
        if self.client:
            findings = await self._llm_analyze(source, dc_in_loops, has_msgvalue, contract_path.name)
        else:
            findings = self._basic_findings(dc_in_loops, has_msgvalue, contract_path.name)
        
        return AnalysisResult(tool=self.name, world=self.world, success=True,
                              findings=findings, execution_time=time.time() - start_time)
    
    def _basic_findings(self, dc_in_loops: List[Dict], has_msgvalue: bool, 
                        contract_name: str) -> List[Finding]:
        findings = []
        severity = Severity.CRITICAL if has_msgvalue else Severity.HIGH
        
        for dc in dc_in_loops:
            finding = Finding(
                id=self._generate_finding_id(self.name, "dc_loop", str(dc.get('dc_line', 0))),
                title="delegatecall in loop - msg.value reuse",
                description=(
                    f"Function '{dc.get('function', 'unknown')}' has delegatecall inside loop. "
                    f"msg.value persists across iterations allowing attacker to reuse ETH."
                ),
                severity=severity,
                world=self.world,
                tool=self.name,
                confidence="high" if has_msgvalue else "medium",
                location=contract_name,
                line_number=dc.get('dc_line'),
                function=dc.get('function'),
                raw_output={"has_msgvalue": has_msgvalue, "loop_line": dc.get('loop_line')}
            )
            findings.append(finding)
        return findings
    
    async def _llm_analyze(self, source: str, dc_in_loops: List[Dict],
                           has_msgvalue: bool, contract_name: str) -> List[Finding]:
        prompt = f"""Analyze for DELEGATECALL IN LOOP vulnerabilities.
Contract: {contract_name}
Uses msg.value: {has_msgvalue}
Delegatecalls in loops: {json.dumps(dc_in_loops)}

CRITICAL: When delegatecall is in a loop, msg.value is the SAME for ALL iterations.
Attack: multicall([deposit(), deposit(), deposit()]) with 1 ETH → credited 3 ETH

Source:
```solidity
{source[:10000]}
```

JSON only:
{{"findings": [{{"title": "...", "severity": "critical|high|medium|low", "line": N, "function": "...", "description": "...", "confidence": "high|medium|low"}}]}}
Empty if not exploitable: {{"findings": []}}"""

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
            return self._basic_findings(dc_in_loops, has_msgvalue, contract_name)
    
    def _parse_findings(self, raw: List[Dict]) -> List[Finding]:
        findings = []
        sev_map = {'critical': Severity.CRITICAL, 'high': Severity.HIGH,
                   'medium': Severity.MEDIUM, 'low': Severity.LOW, 'info': Severity.INFO}
        
        for f in raw:
            try:
                findings.append(Finding(
                    id=self._generate_finding_id(self.name, f.get('title', ''), str(f.get('line', 0))),
                    title=f.get('title', 'Delegatecall Loop'),
                    description=f.get('description', ''),
                    severity=sev_map.get(f.get('severity', 'high').lower(), Severity.HIGH),
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
