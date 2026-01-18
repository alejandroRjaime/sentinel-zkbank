"""
CrossChainReplayAnalyzer - Detecta vulnerabilidades de replay de mensajes en bridges.

Vulnerabilidades detectadas:
- Bridge sin tracking de mensajes ejecutados
- Forwarder sin nonce/messageId único
- Funciones que procesan mensajes sin verificar duplicados
- getSender() patterns sin estado persistente

Ejemplo vulnerable (TokenBridge + L1Forwarder):
    function executeTokenWithdrawal(address receiver, uint256 amount) external {
        if (msg.sender != address(l1Forwarder) || l1Forwarder.getSender() != otherBridge)
            revert Unauthorized();
        // VULNERABLE: No verifica si este withdrawal ya fue ejecutado
        totalDeposits -= amount;
        token.transfer(receiver, amount);
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


class CrossChainReplayAnalyzer(BaseAnalyzer):
    """
    Detecta vulnerabilidades de replay de mensajes en bridges cross-chain.
    """

    # Indicadores de que es un bridge/forwarder
    INDICATORS = [
        'bridge', 'forwarder', 'gateway', 'relay',
        'l1', 'l2', 'crosschain', 'cross_chain',
        'executewithdrawal', 'processmessage', 'relaymessage',
        'forwardcall', 'receivemessage', 'handlemessage',
        'getsender', 'originalsender', 'xdomainmessagesender',
        'otherbridge', 'remotebridge', 'counterpart',
        'l1forwarder', 'l2handler', 'messagestore'
    ]

    # Patrones de protección (si existen, probablemente OK)
    PROTECTION_PATTERNS = [
        r'executedmessages?\s*\[',
        r'usedmessages?\s*\[',
        r'processedmessages?\s*\[',
        r'executedwithdrawals?\s*\[',
        r'usednonces?\s*\[',
        r'executednonces?\s*\[',
        r'messagestatus\s*\[',
        r'isexecuted\s*\[',
        r'wasexecuted\s*\[',
        r'already\s*executed',
        r'already\s*processed',
        r'message\s*already',
        r'require\s*\(\s*!.*executed',
        r'require\s*\(\s*!.*processed',
        r'require\s*\(\s*!.*used',
        r'revert.*alreadyexecuted',
        r'revert.*alreadyprocessed',
    ]

    # Patrones de vulnerabilidad potencial
    VULNERABLE_PATTERNS = [
        (r'msg\.sender\s*[!=]=\s*(?:address\s*\()?\s*\w*forwarder', 'forwarder_check'),
        (r'\.getsender\s*\(\s*\)', 'getsender_call'),
        (r'execute.*withdrawal', 'execute_withdrawal'),
        (r'process.*message', 'process_message'),
        (r'relay.*message', 'relay_message'),
        (r'totald?eposits?\s*[-+]=', 'balance_modify'),
        (r'\.transfer\s*\(', 'token_transfer'),
        (r'\.safeTransfer\s*\(', 'safe_transfer'),
    ]

    LLM_PROMPT = """Analyze this Solidity contract for CROSS-CHAIN MESSAGE REPLAY vulnerabilities.

## What to look for:

### Message Replay Attack
A message from L2/other chain can be executed multiple times on L1 if:
- No tracking of which messages/withdrawals have been executed
- Missing `mapping(bytes32 => bool) executedMessages` or similar
- No nonce or messageId verification
- Only checks msg.sender but not message uniqueness

### VULNERABLE Pattern:
```solidity
function executeWithdrawal(address to, uint256 amount) external {{
    require(msg.sender == trustedForwarder);  // Only checks sender
    require(forwarder.getSender() == otherBridge);  // Only checks origin
    // MISSING: require(!executedMessages[messageHash]);
    // MISSING: executedMessages[messageHash] = true;
    token.transfer(to, amount);  // Can be called multiple times!
}}
```

### SAFE Pattern:
```solidity
mapping(bytes32 => bool) public executedMessages;

function executeWithdrawal(bytes32 messageId, address to, uint256 amount) external {{
    require(msg.sender == trustedForwarder);
    require(!executedMessages[messageId], "Already executed");  // Replay protection
    executedMessages[messageId] = true;  // Mark as executed
    token.transfer(to, amount);
}}
```

## Contract indicators found:
{indicators}

## Protection patterns found:
{protections}

## Vulnerable patterns found:
{vulnerable_patterns}

## Source code:
```solidity
{source}
```

## Response (JSON only):

If vulnerable:
```json
{{
  "findings": [
    {{
      "title": "Cross-Chain Message Replay Vulnerability",
      "severity": "CRITICAL",
      "line": <line_number or null>,
      "function": "function name",
      "description": "Detailed description",
      "exploit_scenario": "Step by step attack scenario",
      "recommendation": "Add mapping to track executed messages"
    }}
  ]
}}
```

If NOT vulnerable (has proper replay protection):
```json
{{"findings": []}}
```

IMPORTANT:
- CRITICAL if bridge handles value/tokens without replay protection
- HIGH if bridge/forwarder without tracking but no direct value transfer
- Check the ENTIRE contract for protection mappings before reporting
- If protection exists anywhere, it's likely safe"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.provider = config.get('provider', 'openai')
        self.model = config.get('model', 'gpt-4o')
        self.api_key = config.get('api_key', '')
        self.min_indicators = config.get('min_indicators', 1)
        self.timeout = config.get('timeout', 60)

        if HAS_OPENAI and self.api_key:
            self.client = openai.AsyncOpenAI(api_key=self.api_key)
        else:
            self.client = None

    @property
    def name(self) -> str:
        return "crosschain_replay"

    @property
    def world(self) -> World:
        return World.SOURCE

    def is_available(self) -> bool:
        return HAS_OPENAI and bool(self.api_key)

    def _count_indicators(self, source: str) -> Tuple[int, List[str]]:
        """Cuenta indicadores de bridge/forwarder."""
        source_lower = source.lower()
        found = []
        for ind in self.INDICATORS:
            if ind in source_lower:
                found.append(ind)
        return len(found), found

    def _find_protections(self, source: str) -> List[str]:
        """Busca patrones de protección contra replay."""
        source_lower = source.lower()
        found = []
        for pattern in self.PROTECTION_PATTERNS:
            if re.search(pattern, source_lower):
                found.append(pattern)
        return found

    def _find_vulnerable_patterns(self, source: str) -> List[Tuple[int, str, str]]:
        """Busca patrones potencialmente vulnerables con número de línea."""
        found = []
        lines = source.split('\n')
        for i, line in enumerate(lines, 1):
            line_lower = line.lower()
            for pattern, pattern_name in self.VULNERABLE_PATTERNS:
                if re.search(pattern, line_lower):
                    found.append((i, pattern_name, line.strip()))
        return found

    def _extract_contract_name(self, source: str) -> str:
        """Extrae nombre del contrato."""
        match = re.search(r'contract\s+(\w+)', source)
        return match.group(1) if match else "Unknown"

    def parse_output(self, output: str) -> List[Finding]:
        """Parsea salida JSON del LLM a Findings."""
        try:
            # Limpiar markdown
            if output.startswith('```'):
                output = re.sub(r'^```(?:json)?\n?', '', output)
                output = re.sub(r'\n?```$', '', output)

            data = json.loads(output.strip())
            findings_raw = data.get('findings', [])

            if not findings_raw:
                return []

            findings = []
            sev_map = {
                'critical': Severity.CRITICAL,
                'high': Severity.HIGH,
                'medium': Severity.MEDIUM,
                'low': Severity.LOW,
                'info': Severity.INFO
            }

            for f in findings_raw:
                try:
                    finding = Finding(
                        id=self._generate_finding_id(
                            self.name,
                            f.get('title', 'CrossChain Replay'),
                            str(f.get('line', 0))
                        ),
                        title=f.get('title', 'Cross-Chain Message Replay'),
                        description=f.get('description', ''),
                        severity=sev_map.get(f.get('severity', 'high').lower(), Severity.HIGH),
                        world=self.world,
                        tool=self.name,
                        confidence=f.get('confidence', 'high'),
                        line_number=f.get('line'),
                        function=f.get('function'),
                        raw_output=f  # exploit_scenario y recommendation van dentro de f
                    )
                    findings.append(finding)
                except Exception as e:
                    print(f"[{self.name}] Error parsing finding: {e}")
                    continue

            return findings

        except json.JSONDecodeError as e:
            print(f"[{self.name}] JSON parse error: {e}")
            return []

    def _basic_findings(self, vulnerable_patterns: List, contract_name: str, source: str) -> List[Finding]:
        """Genera findings básicos sin LLM cuando no está disponible."""
        if not vulnerable_patterns:
            return []

        # Si hay patrones vulnerables y NO hay protecciones, reportar
        protections = self._find_protections(source)
        if protections:
            return []  # Tiene protección, probablemente safe

        findings = []
        for line_num, pattern_name, line_code in vulnerable_patterns[:3]:
            findings.append(Finding(
                id=self._generate_finding_id(self.name, pattern_name, str(line_num)),
                title=f"Potential Cross-Chain Replay: {pattern_name}",
                description=f"Bridge/forwarder pattern '{pattern_name}' detected without visible replay protection mapping.",
                severity=Severity.HIGH,
                world=self.world,
                tool=self.name,
                confidence="low",
                line_number=line_num,
                location=line_code,
                raw_output={'pattern': pattern_name, 'basic_detection': True}
            ))

        return findings

    async def analyze(self, contract_path: Path) -> AnalysisResult:
        """
        Analiza un contrato en busca de vulnerabilidades de replay cross-chain.
        """
        start_time = time.time()

        if not self.enabled:
            return AnalysisResult(
                tool=self.name,
                world=self.world,
                success=True,
                findings=[],
                execution_time=0,
                raw_output='{"skipped": true, "reason": "Analyzer disabled"}'
            )

        try:
            source = contract_path.read_text()
        except Exception as e:
            return AnalysisResult(
                tool=self.name,
                world=self.world,
                success=False,
                findings=[],
                error=f"Error reading file: {e}",
                execution_time=time.time() - start_time
            )

        contract_name = self._extract_contract_name(source)

        # Pre-filtro: verificar indicadores de bridge
        indicator_count, indicators = self._count_indicators(source)

        if indicator_count < self.min_indicators:
            return AnalysisResult(
                tool=self.name,
                world=self.world,
                success=True,
                findings=[],
                execution_time=time.time() - start_time,
                raw_output=json.dumps({
                    'skipped': True,
                    'reason': f'Only {indicator_count} bridge indicators (min: {self.min_indicators})',
                    'contract': contract_name
                })
            )

        # Buscar protecciones y patrones vulnerables
        protections = self._find_protections(source)
        vulnerable_patterns = self._find_vulnerable_patterns(source)

        # Si no hay cliente LLM, usar detección básica
        if not self.client:
            findings = self._basic_findings(vulnerable_patterns, contract_name, source)
            return AnalysisResult(
                tool=self.name,
                world=self.world,
                success=True,
                findings=findings,
                execution_time=time.time() - start_time,
                raw_output=json.dumps({
                    'contract': contract_name,
                    'indicators': indicators,
                    'protections': protections,
                    'llm_used': False
                })
            )

        # Preparar prompt para LLM
        prompt = self.LLM_PROMPT.format(
            indicators=indicators,
            protections=protections if protections else "None found",
            vulnerable_patterns=[(p[0], p[1]) for p in vulnerable_patterns[:10]],
            source=source[:12000]  # Limitar tamaño
        )

        try:
            response = await asyncio.wait_for(
                self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system",
                         "content": "Smart contract security auditor specializing in cross-chain bridges. Respond only with valid JSON."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.1,
                    max_tokens=2000
                ),
                timeout=self.timeout
            )

            llm_output = response.choices[0].message.content.strip()
            findings = self.parse_output(llm_output)

            return AnalysisResult(
                tool=self.name,
                world=self.world,
                success=True,
                findings=findings,
                execution_time=time.time() - start_time,
                raw_output=json.dumps({
                    'contract': contract_name,
                    'indicators': indicators,
                    'protections': protections,
                    'vulnerable_patterns': len(vulnerable_patterns),
                    'llm_used': True,
                    'model': self.model,
                    'llm_response': llm_output
                })
            )

        except asyncio.TimeoutError:
            print(f"[{self.name}] LLM timeout after {self.timeout}s")
            findings = self._basic_findings(vulnerable_patterns, contract_name, source)
            return AnalysisResult(
                tool=self.name,
                world=self.world,
                success=True,
                findings=findings,
                execution_time=time.time() - start_time,
                raw_output=json.dumps({'contract': contract_name, 'llm_timeout': True})
            )

        except Exception as e:
            print(f"[{self.name}] LLM error: {e}")
            findings = self._basic_findings(vulnerable_patterns, contract_name, source)
            return AnalysisResult(
                tool=self.name,
                world=self.world,
                success=True,
                findings=findings,
                error=str(e),
                execution_time=time.time() - start_time,
                raw_output=json.dumps({'contract': contract_name, 'llm_error': str(e)})
            )


# Test standalone
if __name__ == "__main__":
    import sys
    import os


    async def main():
        if len(sys.argv) < 2:
            print("Usage: python crosschain_replay_analyzer.py <contract.sol>")
            sys.exit(1)

        config = {
            'enabled': True,
            'provider': 'openai',
            'model': 'gpt-4o',
            'api_key': os.environ.get('OPENAI_API_KEY', ''),
            'min_indicators': 1
        }

        analyzer = CrossChainReplayAnalyzer(config)
        result = await analyzer.analyze(Path(sys.argv[1]))

        print(f"\n{'=' * 60}")
        print(f"CrossChain Replay Analysis: {sys.argv[1]}")
        print(f"{'=' * 60}")
        print(f"Tool: {result.tool}")
        print(f"Success: {result.success}")
        print(f"Time: {result.execution_time:.2f}s")
        print(f"Raw: {result.raw_output}")

        if not result.findings:
            print("\n✅ No cross-chain replay vulnerabilities found")
        else:
            print(f"\n⚠️  Found {len(result.findings)} vulnerabilities:\n")
            for f in result.findings:
                print(f"[{f.severity.name}] {f.title}")
                print(f"  Line: {f.line_number}")
                print(f"  Function: {f.function}")
                print(f"  Description: {f.description}")
                if f.recommendation:
                    print(f"  Fix: {f.recommendation}")
                print()


    asyncio.run(main())