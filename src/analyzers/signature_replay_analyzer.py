"""
SignatureReplayAnalyzer - Detecta vulnerabilidades de replay en firmas.

Vulnerabilidades detectadas:
- Falta de nonce (misma firma reutilizable)
- Falta de chainId (replay cross-chain)
- Falta de deadline/expiration (firma nunca expira)
- Falta de domain separator (EIP-712 incompleto)
- Firma no marcada como usada después de ejecución

Ejemplo vulnerable (TokenBridge):
    function executeAction(bytes memory signature, address to, uint256 amount) {
        bytes32 hash = keccak256(abi.encodePacked(to, amount));
        address signer = ECDSA.recover(hash, signature);
        require(signer == operator);
        // VULNERABLE: no hay nonce ni chainId
        token.transfer(to, amount);
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


class SignatureReplayAnalyzer(BaseAnalyzer):
    """
    Detecta vulnerabilidades de replay en verificación de firmas.
    Crítico en bridges, meta-transactions, permits.
    """
    
    SIGNATURE_PATTERNS = [
        (r'ecrecover\s*\(', 'ecrecover'),
        (r'ECDSA\.recover\s*\(', 'ECDSA.recover'),
        (r'ECDSA\.tryRecover\s*\(', 'ECDSA.tryRecover'),
        (r'SignatureChecker\.isValidSignatureNow\s*\(', 'SignatureChecker'),
        (r'isValidSignature\s*\(', 'isValidSignature'),
        (r'\.permit\s*\(', 'permit'),
        (r'recoverSigner\s*\(', 'recoverSigner'),
        (r'verifySignature\s*\(', 'verifySignature'),
    ]
    
    PROTECTION_PATTERNS = {
        'nonce': [r'\bnonces?\b', r'_useNonce\s*\(', r'_nonces\[', r'nonceUsed\['],
        'chainId': [r'block\.chainid', r'chainId', r'CHAIN_ID', r'getChainId\(\)'],
        'deadline': [r'\bdeadline\b', r'\bexpir', r'validUntil', r'block\.timestamp\s*[<>]'],
        'domain': [r'DOMAIN_SEPARATOR', r'domainSeparator', r'EIP712', r'_domainSeparatorV4'],
        'used': [r'usedSignatures?\[', r'usedHashes?\[', r'executed\[', r'processed\['],
    }
    
    INDICATORS = ['ecrecover', 'ECDSA', 'signature', 'Signature', 'recover', 
                  'permit', 'signed', 'signer', 'v, r, s']
    
    HIGH_RISK_CONTEXTS = ['bridge', 'Bridge', 'L1', 'L2', 'relay', 'Relay', 
                          'forwarder', 'Forwarder', 'meta-tx', 'metatx', 'gasless']
    
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
        return "signature_replay"
    
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
    
    def _count_indicators(self, source: str) -> int:
        return sum(1 for ind in self.INDICATORS if ind in source)
    
    def _find_signature_usage(self, source: str) -> List[Tuple[int, str, str]]:
        usages = []
        lines = source.split('\n')
        for i, line in enumerate(lines, 1):
            for pattern, sig_type in self.SIGNATURE_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    usages.append((i, line.strip(), sig_type))
                    break
        return usages
    
    def _check_protections(self, source: str) -> Dict[str, bool]:
        protections = {}
        for prot_name, patterns in self.PROTECTION_PATTERNS.items():
            protections[prot_name] = any(re.search(p, source, re.I) for p in patterns)
        return protections
    
    def _is_high_risk(self, source: str) -> bool:
        return any(ctx.lower() in source.lower() for ctx in self.HIGH_RISK_CONTEXTS)
    
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
        
        sig_usages = self._find_signature_usage(source)
        if not sig_usages:
            return AnalysisResult(tool=self.name, world=self.world, success=True,
                                  findings=[], execution_time=time.time() - start_time)
        
        protections = self._check_protections(source)
        missing = [k for k, v in protections.items() if not v]
        
        # Si tiene nonce y chainId, probablemente OK
        if protections.get('nonce') and protections.get('chainId') and len(missing) <= 1:
            return AnalysisResult(tool=self.name, world=self.world, success=True,
                                  findings=[], execution_time=time.time() - start_time)
        
        is_high_risk = self._is_high_risk(source)
        
        if self.client:
            findings = await self._llm_analyze(source, sig_usages, protections, 
                                                missing, is_high_risk, contract_path.name)
        else:
            findings = self._basic_findings(sig_usages, missing, is_high_risk, 
                                            contract_path.name, source)
        
        return AnalysisResult(tool=self.name, world=self.world, success=True,
                              findings=findings, execution_time=time.time() - start_time)
    
    def _basic_findings(self, usages: List[Tuple], missing: List[str], 
                        is_high_risk: bool, contract_name: str, source: str) -> List[Finding]:
        findings = []
        if not missing:
            return findings
        
        if 'nonce' in missing and 'chainId' in missing:
            severity = Severity.CRITICAL
        elif 'nonce' in missing or 'chainId' in missing:
            severity = Severity.HIGH if is_high_risk else Severity.HIGH
        else:
            severity = Severity.MEDIUM
        
        if is_high_risk and severity == Severity.HIGH:
            severity = Severity.CRITICAL
        
        for line_num, code, sig_type in usages[:2]:
            func_name = self._extract_function_name(source, line_num)
            finding = Finding(
                id=self._generate_finding_id(self.name, "replay_" + "_".join(missing[:2]), str(line_num)),
                title=f"Signature replay - Missing {', '.join(missing[:2])}",
                description=f"Uses {sig_type} but missing: {', '.join(missing)}. Signatures may be replayed.",
                severity=severity,
                world=self.world,
                tool=self.name,
                confidence="high" if len(missing) >= 2 else "medium",
                location=contract_name,
                line_number=line_num,
                function=func_name,
                raw_output={"missing": missing, "high_risk": is_high_risk, "sig_type": sig_type}
            )
            findings.append(finding)
        return findings
    
    async def _llm_analyze(self, source: str, sig_usages: List[Tuple], 
                           protections: Dict, missing: List[str], 
                           is_high_risk: bool, contract_name: str) -> List[Finding]:
        contexts = []
        for line_num, code, sig_type in sig_usages[:3]:
            func_name = self._extract_function_name(source, line_num)
            contexts.append({'line': line_num, 'type': sig_type, 'function': func_name})
        
        prompt = f"""Analyze for SIGNATURE REPLAY vulnerabilities.
Contract: {contract_name}
High-risk (bridge/relay): {is_high_risk}
Signatures at: {json.dumps(contexts)}
Protections: {json.dumps(protections)}
Missing: {missing}

Replay vectors:
- No nonce = same signature reusable
- No chainId = cross-chain replay  
- No deadline = signature never expires

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
                        messages=[{"role": "system",
                                   "content": "Smart contract auditor specializing in signatures. JSON only."},
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
            return self._basic_findings(sig_usages, missing, is_high_risk, contract_name, source)
    
    def _parse_findings(self, raw: List[Dict]) -> List[Finding]:
        findings = []
        sev_map = {'critical': Severity.CRITICAL, 'high': Severity.HIGH,
                   'medium': Severity.MEDIUM, 'low': Severity.LOW, 'info': Severity.INFO}
        
        for f in raw:
            try:
                findings.append(Finding(
                    id=self._generate_finding_id(self.name, f.get('title', ''), str(f.get('line', 0))),
                    title=f.get('title', 'Signature Replay'),
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
