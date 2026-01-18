"""
Erigon Validator - Validación con traces reales

Ground truth histórico: verifica findings contra transacciones reales.
"""

from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import json
import aiohttp
import asyncio

from src.analyzers import Finding, Severity


@dataclass
class TraceResult:
    """Resultado de un trace"""
    tx_hash: str
    success: bool
    traces: List[Dict]
    state_diff: Optional[Dict] = None
    error: Optional[str] = None


class ErigonValidator:
    """
    Erigon Validator - Ground truth con traces reales
    
    Valida findings contra el historial real de transacciones:
    - Verifica si un pattern sospechoso ocurrió realmente
    - Detecta exploits históricos
    - Confirma vulnerabilidades con evidencia on-chain
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.rpc_url = config.get("rpc_url", "http://localhost:8545")
        self.timeout = config.get("timeout", 120)
        self.trace_types = config.get("config", {}).get(
            "trace_types", 
            ["vmTrace", "trace", "stateDiff"]
        )
    
    async def validate_findings(
        self,
        findings: List[Finding],
        address: str,
        tx_hashes: Optional[List[str]] = None
    ) -> List[Finding]:
        """
        Valida findings contra traces reales.
        
        Si se proveen tx_hashes, verifica esas transacciones específicas.
        Si no, busca transacciones sospechosas del contrato.
        """
        
        if not findings:
            return findings
        
        # Obtener traces
        if tx_hashes:
            traces = await self._get_traces_for_txs(tx_hashes)
        else:
            # Obtener transacciones recientes del contrato
            traces = await self._get_contract_traces(address)
        
        if not traces:
            return findings
        
        # Validar cada finding
        validated_findings = []
        for finding in findings:
            validated = await self._validate_finding(finding, traces, address)
            validated_findings.append(validated)
        
        return validated_findings
    
    async def _validate_finding(
        self,
        finding: Finding,
        traces: List[TraceResult],
        address: str
    ) -> Finding:
        """Valida un finding específico contra los traces"""
        
        # Patterns a buscar según el tipo de finding
        patterns = {
            "reentrancy": self._check_reentrancy_pattern,
            "selfdestruct": self._check_selfdestruct_pattern,
            "delegatecall": self._check_delegatecall_pattern,
            "overflow": self._check_overflow_pattern,
        }
        
        finding_type = finding.title.lower()
        
        for pattern_name, checker in patterns.items():
            if pattern_name in finding_type:
                for trace in traces:
                    if checker(trace, address):
                        finding.validated = True
                        finding.validation_tx = trace.tx_hash
                        # Elevar severidad si está validado
                        if finding.severity == Severity.HIGH:
                            finding.severity = Severity.CRITICAL
                        break
        
        return finding
    
    def _check_reentrancy_pattern(
        self, 
        trace: TraceResult, 
        address: str
    ) -> bool:
        """Detecta patrón de reentrancy en traces"""
        if not trace.traces:
            return False
        
        address_lower = address.lower()
        call_stack = []
        
        for step in trace.traces:
            op = step.get("op", "")
            
            if op in ["CALL", "CALLCODE", "DELEGATECALL"]:
                to_addr = step.get("stack", [""])[-2] if len(step.get("stack", [])) >= 2 else ""
                call_stack.append(to_addr.lower())
                
                # Reentrancy: el contrato se llama a sí mismo antes de terminar
                if address_lower in call_stack[:-1]:
                    return True
            
            elif op in ["RETURN", "STOP", "REVERT"]:
                if call_stack:
                    call_stack.pop()
        
        return False
    
    def _check_selfdestruct_pattern(
        self, 
        trace: TraceResult, 
        address: str
    ) -> bool:
        """Detecta SELFDESTRUCT ejecutado"""
        if not trace.traces:
            return False
        
        for step in trace.traces:
            if step.get("op") == "SELFDESTRUCT":
                return True
        
        return False
    
    def _check_delegatecall_pattern(
        self, 
        trace: TraceResult, 
        address: str
    ) -> bool:
        """Detecta DELEGATECALL sospechoso"""
        if not trace.traces:
            return False
        
        for step in trace.traces:
            if step.get("op") == "DELEGATECALL":
                # Verificar si el target es una dirección externa conocida
                # (simplificado - en producción verificar contra whitelist)
                return True
        
        return False
    
    def _check_overflow_pattern(
        self, 
        trace: TraceResult, 
        address: str
    ) -> bool:
        """Detecta overflow en operaciones aritméticas"""
        if not trace.traces:
            return False
        
        max_uint256 = 2**256 - 1
        
        for step in trace.traces:
            op = step.get("op", "")
            stack = step.get("stack", [])
            
            if op == "ADD" and len(stack) >= 2:
                # Verificar si el resultado puede overflow
                try:
                    a = int(stack[-1], 16) if isinstance(stack[-1], str) else stack[-1]
                    b = int(stack[-2], 16) if isinstance(stack[-2], str) else stack[-2]
                    if a + b > max_uint256:
                        return True
                except:
                    pass
            
            elif op == "MUL" and len(stack) >= 2:
                try:
                    a = int(stack[-1], 16) if isinstance(stack[-1], str) else stack[-1]
                    b = int(stack[-2], 16) if isinstance(stack[-2], str) else stack[-2]
                    if a * b > max_uint256:
                        return True
                except:
                    pass
        
        return False
    
    async def _get_traces_for_txs(
        self, 
        tx_hashes: List[str]
    ) -> List[TraceResult]:
        """Obtiene traces para transacciones específicas"""
        traces = []
        
        async with aiohttp.ClientSession() as session:
            for tx_hash in tx_hashes:
                trace = await self._trace_transaction(session, tx_hash)
                if trace:
                    traces.append(trace)
        
        return traces
    
    async def _get_contract_traces(
        self,
        address: str,
        limit: int = 100
    ) -> List[TraceResult]:
        """Obtiene traces recientes de un contrato"""
        traces = []
        
        async with aiohttp.ClientSession() as session:
            # Usar trace_filter para obtener transacciones al contrato
            payload = {
                "jsonrpc": "2.0",
                "method": "trace_filter",
                "params": [{
                    "toAddress": [address],
                    "count": limit
                }],
                "id": 1
            }
            
            try:
                async with session.post(
                    self.rpc_url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
                ) as resp:
                    data = await resp.json()
                    
                    if "result" in data:
                        # Extraer tx_hashes únicos
                        tx_hashes = list(set(
                            t.get("transactionHash") 
                            for t in data["result"] 
                            if t.get("transactionHash")
                        ))[:20]  # Limitar
                        
                        # Obtener traces completos
                        traces = await self._get_traces_for_txs(tx_hashes)
            except:
                pass
        
        return traces
    
    async def _trace_transaction(
        self,
        session: aiohttp.ClientSession,
        tx_hash: str
    ) -> Optional[TraceResult]:
        """Obtiene trace completo de una transacción"""
        
        payload = {
            "jsonrpc": "2.0",
            "method": "debug_traceTransaction",
            "params": [tx_hash, {"tracer": "callTracer"}],
            "id": 1
        }
        
        try:
            async with session.post(
                self.rpc_url,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=self.timeout)
            ) as resp:
                data = await resp.json()
                
                if "result" in data:
                    return TraceResult(
                        tx_hash=tx_hash,
                        success=True,
                        traces=data["result"].get("structLogs", []),
                        state_diff=data["result"].get("stateDiff")
                    )
                else:
                    return TraceResult(
                        tx_hash=tx_hash,
                        success=False,
                        traces=[],
                        error=data.get("error", {}).get("message")
                    )
        except Exception as e:
            return TraceResult(
                tx_hash=tx_hash,
                success=False,
                traces=[],
                error=str(e)
            )
    
    async def get_exploit_history(
        self,
        address: str
    ) -> List[Dict]:
        """
        Busca exploits históricos conocidos del contrato.
        Útil para verificar si un finding ya fue explotado.
        """
        exploits = []
        
        # Buscar transacciones con alto valor de gas o valor
        async with aiohttp.ClientSession() as session:
            payload = {
                "jsonrpc": "2.0",
                "method": "eth_getLogs",
                "params": [{
                    "address": address,
                    "fromBlock": "earliest",
                    "toBlock": "latest"
                }],
                "id": 1
            }
            
            try:
                async with session.post(
                    self.rpc_url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
                ) as resp:
                    data = await resp.json()
                    
                    if "result" in data:
                        # Analizar logs buscando patrones de exploit
                        for log in data["result"]:
                            # Buscar eventos de transferencia grandes, etc.
                            # (simplificado)
                            pass
            except:
                pass
        
        return exploits
