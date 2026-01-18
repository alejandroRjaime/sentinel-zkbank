"""
Oracle Analyzer - Detector de vulnerabilidades de precio/oráculo con LLM

Mundo: SOURCE
Detecta: Flash loan manipulation, spot price dependency, oracle manipulation
Requiere: API key de OpenAI o Anthropic
"""

from pathlib import Path
from typing import List, Dict, Any, Optional
import json
import re
import os
import time

from .base import BaseAnalyzer, Finding, AnalysisResult, World, Severity

# Providers LLM
try:
    from openai import OpenAI

    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False

try:
    import anthropic

    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False


class OracleAnalyzer(BaseAnalyzer):
    """
    Oracle Analyzer - Usa LLM para detectar vulnerabilidades de precio

    Detecta:
    - Flash loan price manipulation
    - Spot price vs TWAP issues
    - Circular dependencies in price feeds
    - Read-only reentrancy affecting prices
    - Sandwich attack vectors
    - Stale price data

    A diferencia de Slither/Mythril que usan análisis estático/simbólico,
    este analyzer usa un LLM para razonar sobre la lógica de negocio.
    """

    # Indicadores para pre-filtro (evita llamar LLM si no hay lógica de precios)
    PRICE_INDICATORS = [
        r'\bprice\b', r'\bgetPrice\b', r'\bcalculatePrice\b',
        r'\bbalanceOf\b.*\/', r'\/.*\bbalanceOf\b',
        r'\breserve[s]?\b', r'\bgetReserves\b',
        r'\boracle\b', r'\bchainlink\b', r'\btwap\b',
        r'\bswap\b', r'\bpool\b', r'\bliquidity\b',
        r'\bdeposit\b.*\bmint\b', r'\bmint\b.*\bdeposit\b',
        r'\bshares?\b', r'\btotalSupply\b.*\bbalance',
        r'\bexchangeRate\b', r'\bgetRate\b',
        r'\bflash\b', r'\bloan\b'
    ]

    SYSTEM_PROMPT = """You are an expert smart contract security auditor specializing in DeFi price oracle vulnerabilities.

Analyze the Solidity contract and identify vulnerabilities related to:
1. **Flash Loan Price Manipulation**: Prices derived from spot balances manipulable in one tx
2. **Spot Price Dependency**: Using current reserves instead of TWAP or Chainlink
3. **Oracle Manipulation**: External price feeds that can be influenced
4. **Read-Only Reentrancy**: Price calculations affected by reentrancy in view functions
5. **Sandwich Attack Vectors**: Functions vulnerable to front/back-running
6. **Stale Price Data**: Missing freshness checks on oracle data

For each vulnerability provide: severity (critical/high/medium/low), confidence (high/medium/low), location, attack scenario, recommendation.

Output ONLY valid JSON:
{
    "has_price_logic": true/false,
    "price_functions": ["function names"],
    "vulnerabilities": [
        {
            "title": "Flash Loan Price Manipulation",
            "severity": "critical",
            "confidence": "high",
            "location": "getPrice()",
            "line_number": 15,
            "description": "Price calculated from manipulable balance",
            "attack_scenario": "1. Flash loan\\n2. Inflate balance\\n3. Exploit\\n4. Repay",
            "recommendation": "Use TWAP or Chainlink"
        }
    ],
    "risk_score": 0-100
}"""

    @property
    def name(self) -> str:
        return "oracle"

    @property
    def world(self) -> World:
        return World.SOURCE

    def is_available(self) -> bool:
        """Verifica si el analyzer está disponible (requiere API key)"""
        if not self.config.get("enabled", True):
            return False

        provider = self.config.get("provider", "openai")

        # API key: primero del config, luego de env
        api_key = self.config.get("api_key") or os.environ.get(
            "OPENAI_API_KEY" if provider == "openai" else "ANTHROPIC_API_KEY"
        )

        if provider == "openai":
            return HAS_OPENAI and bool(api_key)
        elif provider == "anthropic":
            return HAS_ANTHROPIC and bool(api_key)

        return False

    def has_price_logic(self, contract_path: Path) -> Dict[str, Any]:
        """Verifica si el contrato tiene lógica de precios (pre-filtro)"""
        try:
            content = contract_path.read_text().lower()
            matches = []

            for pattern in self.PRICE_INDICATORS:
                if re.search(pattern, content):
                    matches.append(pattern)

            min_indicators = self.config.get("min_indicators", 2)

            return {
                "has_price_logic": len(matches) >= min_indicators,
                "indicators_found": matches,
                "indicator_count": len(matches)
            }
        except:
            return {"has_price_logic": False, "indicators_found": [], "indicator_count": 0}

    def _get_client(self):
        """Obtiene el cliente LLM"""
        provider = self.config.get("provider", "openai")

        # API key: primero del config, luego de env
        api_key = self.config.get("api_key") or os.environ.get(
            "OPENAI_API_KEY" if provider == "openai" else "ANTHROPIC_API_KEY"
        )

        if not api_key:
            return None, None

        if provider == "openai" and HAS_OPENAI:
            return OpenAI(api_key=api_key), "openai"
        elif provider == "anthropic" and HAS_ANTHROPIC:
            return anthropic.Anthropic(api_key=api_key), "anthropic"

        return None, None

    def _call_llm(self, source_code: str) -> str:
        """Llama al LLM con el código fuente"""
        client, provider = self._get_client()

        if not client:
            return "{}"

        model = self.config.get("model", "gpt-4o" if provider == "openai" else "claude-3-5-sonnet-20241022")
        timeout = self.config.get("timeout", 180)

        user_prompt = f"""Analyze this Solidity contract for oracle/price manipulation vulnerabilities:

```solidity
{source_code}
```

Output ONLY the JSON, no markdown."""

        try:
            if provider == "openai":
                response = client.chat.completions.create(
                    model=model,
                    messages=[
                        {"role": "system", "content": self.SYSTEM_PROMPT},
                        {"role": "user", "content": user_prompt}
                    ],
                    temperature=0.1,
                    max_tokens=4000,
                    timeout=timeout
                )
                return response.choices[0].message.content

            elif provider == "anthropic":
                response = client.messages.create(
                    model=model,
                    max_tokens=4000,
                    system=self.SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": user_prompt}]
                )
                return response.content[0].text
        except Exception as e:
            return json.dumps({"error": str(e)})

        return "{}"

    def _parse_response(self, response: str) -> Dict[str, Any]:
        """Parsea la respuesta del LLM"""
        response = response.strip()

        # Limpiar markdown
        if response.startswith("```"):
            response = re.sub(r'^```json?\s*', '', response)
            response = re.sub(r'\s*```$', '', response)

        # Extraer JSON
        json_match = re.search(r'\{[\s\S]*\}', response)
        if json_match:
            try:
                return json.loads(json_match.group())
            except json.JSONDecodeError:
                pass

        return {}

    def _severity_from_string(self, sev: str) -> Severity:
        """Convierte string a Severity enum"""
        mapping = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO
        }
        return mapping.get(sev.lower(), Severity.MEDIUM)

    async def analyze(
            self,
            contract_path: Path,
            bytecode: Optional[str] = None,
            address: Optional[str] = None
    ) -> AnalysisResult:
        """Ejecuta Oracle Analyzer sobre el código fuente"""

        if not self.is_available():
            return AnalysisResult(
                tool=self.name,
                world=self.world,
                success=False,
                error="Oracle analyzer not available (missing API key)"
            )

        if not contract_path or not contract_path.exists():
            return AnalysisResult(
                tool=self.name,
                world=self.world,
                success=False,
                error=f"Contract path not found: {contract_path}"
            )

        start = time.time()

        # Pre-filtro: verificar si tiene lógica de precios
        prefilter = self.has_price_logic(contract_path)

        if not prefilter["has_price_logic"]:
            return AnalysisResult(
                tool=self.name,
                world=self.world,
                success=True,
                findings=[],
                execution_time=time.time() - start,
                raw_output={"skipped": True, "reason": "No price logic detected", **prefilter}
            )

        # Leer código fuente
        try:
            source_code = contract_path.read_text()
        except Exception as e:
            return AnalysisResult(
                tool=self.name,
                world=self.world,
                success=False,
                error=f"Failed to read contract: {e}",
                execution_time=time.time() - start
            )

        # Llamar al LLM
        try:
            response = self._call_llm(source_code)
            data = self._parse_response(response)
        except Exception as e:
            return AnalysisResult(
                tool=self.name,
                world=self.world,
                success=False,
                error=f"LLM call failed: {e}",
                execution_time=time.time() - start
            )

        # Verificar si hubo error en el LLM
        if data.get("error"):
            return AnalysisResult(
                tool=self.name,
                world=self.world,
                success=False,
                error=data["error"],
                execution_time=time.time() - start
            )

        # Parsear vulnerabilidades
        findings = self.parse_output(data, str(contract_path))

        execution_time = time.time() - start

        return AnalysisResult(
            tool=self.name,
            world=self.world,
            success=True,
            findings=findings,
            execution_time=execution_time,
            raw_output={
                **data,
                "prefilter": prefilter,
                "provider": self.config.get("provider", "openai"),
                "model": self.config.get("model", "gpt-4o")
            }
        )

    def parse_output(self, data: Dict, contract_path: str = "") -> List[Finding]:
        """Parsea la salida del LLM a Findings"""
        findings = []

        for vuln in data.get("vulnerabilities", []):
            title = vuln.get("title", "Oracle Vulnerability")
            severity = self._severity_from_string(vuln.get("severity", "medium"))
            confidence = vuln.get("confidence", "medium")
            location = vuln.get("location", "")
            line_number = vuln.get("line_number")

            # Construir descripción completa (incluye recommendation)
            description = vuln.get("description", "")
            attack = vuln.get("attack_scenario", "")
            recommendation = vuln.get("recommendation", "")

            full_description = f"{description}\n\n**Attack Scenario:**\n{attack}\n\n**Recommendation:**\n{recommendation}"

            # Generar ID único
            finding_id = self._generate_finding_id(
                self.name,
                f"oracle:{title}",
                location
            )

            # Extraer nombre de función
            function_name = location.split("(")[0] if "(" in location else location

            findings.append(Finding(
                id=finding_id,
                title=title,
                description=full_description,
                severity=severity,
                world=self.world,
                tool=self.name,
                confidence=confidence,
                location=location,
                line_number=line_number,
                function=function_name,
                raw_output=vuln
            ))

        return findings