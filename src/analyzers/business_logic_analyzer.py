"""
Business Logic Analyzer - Detector de errores de lógica con LLM

Mundo: SOURCE
Detecta: Math errors, access control, state machine bugs, economic invariants
Requiere: API key de OpenAI o Anthropic

A diferencia de Oracle Analyzer (solo precio/DeFi), este analiza TODOS los contratos.
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


class BusinessLogicAnalyzer(BaseAnalyzer):
    """
    Business Logic Analyzer - Usa LLM para detectar errores de lógica compleja

    Detecta:
    - Errores matemáticos (redondeo, overflow, división por cero)
    - Access control incorrecto o bypasseable
    - State machine bugs (transiciones inválidas)
    - Invariantes económicas rotas
    - Edge cases no manejados
    - Lógica de fees/rewards incorrecta
    - Condiciones de carrera

    Analiza TODOS los contratos (sin pre-filtro).
    """

    SYSTEM_PROMPT = """You are an expert smart contract security auditor specializing in business logic vulnerabilities.

Analyze the Solidity contract for logic errors that static analyzers miss:

1. **Math Errors**: Rounding issues, precision loss, division before multiplication, overflow in complex calculations, fee calculation bugs
2. **Access Control**: Missing modifiers, bypasseable checks, privilege escalation, initialization issues
3. **State Machine Bugs**: Invalid state transitions, missing state checks, race conditions between states
4. **Economic Invariants**: Broken accounting, supply/balance mismatches, reward calculation errors
5. **Edge Cases**: Empty arrays, zero values, boundary conditions, first/last user issues
6. **Timing Issues**: Block timestamp manipulation, deadline bypasses, time-dependent logic
7. **Input Validation**: Missing checks, type confusion, array length mismatches

Focus on LOGIC bugs, not syntax or known patterns (reentrancy, etc). Those are covered by other tools.

For each vulnerability provide:
- severity: critical/high/medium/low
- confidence: high/medium/low  
- location: function name
- description: what's wrong
- attack_scenario: how to exploit
- recommendation: how to fix

Output ONLY valid JSON:
{
    "vulnerabilities": [
        {
            "title": "Precision Loss in Fee Calculation",
            "severity": "high",
            "confidence": "high",
            "location": "calculateFee()",
            "line_number": 45,
            "description": "Division before multiplication causes precision loss",
            "attack_scenario": "1. Deposit small amounts\\n2. Fee rounds to zero\\n3. Repeat to avoid all fees",
            "recommendation": "Multiply before dividing: amount * feeRate / PRECISION"
        }
    ],
    "risk_score": 0-100,
    "complexity_notes": "Brief notes on contract complexity and areas of concern"
}

If no logic vulnerabilities found, return empty vulnerabilities array.
Be thorough but avoid false positives. Only report issues you're confident about."""

    @property
    def name(self) -> str:
        return "business-logic"

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

    def _estimate_complexity(self, source_code: str) -> Dict[str, Any]:
        """Estima complejidad del contrato para decidir si vale analizarlo"""
        lines = len(source_code.split('\n'))
        functions = len(re.findall(r'function\s+\w+', source_code))
        has_math = bool(re.search(r'[\+\-\*\/\%].*[\+\-\*\/\%]', source_code))
        has_state = len(re.findall(r'\b(state|status|phase|stage)\b', source_code.lower())) > 0
        has_access = bool(re.search(r'\b(owner|admin|role|access|only|require.*msg\.sender)\b', source_code.lower()))

        # Skip contratos muy simples (interfaces, abstracts pequeños)
        min_lines = self.config.get("min_lines", 20)
        min_functions = self.config.get("min_functions", 2)

        should_analyze = lines >= min_lines and functions >= min_functions

        return {
            "lines": lines,
            "functions": functions,
            "has_math": has_math,
            "has_state_machine": has_state,
            "has_access_control": has_access,
            "should_analyze": should_analyze
        }

    def _call_llm(self, source_code: str, static_findings: List[str] = None) -> str:
        """Llama al LLM con el código fuente"""
        client, provider = self._get_client()

        if not client:
            return "{}"

        model = self.config.get("model", "gpt-4o" if provider == "openai" else "claude-3-5-sonnet-20241022")
        timeout = self.config.get("timeout", 180)

        # Incluir findings de otras herramientas para evitar duplicados
        context = ""
        if static_findings:
            context = f"\n\nNote: Other tools already found these issues (don't duplicate):\n- " + "\n- ".join(
                static_findings[:10])

        user_prompt = f"""Analyze this Solidity contract for business logic vulnerabilities:

```solidity
{source_code}
```
{context}
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
            address: Optional[str] = None,
            static_findings: List[str] = None
    ) -> AnalysisResult:
        """Ejecuta Business Logic Analyzer sobre el código fuente"""

        if not self.is_available():
            return AnalysisResult(
                tool=self.name,
                world=self.world,
                success=False,
                error="Business Logic analyzer not available (missing API key)"
            )

        if not contract_path or not contract_path.exists():
            return AnalysisResult(
                tool=self.name,
                world=self.world,
                success=False,
                error=f"Contract path not found: {contract_path}"
            )

        start = time.time()

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

        # Estimar complejidad
        complexity = self._estimate_complexity(source_code)

        if not complexity["should_analyze"]:
            return AnalysisResult(
                tool=self.name,
                world=self.world,
                success=True,
                findings=[],
                execution_time=time.time() - start,
                raw_output={
                    "skipped": True,
                    "reason": f"Contract too simple ({complexity['lines']} lines, {complexity['functions']} functions)",
                    **complexity
                }
            )

        # Llamar al LLM
        try:
            response = self._call_llm(source_code, static_findings)
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
                "complexity": complexity,
                "provider": self.config.get("provider", "openai"),
                "model": self.config.get("model", "gpt-4o")
            }
        )

    def parse_output(self, data: Dict, contract_path: str = "") -> List[Finding]:
        """Parsea la salida del LLM a Findings"""
        findings = []

        for vuln in data.get("vulnerabilities", []):
            title = vuln.get("title", "Business Logic Vulnerability")
            severity = self._severity_from_string(vuln.get("severity", "medium"))
            confidence = vuln.get("confidence", "medium")
            location = vuln.get("location", "")
            line_number = vuln.get("line_number")

            # Construir descripción completa
            description = vuln.get("description", "")
            attack = vuln.get("attack_scenario", "")
            recommendation = vuln.get("recommendation", "")

            full_description = f"{description}\n\n**Attack Scenario:**\n{attack}\n\n**Recommendation:**\n{recommendation}"

            # Generar ID único
            finding_id = self._generate_finding_id(
                self.name,
                f"logic:{title}",
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