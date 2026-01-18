"""
SENTINEL - Nuevos Agentes LLM (VERSIÓN CORREGIDA)

Agentes adicionales para análisis avanzado que usan la estructura
Finding correcta de analyzers.base

Agentes:
- CorrelatorAgent: Fusiona findings de múltiples herramientas
- AttackChainAgent: Detecta vulnerabilidades compuestas
- ExploitValidatorAgent: Valida exploits en fork de mainnet

CORRECCIÓN: Todos los agentes ahora usan:
- Finding de analyzers.base
- Severity enum (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- World enum (SOURCE, BYTECODE)
"""

from .correlator_agent import (
    CorrelatorAgent,
    CorrelatedFinding,
    CorrelationResult
)

from .attack_chain_agent import (
    AttackChainAgent,
    AttackChain,
    ChainType,
    ChainDetectionResult
)

from .exploit_validator_agent import (
    ExploitValidatorAgent,
    ValidationResult,
    ExploitMetrics
)


__all__ = [
    # Correlator
    'CorrelatorAgent',
    'CorrelatedFinding',
    'CorrelationResult',
    
    # Attack Chains
    'AttackChainAgent',
    'AttackChain',
    'ChainType',
    'ChainDetectionResult',
    
    # Exploit Validator
    'ExploitValidatorAgent',
    'ValidationResult',
    'ExploitMetrics',
]


__version__ = '1.1.0'  # Actualizado con correcciones de Finding
