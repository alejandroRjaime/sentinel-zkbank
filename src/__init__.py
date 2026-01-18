"""
SENTINEL Engine - Smart Contract Security Analyzer (Distributed)

Stack híbrido de dos mundos con Ray:
- Source World: Slither, Echidna (Ray Tasks)
- Bytecode World: Mythril, Manticore, Hevm (Ray Tasks)
- Validation: Erigon traces
- LLM: Correlación, Attack Chains, Exploit Validation
- Human Bridge: Panoramix
"""

from .engine import SentinelEngine, AnalysisReport, DistributedConfig

__version__ = "3.0.0"
__all__ = ['SentinelEngine', 'AnalysisReport', 'DistributedConfig']