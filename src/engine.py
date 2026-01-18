"""
SENTINEL Engine - Motor Principal Distribuido con Ray

"El .sol explica la intención. El bytecode prueba la realidad."

Versión distribuida nativa:
- Ray Tasks para cada analyzer (Slither, Mythril, Echidna, Hevm)
- Batch paralelo de contratos
- Configuración interna de workers y paths
"""
import sys
from asyncio import futures
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
import asyncio
import json
import yaml
import hashlib
import subprocess
import os
import time

from .analyzers import CrossChainReplayAnalyzer

# Suprimir warning de Ray sobre GPUs
os.environ["RAY_ACCEL_ENV_VAR_OVERRIDE_ON_ZERO"] = "0"


# ═══════════════════════════════════════════════════════════════════════════
# CONFIGURACIÓN GLOBAL
# ═══════════════════════════════════════════════════════════════════════════

class DistributedConfig:
    """Configuración centralizada - Lee de tools.yaml si existe"""

    # ─────────────────────────── PATHS ───────────────────────────
    PROJECT_ROOT = Path(__file__).parent.parent
    CONFIG_PATH = PROJECT_ROOT / "config" / "tools.yaml"
    ETHEREUM_CONFIG = PROJECT_ROOT / "config" / "ethereum.yaml"
    REPORTS_DIR = PROJECT_ROOT / "reports"
    CONTRACTS_DIR = PROJECT_ROOT / "contracts"

    # ─────────────────────────── DEFAULTS ───────────────────────────
    RAY_ENABLED = True
    NUM_WORKERS = os.cpu_count() or 4

    SLITHER_TIMEOUT = 120
    MYTHRIL_TIMEOUT = 300
    ECHIDNA_TIMEOUT = 300
    HEVM_TIMEOUT = 300
    MANTICORE_TIMEOUT = 3600
    COMPILE_TIMEOUT = 60

    SLITHER_ENABLED = True
    ECHIDNA_ENABLED = True
    MYTHRIL_ENABLED = True
    HEVM_ENABLED = True
    MANTICORE_ENABLED = False

    # LLM Defaults
    LLM_ENABLED = False  # Default OFF, se activa por config
    LLM_PROVIDER = "openai"
    LLM_MODEL = "gpt-4o"
    LLM_TIMEOUT = 180
    CORRELATION_ENABLED = True
    ATTACK_CHAINS_ENABLED = True
    EXPLOIT_VALIDATION_ENABLED = False

    # Oracle Analyzer Defaults
    ORACLE_ENABLED = False  # Se activa por config en source_world.oracle
    ORACLE_PROVIDER = "openai"
    ORACLE_MODEL = "gpt-4o"

    @classmethod
    def load_from_yaml(cls):
        """Carga configuración desde tools.yaml"""
        print(f"  📁 Buscando config: {cls.CONFIG_PATH}")

        if not cls.CONFIG_PATH.exists():
            print(f"  ⚠️ Config no encontrado, usando defaults")
            return

        try:
            with open(cls.CONFIG_PATH) as f:
                config = yaml.safe_load(f) or {}

            print(f"  ✓ Config cargado: {cls.CONFIG_PATH}")

            # LLM Config
            llm = config.get("llm", {})
            print(f"    LLM config: enabled={llm.get('enabled', False)}, provider={llm.get('provider', 'N/A')}")

            if llm.get("enabled", False):
                cls.LLM_ENABLED = True
                cls.LLM_PROVIDER = llm.get("provider", cls.LLM_PROVIDER)
                cls.LLM_MODEL = llm.get("model", cls.LLM_MODEL)
                cls.LLM_TIMEOUT = llm.get("timeout", cls.LLM_TIMEOUT)
                print(f"  ✓ LLM ACTIVADO: {cls.LLM_PROVIDER}/{cls.LLM_MODEL}")
            else:
                print(f"  ⚠️ LLM deshabilitado en config")

            # Source World
            source = config.get("source_world", {})
            cls.SLITHER_ENABLED = source.get("slither", {}).get("enabled", cls.SLITHER_ENABLED)
            cls.ECHIDNA_ENABLED = source.get("echidna", {}).get("enabled", cls.ECHIDNA_ENABLED)

            # Oracle Analyzer (usa config del source_world)
            oracle_config = source.get("oracle", {})
            cls.ORACLE_ENABLED = oracle_config.get("enabled", False)
            if cls.ORACLE_ENABLED:
                # Si oracle está enabled, usar su provider/model o heredar del LLM global
                cls.ORACLE_PROVIDER = oracle_config.get("provider", cls.LLM_PROVIDER)
                cls.ORACLE_MODEL = oracle_config.get("model", cls.LLM_MODEL)
                print(f"  ✓ Oracle Analyzer ACTIVADO: {cls.ORACLE_PROVIDER}/{cls.ORACLE_MODEL}")

            # Bytecode World
            bytecode = config.get("bytecode_world", {})
            cls.MYTHRIL_ENABLED = bytecode.get("mythril", {}).get("enabled", cls.MYTHRIL_ENABLED)
            cls.HEVM_ENABLED = bytecode.get("hevm", {}).get("enabled", cls.HEVM_ENABLED)
            cls.MANTICORE_ENABLED = bytecode.get("manticore", {}).get("enabled", cls.MANTICORE_ENABLED)

        except Exception as e:
            print(f"  ⚠️ Error cargando config: {e}")
            import traceback
            traceback.print_exc()


# Cargar config al importar
DistributedConfig.load_from_yaml()

# ═══════════════════════════════════════════════════════════════════════════
# RAY INITIALIZATION
# ═══════════════════════════════════════════════════════════════════════════

ray = None


def _init_ray():
    """Inicializa Ray si está disponible"""
    global ray

    if not DistributedConfig.RAY_ENABLED:
        return False

    try:
        import ray as ray_module
        ray = ray_module

        if not ray.is_initialized():
            ray.init(
                num_cpus=DistributedConfig.NUM_WORKERS,
                ignore_reinit_error=True,
                logging_level="warning"
            )

        cpus = ray.cluster_resources().get("CPU", 0)
        print(f"⚡ Ray: {int(cpus)} CPUs")
        return True

    except ImportError:
        print("⚠️  Ray no disponible. Ejecutando en modo asyncio.")
        DistributedConfig.RAY_ENABLED = False
        return False


# ═══════════════════════════════════════════════════════════════════════════
# IMPORTS
# ═══════════════════════════════════════════════════════════════════════════

from .analyzers.base import Finding, AnalysisResult, World, Severity
from .analyzers.slither_analyzer import SlitherAnalyzer
from .analyzers.echidna_analyzer import EchidnaAnalyzer
from .analyzers.mythril_analyzer import MythrilAnalyzer
from .analyzers.manticore_analyzer import ManticoreAnalyzer
from .analyzers.hevm_analyzer import HevmAnalyzer
from .analyzers.oracle_analyzer import OracleAnalyzer
from .analyzers.business_logic_analyzer import BusinessLogicAnalyzer
from .analyzers.arbitrary_call_analyzer import ArbitraryCallAnalyzer
from .analyzers.signature_replay_analyzer import SignatureReplayAnalyzer
from .analyzers.delegatecall_loop_analyzer import DelegatecallLoopAnalyzer
from .validators.erigon_validator import ErigonValidator
from .decompilers.panoramix_decompiler import PanoramixDecompiler
from .fetchers.contract_fetcher import ContractFetcher, ContractInfo
from .llm.agents import LLMPipeline
from .llm.correlator_agent import CorrelatorAgent, CorrelationResult
from .llm.attack_chain_agent import AttackChainAgent, AttackChain, ChainDetectionResult
from .llm.exploit_validator_agent import ExploitValidatorAgent, ExploitMetrics


# ═══════════════════════════════════════════════════════════════════════════
# RAY TASKS
# ═══════════════════════════════════════════════════════════════════════════

def _run_analyzer_sync(analyzer_class, config: Dict, contract_path: str, bytecode: str = None) -> Dict:
    """Ejecuta un analyzer sincrónicamente (para Ray)"""
    from pathlib import Path
    import asyncio

    analyzer = analyzer_class(config)

    if not analyzer.is_available():
        return {
            "tool": analyzer.name,
            "world": analyzer.world.value if hasattr(analyzer, 'world') else "source",
            "success": False,
            "error": f"{analyzer.name} not available",
            "findings": [],
            "execution_time": 0
        }

    try:
        result = asyncio.run(analyzer.analyze(
            Path(contract_path) if contract_path else None,
            bytecode
        ))
        return result.to_dict()
    except Exception as e:
        return {
            "tool": analyzer.name,
            "world": "source",
            "success": False,
            "error": str(e),
            "findings": [],
            "execution_time": 0
        }


def _create_ray_tasks():
    """Crea Ray tasks para cada analyzer"""
    if ray is None:
        return None

    @ray.remote(num_cpus=1)
    def slither_task(contract_path: str, config: Dict) -> Dict:
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from src.analyzers.slither_analyzer import SlitherAnalyzer
        return _run_analyzer_sync(SlitherAnalyzer, config, contract_path)

    @ray.remote(num_cpus=1)
    def mythril_task(contract_path: str, bytecode: str, config: Dict) -> Dict:
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from src.analyzers.mythril_analyzer import MythrilAnalyzer
        return _run_analyzer_sync(MythrilAnalyzer, config, contract_path, bytecode)

    @ray.remote(num_cpus=1)
    def echidna_task(contract_path: str, config: Dict) -> Dict:
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from src.analyzers.echidna_analyzer import EchidnaAnalyzer
        return _run_analyzer_sync(EchidnaAnalyzer, config, contract_path)

    @ray.remote(num_cpus=1)
    def hevm_task(contract_path: str, bytecode: str, config: Dict) -> Dict:
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from src.analyzers.hevm_analyzer import HevmAnalyzer
        return _run_analyzer_sync(HevmAnalyzer, config, contract_path, bytecode)

    @ray.remote(num_cpus=1)
    def manticore_task(contract_path: str, bytecode: str, config: Dict) -> Dict:
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from src.analyzers.manticore_analyzer import ManticoreAnalyzer
        return _run_analyzer_sync(ManticoreAnalyzer, config, contract_path, bytecode)

    @ray.remote(num_cpus=1)
    def oracle_task(contract_path: str, config: Dict) -> Dict:
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from src.analyzers.oracle_analyzer import OracleAnalyzer
        return _run_analyzer_sync(OracleAnalyzer, config, contract_path)

    @ray.remote(num_cpus=1)
    def business_logic_task(contract_path: str, config: Dict) -> Dict:
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from src.analyzers.business_logic_analyzer import BusinessLogicAnalyzer
        return _run_analyzer_sync(BusinessLogicAnalyzer, config, contract_path)

    @ray.remote(num_cpus=1)
    def arbitrary_call_task(contract_path: str, config: Dict) -> Dict:
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from src.analyzers.arbitrary_call_analyzer import ArbitraryCallAnalyzer
        return _run_analyzer_sync(ArbitraryCallAnalyzer, config, contract_path)

    @ray.remote(num_cpus=1)
    def signature_replay_task(contract_path: str, config: Dict) -> Dict:
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from src.analyzers.signature_replay_analyzer import SignatureReplayAnalyzer
        return _run_analyzer_sync(SignatureReplayAnalyzer, config, contract_path)

    @ray.remote(num_cpus=1)
    def delegatecall_loop_task(contract_path: str, config: Dict) -> Dict:
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from src.analyzers.delegatecall_loop_analyzer import DelegatecallLoopAnalyzer
        return _run_analyzer_sync(DelegatecallLoopAnalyzer, config, contract_path)

    @ray.remote(num_cpus=1)
    def crosschain_replay_task(contract_path: str, config: Dict) -> Dict:
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from src.analyzers.crosschain_replay_analyzer import CrossChainReplayAnalyzer
        return _run_analyzer_sync(CrossChainReplayAnalyzer, config, contract_path)

    return {
        "slither": slither_task,
        "mythril": mythril_task,
        "echidna": echidna_task,
        "hevm": hevm_task,
        "manticore": manticore_task,
        "oracle": oracle_task,
        "business_logic": business_logic_task,
        "arbitrary_call": arbitrary_call_task,
        "signature_replay": signature_replay_task,
        "delegatecall_loop": delegatecall_loop_task,
        "crosschain_replay": crosschain_replay_task,  # ← NUEVO
    }


# ═══════════════════════════════════════════════════════════════════════════
# ANALYSIS REPORT
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class AnalysisReport:
    """Reporte completo de análisis"""
    address: str
    contract_name: Optional[str]
    has_source: bool
    is_proxy: bool
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    source_world_results: List[AnalysisResult] = field(default_factory=list)
    bytecode_world_results: List[AnalysisResult] = field(default_factory=list)

    all_findings: List[Finding] = field(default_factory=list)
    validated_findings: List[Finding] = field(default_factory=list)

    llm_filtered_findings: List[Finding] = field(default_factory=list)
    llm_analyses: List[Dict] = field(default_factory=list)
    llm_pocs: List[Dict] = field(default_factory=list)
    llm_remediations: List[Dict] = field(default_factory=list)
    llm_summary: Dict = field(default_factory=dict)

    correlation_result: Optional[CorrelationResult] = None
    attack_chains_result: Optional[ChainDetectionResult] = None
    exploit_validation_metrics: Optional[ExploitMetrics] = None

    decompiled_code: Optional[str] = None
    summary: Dict = field(default_factory=dict)
    execution_time: float = 0.0

    def get_all_findings(self) -> List[Finding]:
        severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
        return sorted(self.all_findings, key=lambda f: severity_order.get(f.severity, 5))

    def to_dict(self) -> Dict:
        d = {
            "address": self.address,
            "contract_name": self.contract_name,
            "has_source": self.has_source,
            "is_proxy": self.is_proxy,
            "timestamp": self.timestamp,
            "summary": self.summary,
            "execution_time": self.execution_time,
            "source_world": [r.to_dict() for r in self.source_world_results],
            "bytecode_world": [r.to_dict() for r in self.bytecode_world_results],
            "findings": [f.to_dict() for f in self.get_all_findings()],
            "validated_count": len(self.validated_findings),
            "llm": {
                "enabled": bool(self.llm_summary),
                "filtered_count": len(self.llm_filtered_findings),
                "analyses": self.llm_analyses,
                "pocs_generated": len(self.llm_pocs),
                "remediations": len(self.llm_remediations),
                "summary": self.llm_summary
            }
        }

        if self.correlation_result:
            d["llm"]["correlation"] = {
                "original_count": self.correlation_result.original_count,
                "duplicates_removed": self.correlation_result.duplicates_removed,
                "confidence_increased": self.correlation_result.confidence_increased
            }

        if self.attack_chains_result:
            d["llm"]["attack_chains"] = {
                "chains_found": len(self.attack_chains_result.chains_found),
                "risk_score": self.attack_chains_result.risk_score,
                "chains": [{"name": c.name, "type": c.chain_type.value, "severity": c.severity.value,
                            "exploitability": c.exploitability, "components": len(c.components),
                            "scenario": c.attack_scenario} for c in self.attack_chains_result.chains_found]
            }

        if self.exploit_validation_metrics:
            d["llm"]["exploit_validation"] = {"total_tested": self.exploit_validation_metrics.total_tested,
                                              "successful": self.exploit_validation_metrics.successful_exploits,
                                              "failed": self.exploit_validation_metrics.failed_exploits,
                                              "severity_confirmed": self.exploit_validation_metrics.estimated_severity_confirmed}

        return d

    def compute_summary(self):
        findings = self.get_all_findings()
        breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            breakdown[f.severity.value] += 1

        risk_score = breakdown["critical"] * 10 + breakdown["high"] * 5 + breakdown["medium"] * 2 + breakdown["low"]

        if self.attack_chains_result and self.attack_chains_result.chains_found:
            risk_score += self.attack_chains_result.risk_score

        if breakdown["critical"] > 0 or risk_score >= 20:
            risk_level = "CRITICAL"
        elif breakdown["high"] > 0 or risk_score >= 10:
            risk_level = "HIGH"
        elif breakdown["medium"] > 0 or risk_score >= 5:
            risk_level = "MEDIUM"
        elif breakdown["low"] > 0:
            risk_level = "LOW"
        else:
            risk_level = "SAFE"

        self.summary = {
            "risk_level": risk_level,
            "risk_score": risk_score,
            "total_findings": len(findings),
            "severity_breakdown": breakdown,
            "source_world_findings": sum(1 for f in findings if f.world == World.SOURCE),
            "bytecode_world_findings": sum(1 for f in findings if f.world == World.BYTECODE),
            "validated_findings": len(self.validated_findings),
            "tools_used": {"source": [r.tool for r in self.source_world_results if r.success],
                           "bytecode": [r.tool for r in self.bytecode_world_results if r.success]},
            "execution_time": self.execution_time
        }

        if self.attack_chains_result and self.attack_chains_result.chains_found:
            self.summary["attack_chains_detected"] = len(self.attack_chains_result.chains_found)
            self.summary["chain_risk_score"] = self.attack_chains_result.risk_score


# ═══════════════════════════════════════════════════════════════════════════
# SENTINEL ENGINE
# ═══════════════════════════════════════════════════════════════════════════

class SentinelEngine:
    """
    Motor principal de análisis distribuido.

    Modos:
    - quick: Solo Mythril (~5 min)
    - normal: Source + Bytecode completo (~15 min)
    - deep: Todo + validación + LLM avanzado (~30+ min)
    """

    def __init__(self, config_path: Optional[Path] = None, num_workers: int = None):
        # Configuración
        if config_path and config_path.exists():
            with open(config_path) as f:
                self.config = yaml.safe_load(f)
        else:
            self.config = self._default_config()

        # Workers
        if num_workers:
            DistributedConfig.NUM_WORKERS = num_workers

        # Ray
        self.ray_enabled = _init_ray()
        self.ray_tasks = _create_ray_tasks() if self.ray_enabled else None

        # Inicializar
        self._init_analyzers()
        self._init_validator()
        self._init_decompiler()
        self._init_llm()

        # Fetcher
        eth_config = {}
        if DistributedConfig.ETHEREUM_CONFIG.exists():
            with open(DistributedConfig.ETHEREUM_CONFIG) as f:
                eth_config = yaml.safe_load(f) or {}
        self.fetcher = ContractFetcher(eth_config)

        # Directorios
        self.reports_dir = Path(eth_config.get("directories", {}).get("reports", str(DistributedConfig.REPORTS_DIR)))
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def _default_config(self) -> Dict:
        return {
            "source_world": {
                "slither": {"enabled": DistributedConfig.SLITHER_ENABLED, "timeout": DistributedConfig.SLITHER_TIMEOUT},
                "echidna": {"enabled": DistributedConfig.ECHIDNA_ENABLED, "timeout": DistributedConfig.ECHIDNA_TIMEOUT},
                "oracle": {
                    "enabled": DistributedConfig.ORACLE_ENABLED,
                    "provider": DistributedConfig.ORACLE_PROVIDER,
                    "model": DistributedConfig.ORACLE_MODEL,
                    "timeout": DistributedConfig.LLM_TIMEOUT,
                    "min_indicators": 2
                }
            },
            "bytecode_world": {
                "mythril": {"enabled": DistributedConfig.MYTHRIL_ENABLED, "timeout": DistributedConfig.MYTHRIL_TIMEOUT},
                "manticore": {"enabled": DistributedConfig.MANTICORE_ENABLED,
                              "timeout": DistributedConfig.MANTICORE_TIMEOUT},
                "hevm": {"enabled": DistributedConfig.HEVM_ENABLED, "timeout": DistributedConfig.HEVM_TIMEOUT}
            },
            "validation": {"erigon": {"enabled": True, "rpc_url": "http://localhost:8545"}},
            "human_bridge": {"panoramix": {"enabled": True, "timeout": 300}},
            "llm": {
                "enabled": DistributedConfig.LLM_ENABLED,
                "provider": DistributedConfig.LLM_PROVIDER,
                "model": DistributedConfig.LLM_MODEL,
                "timeout": DistributedConfig.LLM_TIMEOUT,
                "correlation": {"enabled": DistributedConfig.CORRELATION_ENABLED, "min_confidence": 0.6},
                "attack_chains": {"enabled": DistributedConfig.ATTACK_CHAINS_ENABLED},
                "exploit_validation": {"enabled": DistributedConfig.EXPLOIT_VALIDATION_ENABLED}
            }
        }

    def _init_analyzers(self):
        source_config = self.config.get("source_world", {})
        bytecode_config = self.config.get("bytecode_world", {})

        self.source_analyzers = []
        if source_config.get("slither", {}).get("enabled", True):
            self.source_analyzers.append(SlitherAnalyzer(source_config.get("slither", {})))
        if source_config.get("echidna", {}).get("enabled", True):
            self.source_analyzers.append(EchidnaAnalyzer(source_config.get("echidna", {})))
        if source_config.get("oracle", {}).get("enabled", False):
            self.source_analyzers.append(OracleAnalyzer(source_config.get("oracle", {})))
        if source_config.get("business_logic", {}).get("enabled", False):
            self.source_analyzers.append(BusinessLogicAnalyzer(source_config.get("business_logic", {})))
        if source_config.get("arbitrary_call", {}).get("enabled", False):
            self.source_analyzers.append(ArbitraryCallAnalyzer(source_config.get("arbitrary_call", {})))
        if source_config.get("signature_replay", {}).get("enabled", False):
            self.source_analyzers.append(SignatureReplayAnalyzer(source_config.get("signature_replay", {})))

        if source_config.get("delegatecall_loop", {}).get("enabled", False):
            self.source_analyzers.append(DelegatecallLoopAnalyzer(source_config.get("delegatecall_loop", {})))

        if source_config.get("crosschain_replay", {}).get("enabled", False):
            self.source_analyzers.append(CrossChainReplayAnalyzer(source_config.get("crosschain_replay", {})))


        self.bytecode_analyzers = []
        if bytecode_config.get("mythril", {}).get("enabled", True):
            self.bytecode_analyzers.append(MythrilAnalyzer(bytecode_config.get("mythril", {})))
        if bytecode_config.get("manticore", {}).get("enabled", False):
            self.bytecode_analyzers.append(ManticoreAnalyzer(bytecode_config.get("manticore", {})))
        if bytecode_config.get("hevm", {}).get("enabled", True):
            self.bytecode_analyzers.append(HevmAnalyzer(bytecode_config.get("hevm", {})))

    def _init_validator(self):
        validation_config = self.config.get("validation", {}).get("erigon", {})
        self.validator = ErigonValidator(validation_config)

    def _init_decompiler(self):
        decomp_config = self.config.get("human_bridge", {}).get("panoramix", {})
        self.decompiler = PanoramixDecompiler(decomp_config)

    def _init_llm(self):
        llm_config = self.config.get("llm", {})
        self.llm_pipeline = LLMPipeline(llm_config)

    # ═══════════════════════════════════════════════════════════════════════
    # PARALLEL EXECUTION
    # ═══════════════════════════════════════════════════════════════════════

    async def _run_parallel_ray(
            self,
            contract_path: Path,
            bytecode: Optional[str],
            use_source: bool = True,
            use_bytecode: bool = True,
            mode: str = "normal"
    ) -> tuple:
        """Ejecuta analyzers en paralelo con Ray Tasks"""

        source_config = self.config.get("source_world", {})
        bytecode_config = self.config.get("bytecode_world", {})

        futures = {}
        contract_str = str(contract_path) if contract_path else None

        # Source World
        if use_source and contract_path:
            if source_config.get("slither", {}).get("enabled", True):
                print(f"  ▶ Slither → Ray Task")
                futures["slither"] = self.ray_tasks["slither"].remote(contract_str, source_config.get("slither", {}))

            if source_config.get("echidna", {}).get("enabled", True):
                print(f"  ▶ Echidna → Ray Task")
                futures["echidna"] = self.ray_tasks["echidna"].remote(contract_str, source_config.get("echidna", {}))

            if source_config.get("oracle", {}).get("enabled", False):
                print(f"  ▶ Oracle (LLM) → Ray Task")
                futures["oracle"] = self.ray_tasks["oracle"].remote(contract_str, source_config.get("oracle", {}))

            if source_config.get("business_logic", {}).get("enabled", False):
                print(f"  ▶ Business Logic (LLM) → Ray Task")
                futures["business_logic"] = self.ray_tasks["business_logic"].remote(contract_str,
                                                                                    source_config.get("business_logic",
                                                                                                      {}))

            if source_config.get("arbitrary_call", {}).get("enabled", False):
                print(f"  ▶ Arbitrary Call (LLM) → Ray Task")
                futures["arbitrary_call"] = self.ray_tasks["arbitrary_call"].remote(
                    contract_str, source_config.get("arbitrary_call", {}))

            if source_config.get("signature_replay", {}).get("enabled", False):
                print(f"  ▶ Signature Replay (LLM) → Ray Task")
                futures["signature_replay"] = self.ray_tasks["signature_replay"].remote(
                    contract_str, source_config.get("signature_replay", {}))

            if source_config.get("delegatecall_loop", {}).get("enabled", False):
                print(f"  ▶ Delegatecall Loop (LLM) → Ray Task")
                futures["delegatecall_loop"] = self.ray_tasks["delegatecall_loop"].remote(
                    contract_str, source_config.get("delegatecall_loop", {}))

            if source_config.get("crosschain_replay", {}).get("enabled", False):
                print(f"  ▶ CrossChain Replay (LLM) → Ray Task")
                futures["crosschain_replay"] = self.ray_tasks["crosschain_replay"].remote(
                    contract_str, source_config.get("crosschain_replay", {}))

        # Bytecode World
        if use_bytecode:
            if bytecode_config.get("mythril", {}).get("enabled", True):
                print(f"  ▶ Mythril → Ray Task")
                futures["mythril"] = self.ray_tasks["mythril"].remote(contract_str, bytecode,
                                                                      bytecode_config.get("mythril", {}))

            if bytecode_config.get("hevm", {}).get("enabled", True):
                print(f"  ▶ Hevm → Ray Task")
                futures["hevm"] = self.ray_tasks["hevm"].remote(contract_str, bytecode, bytecode_config.get("hevm", {}))

            if mode == "deep" and bytecode_config.get("manticore", {}).get("enabled", False):
                print(f"  ▶ Manticore → Ray Task")
                futures["manticore"] = self.ray_tasks["manticore"].remote(contract_str, bytecode,
                                                                          bytecode_config.get("manticore", {}))

        # Recoger resultados
        source_results = []
        bytecode_results = []

        print("\n  ⏳ Esperando resultados...")
        for name, future in futures.items():
            try:
                result_dict = ray.get(future)
                result = self._dict_to_result(result_dict)

                if name in ["slither", "echidna", "oracle", "business_logic",
                           "arbitrary_call", "signature_replay", "delegatecall_loop"]:
                    source_results.append(result)
                else:
                    bytecode_results.append(result)

                status = "✓" if result.success else "⚠️"
                print(f"    {status} {name}: {len(result.findings)} findings ({result.execution_time:.1f}s)")

            except Exception as e:
                print(f"    ✗ {name}: Error - {e}")

        return source_results, bytecode_results

    async def _run_parallel_asyncio(
            self,
            analyzers: list,
            contract_path: Optional[Path],
            bytecode: Optional[str],
            address: str = None
    ) -> List[AnalysisResult]:
        """Fallback: asyncio.gather (sin Ray)"""
        tasks = []
        for analyzer in analyzers:
            if analyzer.is_available():
                print(f"  ▶ Ejecutando {analyzer.name}...")
                tasks.append(analyzer.analyze(contract_path, bytecode, address))
            else:
                print(f"  ⚠ {analyzer.name} no disponible")

        if not tasks:
            return []

        results = await asyncio.gather(*tasks, return_exceptions=True)

        clean = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                print(f"  ❌ Error en {analyzers[i].name}: {result}")
            else:
                print(f"  ✓ {result.tool}: {len(result.findings)} findings")
                clean.append(result)

        return clean

    def _dict_to_result(self, d: Dict) -> AnalysisResult:
        """Convierte dict a AnalysisResult"""
        findings = []
        for f in d.get("findings", []):
            findings.append(Finding(
                id=f.get("id", ""),
                title=f.get("title", ""),
                description=f.get("description", ""),
                severity=Severity(f.get("severity", "info")),
                world=World(f.get("world", "source")),
                tool=f.get("tool", ""),
                confidence=f.get("confidence", "medium"),
                location=f.get("location"),
                line_number=f.get("line_number"),
                function=f.get("function"),
                validated=f.get("validated", False)
            ))

        return AnalysisResult(
            tool=d.get("tool", ""),
            world=World(d.get("world", "source")),
            success=d.get("success", False),
            findings=findings,
            execution_time=d.get("execution_time", 0),
            error=d.get("error")
        )

    # ═══════════════════════════════════════════════════════════════════════
    # ANALYZE FILE
    # ═══════════════════════════════════════════════════════════════════════

    async def analyze_file(
            self,
            file_path: Path,
            mode: str = "normal",
            contract_name: Optional[str] = None
    ) -> AnalysisReport:
        """Analiza un archivo .sol local"""

        start_time = time.time()

        print(f"\n{'=' * 60}")
        print(f"SENTINEL ENGINE - Análisis Distribuido")
        print(f"Archivo: {file_path}")
        print(f"Modo: {mode}")
        print(f"Ray: {'✓' if self.ray_enabled else '✗'}")
        print(f"{'=' * 60}\n")

        # ID único
        file_hash = hashlib.sha256(file_path.read_bytes()).hexdigest()[:16]
        pseudo_address = f"local_{file_path.stem}_{file_hash}"

        report = AnalysisReport(
            address=pseudo_address,
            contract_name=contract_name or file_path.stem,
            has_source=True,
            is_proxy=False
        )

        # Compilar
        print("📝 Compilando contrato...")
        bytecode = await self._compile_contract(file_path, contract_name)
        if bytecode:
            print(f"  ✓ Bytecode: {len(bytecode)} bytes")
        else:
            print("  ⚠ Sin bytecode")

        # Análisis
        if mode == "quick":
            print("\n⚡ Modo QUICK: Solo Mythril...")
            mythril = MythrilAnalyzer(self.config.get("bytecode_world", {}).get("mythril", {}))
            result = await mythril.analyze(contract_path=file_path, bytecode=bytecode)
            report.bytecode_world_results.append(result)
            report.all_findings.extend(result.findings)

        elif self.ray_enabled and self.ray_tasks:
            # MODO PARALELO CON RAY
            print("\n🔷 MUNDO SOURCE + 🔶 MUNDO BYTECODE (Ray paralelo)...")
            source_results, bytecode_results = await self._run_parallel_ray(
                file_path, bytecode, use_source=True, use_bytecode=True, mode=mode
            )
            report.source_world_results = source_results
            report.bytecode_world_results = bytecode_results
            for r in source_results + bytecode_results:
                report.all_findings.extend(r.findings)

        else:
            # FALLBACK ASYNCIO
            print("\n🔷 MUNDO SOURCE: Slither + Echidna...")
            source_results = await self._run_parallel_asyncio(self.source_analyzers, file_path, bytecode, None)
            report.source_world_results = source_results
            for r in source_results:
                report.all_findings.extend(r.findings)

            print("\n🔶 MUNDO BYTECODE: Mythril + Hevm...")
            analyzers = [a for a in self.bytecode_analyzers if
                         a.name in ["mythril", "hevm"]] if mode != "deep" else self.bytecode_analyzers
            bytecode_results = await self._run_parallel_asyncio(analyzers, file_path, bytecode, None)
            report.bytecode_world_results = bytecode_results
            for r in bytecode_results:
                report.all_findings.extend(r.findings)

        # LLM
        if self.llm_pipeline.enabled and report.all_findings:
            source_code = file_path.read_text()
            await self._run_llm_pipeline(report, source_code, mode)

        # Finalizar
        report.execution_time = time.time() - start_time
        report.compute_summary()
        await self._save_report(report)

        return report

    async def _run_llm_pipeline(self, report: AnalysisReport, source_code: str, mode: str):
        """Pipeline LLM avanzado"""
        print("\n🧠 ANÁLISIS LLM AVANZADO...")
        working_findings = report.all_findings

        # 1. Correlación
        correlation_config = self.config.get("llm", {}).get("correlation", {})
        if correlation_config.get("enabled", True):
            try:
                print("  🔗 Correlando findings...")
                correlator = CorrelatorAgent(self.llm_pipeline.client)
                correlation = await correlator.correlate(working_findings, source_code)
                report.correlation_result = correlation
                clean_findings = correlator.get_consolidated_findings(correlation.correlated_findings,
                                                                      min_confidence=correlation_config.get(
                                                                          "min_confidence", 0.6))
                print(f"    ✓ Duplicados eliminados: {correlation.duplicates_removed}")
                working_findings = clean_findings
            except Exception as e:
                print(f"    ⚠️ Error: {e}")

        # 2. Attack Chains
        chains_config = self.config.get("llm", {}).get("attack_chains", {})
        if chains_config.get("enabled", True):
            try:
                print("  ⚔️  Detectando attack chains...")
                chain_detector = AttackChainAgent(self.llm_pipeline.client)
                chains = await chain_detector.detect_chains(working_findings, source_code)
                report.attack_chains_result = chains
                if chains.chains_found:
                    print(f"    ⚠️  {len(chains.chains_found)} chains detectados")
                working_findings = chains.enhanced_findings
            except Exception as e:
                print(f"    ⚠️ Error: {e}")

        # 3. Pipeline tradicional (filtrado, POCs, remediaciones)
        try:
            print("  🤖 Pipeline LLM...")
            llm_results = await self.llm_pipeline.process(findings=working_findings, source_code=source_code,
                                                          generate_pocs=(mode == "deep"), generate_remediations=True)
            report.llm_filtered_findings = llm_results.get("filtered_findings", [])
            report.llm_analyses.extend(
                [{"finding": a.finding.title, "root_cause": a.root_cause, "cvss": a.cvss_estimate} for a in
                 llm_results.get("analyses", [])])
            report.llm_pocs = [{"finding": p.finding.title, "code": p.poc_code[:500]} for p in
                               llm_results.get("pocs", [])]
            report.llm_remediations = [{"finding": r.finding.title, "fix": r.minimal_fix} for r in
                                       llm_results.get("remediations", [])]
            report.llm_summary = llm_results.get("summary", {})
            report.all_findings = report.llm_filtered_findings
            print(f"    ✓ Findings filtrados: {len(report.llm_filtered_findings)}")
        except Exception as e:
            print(f"  ⚠️ Error: {e}")

    # ═══════════════════════════════════════════════════════════════════════
    # BATCH PARALELO
    # ═══════════════════════════════════════════════════════════════════════

    async def analyze_batch(
            self,
            batch_dir: Path,
            mode: str = "normal",
            recursive: bool = False,
            pattern: str = "*.sol",
            parallel: int = None
    ) -> List[AnalysisReport]:
        """
        Analiza múltiples contratos EN PARALELO.

        Con Ray: N contratos simultáneos, cada uno con sus herramientas en paralelo
        Sin Ray: Secuencial con asyncio
        """

        workers = parallel or DistributedConfig.NUM_WORKERS

        print(f"\n📁 MODO BATCH DISTRIBUIDO")
        print(f"   Directorio: {batch_dir}")
        print(f"   Contratos paralelos: {workers}")
        print(f"   Ray: {'✓' if self.ray_enabled else '✗'}")

        if recursive:
            sol_files = list(batch_dir.rglob(pattern))
        else:
            sol_files = list(batch_dir.glob(pattern))

        if not sol_files:
            print(f"\n❌ No se encontraron archivos {pattern}")
            return []

        print(f"\n✓ Encontrados {len(sol_files)} archivos")
        for i, f in enumerate(sol_files[:10], 1):
            print(f"   {i}. {f.name}")
        if len(sol_files) > 10:
            print(f"   ... y {len(sol_files) - 10} más")

        if self.ray_enabled:
            return await self._batch_parallel_ray(sol_files, mode, workers)
        else:
            return await self._batch_sequential(sol_files, mode)

    async def _batch_parallel_ray(
            self,
            sol_files: List[Path],
            mode: str,
            workers: int
    ) -> List[AnalysisReport]:
        """Batch con Ray - contratos en paralelo"""

        # Crear Ray task para analizar un contrato completo
        @ray.remote(num_cpus=1)
        def analyze_contract_task(
                contract_path: str,
                mode: str,
                config: Dict,
                reports_dir: str,
                project_root: str  # NUEVO: path correcto del proyecto
        ) -> Dict:
            """Ray Task: Analiza un contrato completo"""
            import asyncio
            import sys
            import json
            import hashlib
            import time
            from pathlib import Path

            # Setup imports - usar el project_root pasado
            if project_root not in sys.path:
                sys.path.insert(0, project_root)

            start_time = time.time()
            contract_path = Path(contract_path)
            errors = []  # Capturar errores para debug

            try:
                # Importar dentro del task
                from src.analyzers.slither_analyzer import SlitherAnalyzer
                from src.analyzers.mythril_analyzer import MythrilAnalyzer
                from src.analyzers.echidna_analyzer import EchidnaAnalyzer
                from src.analyzers.hevm_analyzer import HevmAnalyzer
                from src.analyzers.base import Finding, AnalysisResult, World, Severity

                # Compilar
                import subprocess
                bytecode = None
                try:
                    result = subprocess.run(
                        ["solc", "--combined-json", "bin,bin-runtime,abi", str(contract_path)],
                        capture_output=True, text=True, timeout=60
                    )
                    if result.returncode == 0:
                        data = json.loads(result.stdout)
                        for key, val in data.get("contracts", {}).items():
                            bc = val.get("bin-runtime") or val.get("bin")
                            if bc:
                                bytecode = "0x" + bc
                                break
                except Exception as e:
                    errors.append(f"compile: {e}")

                # Ejecutar analyzers secuencialmente dentro del task
                # (Ray ya paraleliza a nivel de contratos)
                all_findings = []
                results_data = {"source": [], "bytecode": []}
                tool_stats = {}  # Track findings por herramienta

                source_config = config.get("source_world", {})
                bytecode_config = config.get("bytecode_world", {})

                # Slither
                if source_config.get("slither", {}).get("enabled", True):
                    try:
                        analyzer = SlitherAnalyzer(source_config.get("slither", {}))
                        if analyzer.is_available():
                            result = asyncio.run(analyzer.analyze(contract_path))
                            results_data["source"].append(result.to_dict())
                            findings_list = [f.to_dict() for f in result.findings]
                            all_findings.extend(findings_list)
                            tool_stats["slither"] = {
                                "findings": len(findings_list),
                                "status": "✓",
                                "time": result.execution_time,
                                "details": [f.get("title", "")[:40] for f in findings_list[:3]]
                            }
                        else:
                            tool_stats["slither"] = {"findings": 0, "status": "⚠ N/A", "time": 0, "details": []}
                    except Exception as e:
                        errors.append(f"slither: {e}")
                        tool_stats["slither"] = {"findings": 0, "status": f"✗", "time": 0, "details": [str(e)[:50]]}

                # Echidna
                if source_config.get("echidna", {}).get("enabled", True):
                    try:
                        analyzer = EchidnaAnalyzer(source_config.get("echidna", {}))
                        if analyzer.is_available():
                            result = asyncio.run(analyzer.analyze(contract_path))
                            results_data["source"].append(result.to_dict())
                            findings_list = [f.to_dict() for f in result.findings]
                            all_findings.extend(findings_list)
                            tool_stats["echidna"] = {
                                "findings": len(findings_list),
                                "status": "✓",
                                "time": result.execution_time,
                                "details": [f.get("title", "")[:40] for f in findings_list[:3]]
                            }
                        else:
                            tool_stats["echidna"] = {"findings": 0, "status": "⚠ N/A", "time": 0, "details": []}
                    except Exception as e:
                        errors.append(f"echidna: {e}")
                        tool_stats["echidna"] = {"findings": 0, "status": f"✗", "time": 0, "details": [str(e)[:50]]}

                # Oracle (LLM-based)
                if source_config.get("oracle", {}).get("enabled", False):
                    try:
                        from src.analyzers.oracle_analyzer import OracleAnalyzer
                        analyzer = OracleAnalyzer(source_config.get("oracle", {}))
                        if analyzer.is_available():
                            result = asyncio.run(analyzer.analyze(contract_path))
                            results_data["source"].append(result.to_dict())
                            findings_list = [f.to_dict() for f in result.findings]
                            all_findings.extend(findings_list)
                            tool_stats["oracle"] = {
                                "findings": len(findings_list),
                                "status": "✓",
                                "time": result.execution_time,
                                "details": [f.get("title", "")[:40] for f in findings_list[:3]]
                            }
                        else:
                            tool_stats["oracle"] = {"findings": 0, "status": "⚠ N/A", "time": 0,
                                                    "details": ["No API key"]}
                    except Exception as e:
                        errors.append(f"oracle: {e}")
                        tool_stats["oracle"] = {"findings": 0, "status": f"✗", "time": 0, "details": [str(e)[:50]]}

                # Business Logic (LLM-based)
                if source_config.get("business_logic", {}).get("enabled", False):
                    try:
                        from src.analyzers.business_logic_analyzer import BusinessLogicAnalyzer
                        analyzer = BusinessLogicAnalyzer(source_config.get("business_logic", {}))
                        if analyzer.is_available():
                            # Pasar findings de otras herramientas para evitar duplicados
                            static_findings = [f.get("title", "") for f in all_findings]
                            result = asyncio.run(analyzer.analyze(contract_path, static_findings=static_findings))
                            results_data["source"].append(result.to_dict())
                            findings_list = [f.to_dict() for f in result.findings]
                            all_findings.extend(findings_list)
                            tool_stats["business_logic"] = {
                                "findings": len(findings_list),
                                "status": "✓",
                                "time": result.execution_time,
                                "details": [f.get("title", "")[:40] for f in findings_list[:3]]
                            }
                        else:
                            tool_stats["business_logic"] = {"findings": 0, "status": "⚠ N/A", "time": 0,
                                                            "details": ["No API key"]}
                    except Exception as e:
                        errors.append(f"business_logic: {e}")
                        tool_stats["business_logic"] = {"findings": 0, "status": f"✗", "time": 0,
                                                        "details": [str(e)[:50]]}

                # Arbitrary Call Analyzer (LLM)
                if source_config.get("arbitrary_call", {}).get("enabled", False):
                    try:
                        from src.analyzers.arbitrary_call_analyzer import ArbitraryCallAnalyzer
                        analyzer = ArbitraryCallAnalyzer(source_config.get("arbitrary_call", {}))
                        if analyzer.is_available():
                            result = asyncio.run(analyzer.analyze(contract_path))
                            results_data["source"].append(result.to_dict())
                            findings_list = [f.to_dict() for f in result.findings]
                            all_findings.extend(findings_list)
                            tool_stats["arbitrary_call"] = {
                                "findings": len(findings_list),
                                "status": "✓",
                                "time": result.execution_time,
                                "details": [f.get("title", "")[:40] for f in findings_list[:3]]
                            }
                        else:
                            tool_stats["arbitrary_call"] = {"findings": 0, "status": "⚠ N/A", "time": 0,
                                                            "details": ["No API key"]}
                    except Exception as e:
                        errors.append(f"arbitrary_call: {e}")
                        tool_stats["arbitrary_call"] = {"findings": 0, "status": f"✗", "time": 0,
                                                        "details": [str(e)[:50]]}

                # Signature Replay Analyzer (LLM)
                if source_config.get("signature_replay", {}).get("enabled", False):
                    try:
                        from src.analyzers.signature_replay_analyzer import SignatureReplayAnalyzer
                        analyzer = SignatureReplayAnalyzer(source_config.get("signature_replay", {}))
                        if analyzer.is_available():
                            result = asyncio.run(analyzer.analyze(contract_path))
                            results_data["source"].append(result.to_dict())
                            findings_list = [f.to_dict() for f in result.findings]
                            all_findings.extend(findings_list)
                            tool_stats["signature_replay"] = {
                                "findings": len(findings_list),
                                "status": "✓",
                                "time": result.execution_time,
                                "details": [f.get("title", "")[:40] for f in findings_list[:3]]
                            }
                        else:
                            tool_stats["signature_replay"] = {"findings": 0, "status": "⚠ N/A", "time": 0,
                                                              "details": ["No API key"]}
                    except Exception as e:
                        errors.append(f"signature_replay: {e}")
                        tool_stats["signature_replay"] = {"findings": 0, "status": f"✗", "time": 0,
                                                          "details": [str(e)[:50]]}

                # Delegatecall Loop Analyzer (LLM)
                if source_config.get("delegatecall_loop", {}).get("enabled", False):
                    try:
                        from src.analyzers.delegatecall_loop_analyzer import DelegatecallLoopAnalyzer
                        analyzer = DelegatecallLoopAnalyzer(source_config.get("delegatecall_loop", {}))
                        if analyzer.is_available():
                            result = asyncio.run(analyzer.analyze(contract_path))
                            results_data["source"].append(result.to_dict())
                            findings_list = [f.to_dict() for f in result.findings]
                            all_findings.extend(findings_list)
                            tool_stats["delegatecall_loop"] = {
                                "findings": len(findings_list),
                                "status": "✓",
                                "time": result.execution_time,
                                "details": [f.get("title", "")[:40] for f in findings_list[:3]]
                            }
                        else:
                            tool_stats["delegatecall_loop"] = {"findings": 0, "status": "⚠ N/A", "time": 0,
                                                               "details": ["No API key"]}
                    except Exception as e:
                        errors.append(f"delegatecall_loop: {e}")
                        tool_stats["delegatecall_loop"] = {"findings": 0, "status": f"✗", "time": 0,
                                                           "details": [str(e)[:50]]}

                # CrossChain Replay Analyzer (LLM)
                if source_config.get("crosschain_replay", {}).get("enabled", False):
                    try:
                        from src.analyzers.crosschain_replay_analyzer import CrossChainReplayAnalyzer
                        analyzer = CrossChainReplayAnalyzer(source_config.get("crosschain_replay", {}))
                        if analyzer.is_available():
                            result = asyncio.run(analyzer.analyze(contract_path))
                            results_data["source"].append(result.to_dict())
                            findings_list = [f.to_dict() for f in result.findings]
                            all_findings.extend(findings_list)
                            tool_stats["crosschain_replay"] = {
                                "findings": len(findings_list),
                                "status": "✓",
                                "time": result.execution_time,
                                "details": [f.get("title", "")[:40] for f in findings_list[:3]]
                            }
                        else:
                            tool_stats["crosschain_replay"] = {"findings": 0, "status": "⚠ N/A", "time": 0,
                                                               "details": ["No API key"]}
                    except Exception as e:
                        errors.append(f"crosschain_replay: {e}")
                        tool_stats["crosschain_replay"] = {"findings": 0, "status": f"✗", "time": 0,
                                                           "details": [str(e)[:50]]}

                # Mythril
                if bytecode_config.get("mythril", {}).get("enabled", True):
                    try:
                        analyzer = MythrilAnalyzer(bytecode_config.get("mythril", {}))
                        if analyzer.is_available():
                            result = asyncio.run(analyzer.analyze(contract_path, bytecode=bytecode))
                            results_data["bytecode"].append(result.to_dict())
                            findings_list = [f.to_dict() for f in result.findings]
                            all_findings.extend(findings_list)
                            tool_stats["mythril"] = {
                                "findings": len(findings_list),
                                "status": "✓",
                                "time": result.execution_time,
                                "details": [f.get("title", "")[:40] for f in findings_list[:3]]
                            }
                        else:
                            tool_stats["mythril"] = {"findings": 0, "status": "⚠ N/A", "time": 0, "details": []}
                    except Exception as e:
                        errors.append(f"mythril: {e}")
                        tool_stats["mythril"] = {"findings": 0, "status": f"✗", "time": 0, "details": [str(e)[:50]]}

                # Hevm
                if bytecode_config.get("hevm", {}).get("enabled", True):
                    try:
                        analyzer = HevmAnalyzer(bytecode_config.get("hevm", {}))
                        if analyzer.is_available():
                            result = asyncio.run(analyzer.analyze(contract_path, bytecode=bytecode))
                            results_data["bytecode"].append(result.to_dict())
                            findings_list = [f.to_dict() for f in result.findings]
                            all_findings.extend(findings_list)
                            tool_stats["hevm"] = {
                                "findings": len(findings_list),
                                "status": "✓",
                                "time": result.execution_time,
                                "details": [f.get("title", "")[:40] for f in findings_list[:3]]
                            }
                        else:
                            tool_stats["hevm"] = {"findings": 0, "status": "⚠ N/A", "time": 0, "details": []}
                    except Exception as e:
                        errors.append(f"hevm: {e}")
                        tool_stats["hevm"] = {"findings": 0, "status": f"✗", "time": 0, "details": [str(e)[:50]]}

                # Calcular summary
                breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
                for f in all_findings:
                    breakdown[f.get("severity", "info")] += 1

                risk_score = breakdown["critical"] * 10 + breakdown["high"] * 5 + breakdown["medium"] * 2 + breakdown[
                    "low"]

                if breakdown["critical"] > 0 or risk_score >= 20:
                    risk_level = "CRITICAL"
                elif breakdown["high"] > 0 or risk_score >= 10:
                    risk_level = "HIGH"
                elif breakdown["medium"] > 0 or risk_score >= 5:
                    risk_level = "MEDIUM"
                elif breakdown["low"] > 0:
                    risk_level = "LOW"
                else:
                    risk_level = "SAFE"

                file_hash = hashlib.sha256(contract_path.read_bytes()).hexdigest()[:16]
                address = f"local_{contract_path.stem}_{file_hash}"

                execution_time = time.time() - start_time

                report_data = {
                    "address": address,
                    "contract_name": contract_path.stem,
                    "has_source": True,
                    "is_proxy": False,
                    "findings": all_findings,
                    "source_world": results_data["source"],
                    "bytecode_world": results_data["bytecode"],
                    "execution_time": execution_time,
                    "errors": errors,
                    "tool_stats": tool_stats,  # Stats por herramienta
                    "summary": {
                        "risk_level": risk_level,
                        "risk_score": risk_score,
                        "total_findings": len(all_findings),
                        "severity_breakdown": breakdown,
                        "execution_time": execution_time,
                        "analyzer_errors": len(errors),
                        "tool_stats": tool_stats  # También en summary
                    }
                }

                # Guardar reporte
                report_dir = Path(reports_dir) / address
                report_dir.mkdir(parents=True, exist_ok=True)
                with open(report_dir / "report.json", 'w') as f:
                    json.dump(report_data, f, indent=2)

                return {
                    "success": True,
                    "contract": contract_path.name,
                    "report": report_data,
                    "errors": errors,
                    "tool_stats": tool_stats  # Retornar para el dashboard
                }

            except Exception as e:
                return {
                    "success": False,
                    "contract": str(contract_path),
                    "error": str(e)
                }

        print(f"\n⚡ Lanzando {len(sol_files)} contratos en PARALELO (max {workers} simultáneos)...\n")

        # Modo de visualización
        # Por defecto: ASCII (funciona en todas las terminales)
        # Para Rich dashboard: SENTINEL_RICH=1 python sentinel.py
        USE_RICH = False
        force_rich = os.environ.get("SENTINEL_RICH", "0") == "1"

        if force_rich:
            try:
                from rich.live import Live
                from rich.table import Table
                from rich.console import Console
                from rich.panel import Panel
                USE_RICH = True
                print("  📊 Modo: Dashboard Rich (SENTINEL_RICH=1)\n")
            except ImportError:
                print("  ⚠️ Rich no instalado, usando ASCII\n")
        else:
            print("  📊 Modo: ASCII (usar SENTINEL_RICH=1 para dashboard visual)\n")

        # Obtener el project root (donde está src/)
        project_root = str(DistributedConfig.PROJECT_ROOT)

        print("  🚀 Inicializando Ray workers (puede tomar unos segundos)...")
        sys.stdout.flush()

        # Lanzar todos los tasks
        futures = {}
        launch_times = {}
        for sol_file in sol_files:
            future = analyze_contract_task.options(num_cpus=1).remote(
                str(sol_file),
                mode,
                self.config,
                str(self.reports_dir),
                project_root  # NUEVO: pasar el path correcto
            )
            futures[sol_file.name] = future
            launch_times[sol_file.name] = time.time()

        # Dar tiempo a Ray para imprimir sus warnings antes del dashboard
        sys.stdout.flush()
        sys.stderr.flush()
        await asyncio.sleep(1.0)  # Esperar 1 segundo para warnings de Ray
        print("  ✓ Workers listos\n")

        # Estado
        reports = []
        completed = 0
        failed = 0
        analyzer_errors = 0
        total = len(sol_files)
        start_time = time.time()
        recent_completed = []
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "SAFE": 0}

        # Stats globales por herramienta
        global_tool_stats = {
            "slither": {"runs": 0, "findings": 0, "errors": 0},
            "echidna": {"runs": 0, "findings": 0, "errors": 0},
            "mythril": {"runs": 0, "findings": 0, "errors": 0},
            "hevm": {"runs": 0, "findings": 0, "errors": 0},
            "oracle": {"runs": 0, "findings": 0, "errors": 0},
            "business_logic": {"runs": 0, "findings": 0, "errors": 0},
            "arbitrary_call": {"runs": 0, "findings": 0, "errors": 0},
            "signature_replay": {"runs": 0, "findings": 0, "errors": 0},
            "delegatecall_loop": {"runs": 0, "findings": 0, "errors": 0}
        }

        # Tracking de vulnerabilidades detectadas
        all_vulns = []  # Lista de todas las vulns: {contract, title, severity, tool, location}
        vuln_types = {}  # Conteo por tipo de vulnerabilidad

        if USE_RICH:
            console = Console()

            def make_dashboard():
                elapsed = time.time() - start_time
                rate = completed / elapsed if elapsed > 0 else 0
                remaining = total - completed
                eta = remaining / rate if rate > 0 else 0
                pct = (completed / total) * 100 if total > 0 else 0

                # Barra de progreso grande
                bar_w = 80
                filled = int(bar_w * completed / total) if total > 0 else 0
                bar = "█" * filled + "░" * (bar_w - filled)

                # Tabla de stats horizontales
                stats_row = Table(show_header=False, box=None, expand=True)
                stats_row.add_column("", justify="center")
                stats_row.add_column("", justify="center")
                stats_row.add_column("", justify="center")
                stats_row.add_column("", justify="center")
                stats_row.add_column("", justify="center")
                stats_row.add_column("", justify="center")
                stats_row.add_row(
                    f"[cyan]⏱️ {elapsed:.0f}s[/cyan]",
                    f"[white]📊 {completed}/{total}[/white]",
                    f"[green]⚡ {rate:.2f}/s[/green]",
                    f"[yellow]🎯 ETA {eta / 60:.1f}m[/yellow]",
                    f"[green]✅ {completed - failed}[/green]",
                    f"[red]❌ {failed}[/red]"
                )

                # Tabla de severidades horizontal
                sev_row = Table(show_header=False, box=None, expand=True)
                sev_row.add_column("", justify="center")
                sev_row.add_column("", justify="center")
                sev_row.add_column("", justify="center")
                sev_row.add_column("", justify="center")
                sev_row.add_column("", justify="center")
                sev_row.add_row(
                    f"[red]🔴 CRIT: {severity_counts['CRITICAL']}[/red]",
                    f"[yellow]🟠 HIGH: {severity_counts['HIGH']}[/yellow]",
                    f"[orange3]🟡 MED: {severity_counts['MEDIUM']}[/orange3]",
                    f"[blue]🔵 LOW: {severity_counts['LOW']}[/blue]",
                    f"[green]✅ SAFE: {severity_counts['SAFE']}[/green]"
                )

                # Tabla de herramientas horizontal
                tools_row = Table(title="🔧 Herramientas", show_header=True, header_style="bold magenta", expand=True)
                tools_row.add_column("Slither", justify="center", width=20)
                tools_row.add_column("Echidna", justify="center", width=20)
                tools_row.add_column("Mythril", justify="center", width=20)
                tools_row.add_column("Hevm", justify="center", width=20)

                def tool_cell(name):
                    ts = global_tool_stats.get(name, {})
                    runs = ts.get("runs", 0)
                    finds = ts.get("findings", 0)
                    errs = ts.get("errors", 0)
                    if errs > 0:
                        return f"[white]{runs} runs[/white] | [green]{finds} finds[/green] | [red]{errs} err[/red]"
                    return f"[white]{runs} runs[/white] | [green]{finds} finds[/green]"

                tools_row.add_row(
                    tool_cell("slither"),
                    tool_cell("echidna"),
                    tool_cell("mythril"),
                    tool_cell("hevm")
                )

                # Tabla en vuelo
                flight = Table(title=f"🔄 En Análisis ({min(workers, len(futures))})", show_header=True,
                               header_style="bold cyan")
                flight.add_column("Contrato", width=35)
                flight.add_column("Tiempo", justify="right", width=10)

                now = time.time()
                for i, (name, _) in enumerate(list(futures.items())[:6]):
                    t = now - launch_times.get(name, now)
                    flight.add_row(name[:35], f"{t:.1f}s")
                if len(futures) > 6:
                    flight.add_row(f"[dim]... +{len(futures) - 6} más[/dim]", "")

                # Tabla recientes
                recent = Table(title="✅ Últimos Completados", show_header=True, header_style="bold green")
                recent.add_column("Contrato", width=30)
                recent.add_column("Risk", width=10)
                recent.add_column("Finds", justify="right", width=6)
                recent.add_column("Time", justify="right", width=8)

                colors = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "orange3", "LOW": "blue", "SAFE": "green",
                          "ERROR": "red"}
                for item in recent_completed[-6:]:
                    c = colors.get(item["risk"], "white")
                    recent.add_row(
                        item["name"][:30],
                        f"[{c}]{item['risk']}[/{c}]",
                        str(item["findings"]),
                        f"{item['time']:.1f}s"
                    )

                # Tabla de últimas vulnerabilidades detectadas
                vulns_table = Table(title="🐛 Últimas Vulnerabilidades Detectadas", show_header=True,
                                    header_style="bold red", expand=True)
                vulns_table.add_column("Severidad", width=10)
                vulns_table.add_column("Tipo", width=35)
                vulns_table.add_column("Contrato", width=20)
                vulns_table.add_column("Tool", width=10)

                sev_colors = {"critical": "red", "high": "yellow", "medium": "orange3", "low": "blue", "info": "dim"}
                for v in all_vulns[-8:]:  # Últimas 8 vulns
                    sc = sev_colors.get(v["severity"], "white")
                    vulns_table.add_row(
                        f"[{sc}]{v['severity'].upper()}[/{sc}]",
                        v["title"][:35],
                        v["contract"][:20],
                        v["tool"].capitalize()
                    )

                # Layout final
                layout = Table.grid(padding=(0, 1))
                layout.add_column(justify="center")

                # Título
                layout.add_row(
                    f"[bold white on blue] 🛡️  SENTINEL - Analizando {total} Contratos [/bold white on blue]")
                layout.add_row("")

                # Barra de progreso
                layout.add_row(f"[cyan]{bar}[/cyan]")
                layout.add_row(f"[bold]{pct:.1f}%[/bold] completado ({completed}/{total})")
                layout.add_row("")

                # Stats
                layout.add_row(stats_row)
                layout.add_row("")

                # Severidades
                layout.add_row(sev_row)
                layout.add_row("")

                # Herramientas
                layout.add_row(tools_row)
                layout.add_row("")

                # Tablas lado a lado: En vuelo + Completados
                side_by_side = Table.grid(padding=2)
                side_by_side.add_column()
                side_by_side.add_column()
                side_by_side.add_row(flight, recent)
                layout.add_row(side_by_side)
                layout.add_row("")

                # Vulnerabilidades
                if all_vulns:
                    layout.add_row(vulns_table)

                return Panel(layout, border_style="blue", title="[bold]SENTINEL Distributed Engine[/bold]")

            try:
                with Live(make_dashboard(), refresh_per_second=2, console=console, transient=False) as live:
                    while futures:
                        done = []
                        for name, future in list(futures.items()):
                            try:
                                result = ray.get(future, timeout=0.05)
                                done.append((name, result))
                            except ray.exceptions.GetTimeoutError:
                                pass
                            except Exception as e:
                                done.append((name, {"success": False, "error": str(e)}))

                    for name, result in done:
                        completed += 1
                        del futures[name]

                        if result.get("success"):
                            report = self._dict_to_report_full(result["report"])
                            reports.append(report)
                            risk = result["report"]["summary"]["risk_level"]
                            findings = result["report"]["summary"]["total_findings"]
                            exec_time = result["report"]["execution_time"]
                            errs = len(result.get("errors", []))
                            analyzer_errors += errs
                            severity_counts[risk] = severity_counts.get(risk, 0) + 1

                            # Acumular stats de herramientas
                            ts = result.get("tool_stats", {})
                            for tool_name in ["slither", "echidna", "mythril", "hevm", "oracle", "business_logic",
                                              "arbitrary_call", "signature_replay", "delegatecall_loop"]:
                                if tool_name in ts:
                                    tool_data = ts[tool_name]
                                    global_tool_stats[tool_name]["runs"] += 1
                                    global_tool_stats[tool_name]["findings"] += tool_data.get("findings", 0)
                                    if tool_data.get("status", "").startswith("✗"):
                                        global_tool_stats[tool_name]["errors"] += 1

                            # Extraer vulnerabilidades detalladas
                            for f in result["report"].get("findings", []):
                                vuln_info = {
                                    "contract": name,
                                    "title": f.get("title", "Unknown")[:60],
                                    "severity": f.get("severity", "info"),
                                    "tool": f.get("tool", "unknown"),
                                    "location": f.get("location", ""),
                                    "line": f.get("line_number", ""),
                                    "function": f.get("function", ""),
                                    "description": f.get("description", "")[:100]
                                }
                                all_vulns.append(vuln_info)

                                # Contar por tipo
                                vuln_title = f.get("title", "Unknown")
                                if vuln_title not in vuln_types:
                                    vuln_types[vuln_title] = {"count": 0, "severity": f.get("severity", "info"),
                                                              "tool": f.get("tool", "")}
                                vuln_types[vuln_title]["count"] += 1

                            recent_completed.append({
                                "name": name,
                                "risk": risk,
                                "findings": findings,
                                "time": exec_time,
                                "errors": errs
                            })
                        else:
                            failed += 1
                            recent_completed.append(
                                {"name": name, "risk": "ERROR", "findings": 0, "time": 0, "errors": 0})

                    live.update(make_dashboard())
                    await asyncio.sleep(0.2)
            except Exception as e:
                print(f"\n  ⚠️ Error en dashboard Rich: {e}")
                print("  📊 Usando modo texto...\n")
                USE_RICH = False  # Fallback al modo ASCII

        if not USE_RICH:
            # Fallback ASCII mejorado
            print("\n  📊 Progreso:\n")
            last_print_time = 0

            while futures:
                done = []
                for name, future in list(futures.items()):
                    try:
                        result = ray.get(future, timeout=0.1)
                        done.append((name, result))
                    except ray.exceptions.GetTimeoutError:
                        pass
                    except Exception as e:
                        done.append((name, {"success": False, "error": str(e)}))

                for name, result in done:
                    completed += 1
                    del futures[name]
                    elapsed = time.time() - start_time
                    rate = completed / elapsed if elapsed > 0 else 0
                    eta = (total - completed) / rate if rate > 0 else 0
                    pct = (completed / total) * 100
                    bar = "█" * int(40 * completed / total) + "░" * (40 - int(40 * completed / total))

                    if result.get("success"):
                        report = self._dict_to_report_full(result["report"])
                        reports.append(report)
                        risk = result["report"]["summary"]["risk_level"]
                        findings_count = result["report"]["summary"]["total_findings"]
                        errs = len(result.get("errors", []))
                        analyzer_errors += errs
                        severity_counts[risk] = severity_counts.get(risk, 0) + 1

                        # Acumular stats de herramientas
                        ts = result.get("tool_stats", {})
                        for tool_name in ["slither", "echidna", "mythril", "hevm", "oracle", "business_logic",
                                          "arbitrary_call", "signature_replay", "delegatecall_loop"]:
                            if tool_name in ts:
                                tool_data = ts[tool_name]
                                global_tool_stats[tool_name]["runs"] += 1
                                global_tool_stats[tool_name]["findings"] += tool_data.get("findings", 0)
                                if tool_data.get("status", "").startswith("✗"):
                                    global_tool_stats[tool_name]["errors"] += 1

                        # Extraer vulnerabilidades
                        for f in result["report"].get("findings", []):
                            vuln_info = {
                                "contract": name,
                                "title": f.get("title", "Unknown")[:60],
                                "severity": f.get("severity", "info"),
                                "tool": f.get("tool", "unknown"),
                            }
                            all_vulns.append(vuln_info)

                            vuln_title = f.get("title", "Unknown")
                            if vuln_title not in vuln_types:
                                vuln_types[vuln_title] = {"count": 0, "severity": f.get("severity", "info"),
                                                          "tool": f.get("tool", "")}
                            vuln_types[vuln_title]["count"] += 1

                        # Imprimir línea de progreso cada contrato
                        print(
                            f"  [{bar}] {pct:5.1f}% | {completed}/{total} | {name[:25]:<25} | {risk:<8} | {findings_count} finds | ETA: {eta / 60:.1f}m")
                    else:
                        failed += 1
                        print(
                            f"  [{bar}] {pct:5.1f}% | {completed}/{total} | {name[:25]:<25} | ERROR    | ETA: {eta / 60:.1f}m")

                await asyncio.sleep(0.1)
            print()

        elapsed_total = time.time() - start_time
        print(
            f"\n✅ Completado: {elapsed_total:.1f}s ({elapsed_total / 60:.1f} min) | OK: {completed - failed} | Err: {failed}")
        print(f"  📊 Exitosos: {completed - failed} | Fallidos: {failed}")

        # Resumen de herramientas
        print(f"\n🔧 HERRAMIENTAS:")
        print("┌" + "─" * 50 + "┐")
        print(f"│ {'Tool':<12} │ {'Runs':>6} │ {'Findings':>10} │ {'Errors':>8} │")
        print("├" + "─" * 50 + "┤")
        for tool_name in ["slither", "echidna", "mythril", "hevm", "oracle", "business_logic",
                        "arbitrary_call", "signature_replay", "delegatecall_loop"]:
            ts = global_tool_stats.get(tool_name, {})
            runs = ts.get("runs", 0)
            finds = ts.get("findings", 0)
            errs = ts.get("errors", 0)
            print(f"│ {tool_name.capitalize():<12} │ {runs:>6} │ {finds:>10} │ {errs:>8} │")
        print("└" + "─" * 50 + "┘")

        # Resumen de tipos de vulnerabilidades
        if vuln_types:
            print(f"\n🐛 TIPOS DE VULNERABILIDADES DETECTADAS ({len(all_vulns)} total):")
            print("┌" + "─" * 85 + "┐")
            print(f"│ {'Severidad':<10} │ {'Tipo de Vulnerabilidad':<45} │ {'Count':>6} │ {'Tool':<12} │")
            print("├" + "─" * 85 + "┤")

            # Ordenar por severidad y count
            sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            sorted_vulns = sorted(vuln_types.items(),
                                  key=lambda x: (sev_order.get(x[1]["severity"], 5), -x[1]["count"]))

            for vuln_title, data in sorted_vulns[:20]:  # Top 20
                sev = data["severity"].upper()
                count = data["count"]
                tool = data["tool"].capitalize()
                print(f"│ {sev:<10} │ {vuln_title[:45]:<45} │ {count:>6} │ {tool:<12} │")

            if len(sorted_vulns) > 20:
                print(
                    f"│ {'...':<10} │ {'... y ' + str(len(sorted_vulns) - 20) + ' tipos más':<45} │ {'':>6} │ {'':>12} │")
            print("└" + "─" * 85 + "┘")

        # Top contratos más vulnerables
        if all_vulns:
            contract_vulns = {}
            for v in all_vulns:
                c = v["contract"]
                if c not in contract_vulns:
                    contract_vulns[c] = {"total": 0, "critical": 0, "high": 0}
                contract_vulns[c]["total"] += 1
                if v["severity"] == "critical":
                    contract_vulns[c]["critical"] += 1
                elif v["severity"] == "high":
                    contract_vulns[c]["high"] += 1

            sorted_contracts = sorted(contract_vulns.items(),
                                      key=lambda x: (x[1]["critical"], x[1]["high"], x[1]["total"]), reverse=True)

            print(f"\n⚠️  TOP CONTRATOS MÁS VULNERABLES:")
            print("┌" + "─" * 60 + "┐")
            print(f"│ {'Contrato':<30} │ {'Total':>6} │ {'Crit':>6} │ {'High':>6} │")
            print("├" + "─" * 60 + "┤")
            for contract, data in sorted_contracts[:10]:
                print(f"│ {contract[:30]:<30} │ {data['total']:>6} │ {data['critical']:>6} │ {data['high']:>6} │")
            print("└" + "─" * 60 + "┘")

        return reports

    async def _batch_sequential(
            self,
            sol_files: List[Path],
            mode: str
    ) -> List[AnalysisReport]:
        """Batch secuencial (fallback sin Ray)"""
        reports = []

        for i, sol_file in enumerate(sol_files, 1):
            print(f"\n[{i}/{len(sol_files)}] {sol_file.name}")
            try:
                report = await self.analyze_file(sol_file, mode)
                reports.append(report)
            except Exception as e:
                print(f"  ✗ Error: {e}")

        return reports

    def _dict_to_report_full(self, d: Dict) -> AnalysisReport:
        """Reconstruye AnalysisReport desde dict"""
        findings = []
        for f in d.get("findings", []):
            findings.append(Finding(
                id=f.get("id", ""),
                title=f.get("title", ""),
                description=f.get("description", ""),
                severity=Severity(f.get("severity", "info")),
                world=World(f.get("world", "source")),
                tool=f.get("tool", ""),
                confidence=f.get("confidence", "medium"),
                location=f.get("location"),
                line_number=f.get("line_number"),
                function=f.get("function"),
                validated=f.get("validated", False)
            ))

        report = AnalysisReport(
            address=d.get("address", ""),
            contract_name=d.get("contract_name"),
            has_source=d.get("has_source", True),
            is_proxy=d.get("is_proxy", False)
        )
        report.all_findings = findings
        report.summary = d.get("summary", {})
        report.execution_time = d.get("execution_time", 0)

        return report

    # ═══════════════════════════════════════════════════════════════════════
    # UTILITIES
    # ═══════════════════════════════════════════════════════════════════════

    async def _compile_contract(self, file_path: Path, contract_name: Optional[str] = None) -> Optional[str]:
        try:
            result = subprocess.run(["solc", "--combined-json", "bin,bin-runtime,abi", str(file_path)],
                                    capture_output=True, text=True, timeout=DistributedConfig.COMPILE_TIMEOUT)
            if result.returncode != 0:
                return None
            data = json.loads(result.stdout)
            for key, val in data.get("contracts", {}).items():
                name = key.split(":")[-1]
                if contract_name and name != contract_name:
                    continue
                bc = val.get("bin-runtime") or val.get("bin")
                if bc:
                    return "0x" + bc
            return None
        except:
            return None

    async def _save_report(self, report: AnalysisReport):
        report_dir = self.reports_dir / report.address
        report_dir.mkdir(parents=True, exist_ok=True)
        with open(report_dir / "report.json", 'w') as f:
            json.dump(report.to_dict(), f, indent=2)
        md = self._generate_markdown(report)
        (report_dir / "summary.md").write_text(md)
        print(f"\n📄 Reporte: {report_dir}")

    def _generate_markdown(self, report: AnalysisReport) -> str:
        s = report.summary
        md = f"""# Análisis: {report.address}

**Contrato:** {report.contract_name or 'Unknown'}  
**Fecha:** {report.timestamp}  
**Source:** {'✓' if report.has_source else '✗'} | **Proxy:** {'✓' if report.is_proxy else '✗'}

## Resumen

| Métrica | Valor |
|---------|-------|
| Nivel de Riesgo | **{s.get('risk_level', 'N/A')}** |
| Risk Score | {s.get('risk_score', 0)} |
| Total Findings | {s.get('total_findings', 0)} |
| Tiempo | {s.get('execution_time', 0):.1f}s |

## Severidad

| Sev | # |
|-----|---|
| 🔴 Critical | {s.get('severity_breakdown', {}).get('critical', 0)} |
| 🟠 High | {s.get('severity_breakdown', {}).get('high', 0)} |
| 🟡 Medium | {s.get('severity_breakdown', {}).get('medium', 0)} |
| 🔵 Low | {s.get('severity_breakdown', {}).get('low', 0)} |

"""
        if report.attack_chains_result and report.attack_chains_result.chains_found:
            md += f"\n## ⚠️ Attack Chains: {len(report.attack_chains_result.chains_found)}\n"
            for c in report.attack_chains_result.chains_found:
                md += f"\n### 🔗 {c.name}\n- Severity: {c.severity.value}\n- Exploitability: {c.exploitability}\n"

        md += "\n---\n*SENTINEL Engine v3.0 Distributed*"
        return md

    def check_tools(self) -> Dict[str, bool]:
        status = {}
        for a in self.source_analyzers + self.bytecode_analyzers:
            status[a.name] = a.is_available()
        status["panoramix"] = self.decompiler.is_available()
        status["ray"] = self.ray_enabled
        status["ray_workers"] = DistributedConfig.NUM_WORKERS if self.ray_enabled else 0
        if self.llm_pipeline.enabled:
            status["llm_pipeline"] = True
        return status

    # ═══════════════════════════════════════════════════════════════════════
    # ANALYZE (address) - Compatibilidad
    # ═══════════════════════════════════════════════════════════════════════

    async def analyze(self, address: str, mode: str = "normal", validate: bool = True, decompile: bool = False,
                      tx_hashes: Optional[List[str]] = None, skip_fetch: bool = False) -> AnalysisReport:
        """Analiza contrato por address"""
        print(f"\n{'=' * 60}")
        print(f"SENTINEL ENGINE - Análisis de {address}")
        print(f"{'=' * 60}\n")

        if not skip_fetch:
            print("📥 Obteniendo contrato...")
            contract_info = await self.fetcher.fetch(address)
        else:
            contract_info = ContractInfo(address=address)
            contract_dir = self.fetcher.contracts_dir / address
            if (contract_dir / "sources").exists():
                contract_info.has_source = True
                sources = list((contract_dir / "sources").glob("*.sol"))
                if sources:
                    contract_info.source_path = sources[0]
            bytecode_file = contract_dir / "bytecode.bin"
            if bytecode_file.exists():
                contract_info.bytecode = bytecode_file.read_text()

        print(f"  📝 Has source: {contract_info.has_source}")
        print(f"  🔗 Is proxy: {contract_info.is_proxy}")

        if contract_info.source_path:
            return await self.analyze_file(contract_info.source_path, mode)

        # Solo bytecode
        report = AnalysisReport(address=address, contract_name=contract_info.name, has_source=False,
                                is_proxy=contract_info.is_proxy)

        if self.ray_enabled and self.ray_tasks:
            _, bytecode_results = await self._run_parallel_ray(None, contract_info.bytecode, use_source=False,
                                                               use_bytecode=True, mode=mode)
        else:
            analyzers = [a for a in self.bytecode_analyzers if a.name in ["mythril", "hevm"]]
            bytecode_results = await self._run_parallel_asyncio(analyzers, None, contract_info.bytecode, address)

        report.bytecode_world_results = bytecode_results
        for r in bytecode_results:
            report.all_findings.extend(r.findings)

        if validate and self.validator:
            print("\n✅ VALIDACIÓN: Erigon traces...")
            validated = await self.validator.validate_findings(report.all_findings, address, tx_hashes)
            report.all_findings = validated
            report.validated_findings = [f for f in validated if f.validated]

        if decompile and contract_info.bytecode:
            print("\n🔍 DECOMPILACIÓN...")
            decomp = self.decompiler.decompile(bytecode=contract_info.bytecode)
            if decomp.get("success"):
                report.decompiled_code = decomp.get("decompiled_code")

        report.compute_summary()
        await self._save_report(report)
        return report