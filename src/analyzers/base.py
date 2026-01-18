"""
Base Analyzer - Clase base para todos los analizadores

Cada analizador pertenece a uno de dos mundos:
- SOURCE: Analiza código .sol (Slither, Echidna)
- BYTECODE: Analiza bytecode compilado (Mythril, Manticore, Hevm)
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Any, Optional
from pathlib import Path
import subprocess
import json
import shutil
import asyncio
from datetime import datetime


class World(Enum):
    """Mundo al que pertenece el analizador"""
    SOURCE = "source"      # Requiere .sol
    BYTECODE = "bytecode"  # Trabaja con bytecode


class Severity(Enum):
    """Severidad de findings"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """Un hallazgo de seguridad normalizado"""
    id: str
    title: str
    description: str
    severity: Severity
    world: World
    tool: str
    confidence: str = "medium"
    location: Optional[str] = None
    line_number: Optional[int] = None
    function: Optional[str] = None
    raw_output: Optional[Dict] = None
    validated: bool = False
    validation_tx: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "world": self.world.value,
            "tool": self.tool,
            "confidence": self.confidence,
            "location": self.location,
            "line_number": self.line_number,
            "function": self.function,
            "validated": self.validated,
            "validation_tx": self.validation_tx
        }


@dataclass
class AnalysisResult:
    """Resultado de un análisis"""
    tool: str
    world: World
    success: bool
    findings: List[Finding] = field(default_factory=list)
    execution_time: float = 0.0
    error: Optional[str] = None
    raw_output: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            "tool": self.tool,
            "world": self.world.value,
            "success": self.success,
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "execution_time": self.execution_time,
            "error": self.error
        }


class BaseAnalyzer(ABC):
    """Clase base para todos los analizadores"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.timeout = config.get("timeout", 300)
        self.enabled = config.get("enabled", True)
        
    @property
    @abstractmethod
    def name(self) -> str:
        """Nombre del analizador"""
        pass
    
    @property
    @abstractmethod
    def world(self) -> World:
        """Mundo al que pertenece (SOURCE o BYTECODE)"""
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        """Verifica si la herramienta está instalada"""
        pass
    
    @abstractmethod
    async def analyze(
        self, 
        contract_path: Path,
        bytecode: Optional[str] = None,
        address: Optional[str] = None
    ) -> AnalysisResult:
        """Ejecuta el análisis"""
        pass
    
    @abstractmethod
    def parse_output(self, output: str) -> List[Finding]:
        """Parsea la salida de la herramienta a Findings normalizados"""
        pass
    
    def _check_tool(self, tool_name: str) -> bool:
        """Verifica si un comando está disponible"""
        return shutil.which(tool_name) is not None
    
    async def _run_command(
        self, 
        cmd: List[str], 
        cwd: Optional[Path] = None
    ) -> tuple[int, str, str]:
        """Ejecuta un comando de forma asíncrona"""
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self.timeout
            )
            
            return (
                process.returncode,
                stdout.decode("utf-8", errors="replace"),
                stderr.decode("utf-8", errors="replace")
            )
            
        except asyncio.TimeoutError:
            process.kill()
            return (-1, "", f"Timeout after {self.timeout}s")
        except Exception as e:
            return (-1, "", str(e))
    
    def _generate_finding_id(self, tool: str, title: str, location: str = "") -> str:
        """Genera un ID único para un finding"""
        import hashlib
        content = f"{tool}:{title}:{location}"
        return hashlib.sha256(content.encode()).hexdigest()[:12]
