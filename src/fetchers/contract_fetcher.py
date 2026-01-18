"""
Contract Fetcher - Obtiene contratos desde múltiples fuentes

Flujo: Sourcify → Etherscan → Nodo (bytecode)
"""

from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass
import aiohttp
import asyncio
import json
import os


@dataclass
class ContractInfo:
    """Información de un contrato"""
    address: str
    name: Optional[str] = None
    has_source: bool = False
    source_path: Optional[Path] = None
    bytecode: Optional[str] = None
    abi: Optional[list] = None
    compiler_version: Optional[str] = None
    is_proxy: bool = False
    implementation_address: Optional[str] = None


class ContractFetcher:
    """
    Contract Fetcher - Obtiene código y metadata de contratos
    
    Prioridad:
    1. Sourcify - código verificado con metadata completa
    2. Etherscan - código verificado
    3. Nodo directo - solo bytecode
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.contracts_dir = Path(config.get("directories", {}).get(
            "contracts", "./contracts"
        ))
        self.contracts_dir.mkdir(parents=True, exist_ok=True)
        
        # Sourcify config
        sourcify = config.get("sources", {}).get("sourcify", {})
        self.sourcify_enabled = sourcify.get("enabled", True)
        self.sourcify_url = sourcify.get("base_url", "https://sourcify.dev/server")
        
        # Etherscan config
        etherscan = config.get("sources", {}).get("etherscan", {})
        self.etherscan_enabled = etherscan.get("enabled", True)
        self.etherscan_url = etherscan.get("base_url", "https://api.etherscan.io/api")
        self.etherscan_key = os.environ.get(
            "ETHERSCAN_API_KEY",
            etherscan.get("api_key", "")
        )
        
        # Node config
        node = config.get("node", {})
        self.rpc_url = node.get("rpc_url", "http://localhost:8545")
        self.chain_id = node.get("chain_id", 1)
    
    async def fetch(self, address: str) -> ContractInfo:
        """
        Obtiene información del contrato.
        
        Intenta en orden: Sourcify → Etherscan → Nodo
        """
        
        address = self._normalize_address(address)
        contract_dir = self.contracts_dir / address
        contract_dir.mkdir(parents=True, exist_ok=True)
        
        info = ContractInfo(address=address)
        
        # 1. Intentar Sourcify
        if self.sourcify_enabled:
            sourcify_result = await self._fetch_sourcify(address, contract_dir)
            if sourcify_result:
                info.has_source = True
                info.source_path = sourcify_result.get("source_path")
                info.name = sourcify_result.get("name")
                info.compiler_version = sourcify_result.get("compiler")
                info.abi = sourcify_result.get("abi")
        
        # 2. Fallback a Etherscan
        if not info.has_source and self.etherscan_enabled:
            etherscan_result = await self._fetch_etherscan(address, contract_dir)
            if etherscan_result:
                info.has_source = True
                info.source_path = etherscan_result.get("source_path")
                info.name = etherscan_result.get("name")
                info.abi = etherscan_result.get("abi")
        
        # 3. Siempre obtener bytecode del nodo
        bytecode = await self._fetch_bytecode(address)
        if bytecode:
            info.bytecode = bytecode
            # Guardar bytecode
            bytecode_file = contract_dir / "bytecode.bin"
            bytecode_file.write_text(bytecode)
        
        # 4. Detectar si es proxy
        if info.bytecode:
            proxy_info = self._detect_proxy(info.bytecode)
            info.is_proxy = proxy_info.get("is_proxy", False)
            info.implementation_address = proxy_info.get("implementation")
        
        return info
    
    async def _fetch_sourcify(
        self, 
        address: str, 
        output_dir: Path
    ) -> Optional[Dict]:
        """Obtiene código de Sourcify"""
        
        async with aiohttp.ClientSession() as session:
            # Primero verificar si está verificado
            check_url = f"{self.sourcify_url}/check-all-by-addresses?addresses={address}&chainIds={self.chain_id}"
            
            try:
                async with session.get(check_url, timeout=30) as resp:
                    if resp.status != 200:
                        return None
                    
                    data = await resp.json()
                    if not data or not data[0].get("status"):
                        return None
                
                # Obtener archivos
                files_url = f"{self.sourcify_url}/files/{self.chain_id}/{address}"
                async with session.get(files_url, timeout=30) as resp:
                    if resp.status != 200:
                        return None
                    
                    files = await resp.json()
                    
                    # Guardar archivos
                    source_dir = output_dir / "sources"
                    source_dir.mkdir(exist_ok=True)
                    
                    main_source = None
                    abi = None
                    compiler = None
                    name = None
                    
                    for file in files:
                        filename = file.get("name", "")
                        content = file.get("content", "")
                        
                        if filename.endswith(".sol"):
                            file_path = source_dir / filename
                            file_path.write_text(content)
                            if not main_source:
                                main_source = file_path
                        
                        elif filename == "metadata.json":
                            metadata = json.loads(content)
                            compiler = metadata.get("compiler", {}).get("version")
                            # Encontrar nombre del contrato principal
                            output = metadata.get("output", {})
                            if output:
                                abi = list(output.get("abi", []))
                    
                    return {
                        "source_path": main_source,
                        "name": main_source.stem if main_source else None,
                        "compiler": compiler,
                        "abi": abi
                    }
                    
            except Exception as e:
                return None
    
    async def _fetch_etherscan(
        self, 
        address: str, 
        output_dir: Path
    ) -> Optional[Dict]:
        """Obtiene código de Etherscan"""
        
        if not self.etherscan_key:
            return None
        
        async with aiohttp.ClientSession() as session:
            url = f"{self.etherscan_url}?module=contract&action=getsourcecode&address={address}&apikey={self.etherscan_key}"
            
            try:
                async with session.get(url, timeout=30) as resp:
                    if resp.status != 200:
                        return None
                    
                    data = await resp.json()
                    
                    if data.get("status") != "1":
                        return None
                    
                    result = data.get("result", [{}])[0]
                    source = result.get("SourceCode", "")
                    name = result.get("ContractName", "Contract")
                    abi_str = result.get("ABI", "[]")
                    
                    if not source or source == "":
                        return None
                    
                    # Guardar source
                    source_dir = output_dir / "sources"
                    source_dir.mkdir(exist_ok=True)
                    
                    # Manejar source multi-archivo (JSON)
                    if source.startswith("{{"):
                        # Multi-archivo
                        source_json = json.loads(source[1:-1])
                        sources = source_json.get("sources", {})
                        main_source = None
                        for filename, content in sources.items():
                            file_path = source_dir / Path(filename).name
                            file_path.write_text(content.get("content", ""))
                            if not main_source:
                                main_source = file_path
                    else:
                        # Archivo único
                        main_source = source_dir / f"{name}.sol"
                        main_source.write_text(source)
                    
                    # Parsear ABI
                    try:
                        abi = json.loads(abi_str)
                    except:
                        abi = []
                    
                    return {
                        "source_path": main_source,
                        "name": name,
                        "abi": abi
                    }
                    
            except Exception as e:
                return None
    
    async def _fetch_bytecode(self, address: str) -> Optional[str]:
        """Obtiene bytecode del nodo"""
        
        async with aiohttp.ClientSession() as session:
            payload = {
                "jsonrpc": "2.0",
                "method": "eth_getCode",
                "params": [address, "latest"],
                "id": 1
            }
            
            try:
                async with session.post(
                    self.rpc_url,
                    json=payload,
                    timeout=30
                ) as resp:
                    data = await resp.json()
                    
                    bytecode = data.get("result", "0x")
                    if bytecode and bytecode != "0x":
                        return bytecode
                    return None
                    
            except Exception as e:
                return None
    
    def _detect_proxy(self, bytecode: str) -> Dict[str, Any]:
        """Detecta si el contrato es un proxy"""
        
        bytecode_lower = bytecode.lower()
        
        # EIP-1967 implementation slot
        impl_slot = "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
        
        # EIP-1967 admin slot
        admin_slot = "b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
        
        # EIP-1822 (UUPS)
        uups_slot = "c5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7"
        
        is_proxy = any(slot in bytecode_lower for slot in [impl_slot, admin_slot, uups_slot])
        
        # TODO: Leer implementation address del storage
        
        return {
            "is_proxy": is_proxy,
            "implementation": None  # Requiere llamada al nodo
        }
    
    def _normalize_address(self, address: str) -> str:
        """Normaliza dirección a checksum"""
        address = address.lower().strip()
        if not address.startswith("0x"):
            address = "0x" + address
        return address
