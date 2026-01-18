"""
Panoramix Decompiler - Puente humano

Para entender bytecode cuando no hay source o para validar hallazgos.
"""

from pathlib import Path
from typing import Dict, Any, Optional
import subprocess
import tempfile
import os


class PanoramixDecompiler:
    """
    Panoramix - Decompilador de bytecode EVM
    
    Uso:
    - Cuando no hay source verificado
    - Para validar que el bytecode hace lo que el source dice
    - Para review humano de contratos sospechosos
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.timeout = config.get("timeout", 300)
        self.output_format = config.get("config", {}).get("output_format", "sol")
    
    def is_available(self) -> bool:
        """Verifica si Panoramix está instalado"""
        try:
            result = subprocess.run(
                ["panoramix", "--help"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except:
            return False
    
    def decompile(
        self,
        bytecode: Optional[str] = None,
        address: Optional[str] = None,
        output_path: Optional[Path] = None
    ) -> Dict[str, Any]:
        """
        Decompila bytecode a código legible.
        
        Returns:
            {
                "success": bool,
                "decompiled_code": str,
                "functions": List[str],
                "storage_layout": Dict,
                "error": Optional[str]
            }
        """
        
        if not self.is_available():
            return {
                "success": False,
                "error": "Panoramix not installed (pip install panoramix-decompiler)"
            }
        
        # Preparar input
        if bytecode:
            # Crear archivo temporal con bytecode
            with tempfile.NamedTemporaryFile(
                mode='w', 
                suffix='.bin', 
                delete=False
            ) as f:
                f.write(bytecode.replace("0x", ""))
                input_file = f.name
            
            cmd = ["panoramix", input_file]
            
        elif address:
            cmd = ["panoramix", address]
            input_file = None
            
        else:
            return {
                "success": False,
                "error": "No bytecode or address provided"
            }
        
        # Agregar opciones
        if self.output_format == "sol":
            cmd.append("--sol")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=self.timeout,
                text=True
            )
            
            # Limpiar archivo temporal
            if input_file:
                try:
                    os.unlink(input_file)
                except:
                    pass
            
            if result.returncode != 0:
                return {
                    "success": False,
                    "error": result.stderr or "Decompilation failed"
                }
            
            decompiled = result.stdout
            
            # Extraer información
            functions = self._extract_functions(decompiled)
            storage = self._extract_storage_layout(decompiled)
            
            # Guardar si se especificó output
            if output_path:
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text(decompiled)
            
            return {
                "success": True,
                "decompiled_code": decompiled,
                "functions": functions,
                "storage_layout": storage,
                "output_file": str(output_path) if output_path else None
            }
            
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": f"Decompilation timeout ({self.timeout}s)"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def _extract_functions(self, code: str) -> list:
        """Extrae nombres de funciones del código decompilado"""
        import re
        
        # Patterns para funciones
        patterns = [
            r'function\s+(\w+)\s*\(',          # Solidity style
            r'def\s+(\w+)\s*\(',               # Python style (viejo panoramix)
            r'#\s*Function:\s*(\w+)',          # Comentarios
        ]
        
        functions = set()
        for pattern in patterns:
            matches = re.findall(pattern, code)
            functions.update(matches)
        
        return list(functions)
    
    def _extract_storage_layout(self, code: str) -> Dict:
        """Extrae layout de storage del código decompilado"""
        import re
        
        storage = {}
        
        # Buscar slots de storage
        # Patterns comunes de Panoramix
        patterns = [
            r'stor(\d+)',                      # stor0, stor1, etc
            r'storage\[(\d+)\]',               # storage[0]
            r'slot_(\w+)',                     # slot_admin
            r'_(\w+)_slot\s*=\s*(\d+)',       # _admin_slot = 0
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, code)
            for match in matches:
                if isinstance(match, tuple):
                    name, slot = match
                    storage[name] = int(slot)
                else:
                    storage[f"slot_{match}"] = int(match) if match.isdigit() else match
        
        return storage
    
    def compare_with_source(
        self,
        decompiled: str,
        source: str
    ) -> Dict[str, Any]:
        """
        Compara código decompilado con source original.
        Útil para detectar discrepancias entre lo que dice el source
        y lo que realmente hace el bytecode.
        """
        
        decompiled_funcs = set(self._extract_functions(decompiled))
        source_funcs = set(self._extract_functions(source))
        
        # Funciones que aparecen en source pero no en bytecode
        # (pueden ser funciones internas optimizadas)
        missing_in_bytecode = source_funcs - decompiled_funcs
        
        # Funciones en bytecode que no están en source
        # (código oculto o funciones de fallback)
        extra_in_bytecode = decompiled_funcs - source_funcs
        
        # Storage layout
        decompiled_storage = self._extract_storage_layout(decompiled)
        
        return {
            "matching_functions": list(source_funcs & decompiled_funcs),
            "missing_in_bytecode": list(missing_in_bytecode),
            "extra_in_bytecode": list(extra_in_bytecode),
            "storage_layout": decompiled_storage,
            "suspicious": len(extra_in_bytecode) > 0
        }
