#!/usr/bin/env python3
"""
Contract Replicator - Genera múltiples copias de un contrato .sol

Uso:
    python replicate_contract.py MyContract.sol --count 10000
"""

import argparse
from pathlib import Path
import re


def replicate_contract(
        input_file: Path,
        output_dir: Path,
        count: int = 10000,
        modify_name: bool = True,
        prefix: str = "Contract"
) -> int:
    """
    Replica un contrato .sol múltiples veces

    Args:
        input_file: Archivo .sol original
        output_dir: Directorio de salida
        count: Número de copias a generar
        modify_name: Si True, modifica el nombre del contrato en cada copia
        prefix: Prefijo para los archivos generados

    Returns:
        Número de archivos generados
    """

    if not input_file.exists():
        print(f"❌ Archivo no encontrado: {input_file}")
        return 0

    # Crear directorio de salida
    output_dir.mkdir(parents=True, exist_ok=True)

    # Leer contenido original
    original_content = input_file.read_text()

    # Detectar nombre del contrato original
    contract_name_match = re.search(r'contract\s+(\w+)', original_content)
    original_contract_name = contract_name_match.group(1) if contract_name_match else None

    print(f"\n🔄 Replicando contrato...")
    print(f"   Archivo original: {input_file}")
    print(f"   Contrato detectado: {original_contract_name or 'N/A'}")
    print(f"   Número de copias: {count:,}")
    print(f"   Directorio salida: {output_dir}")
    print(f"   Modificar nombres: {modify_name}")

    # Generar copias
    generated = 0
    batch_size = 1000  # Mostrar progreso cada 1000 archivos

    for i in range(count):
        # Nombre del archivo
        filename = f"{prefix}_{i + 1:05d}.sol"
        output_file = output_dir / filename

        # Contenido (modificado o original)
        if modify_name and original_contract_name:
            # Cambiar nombre del contrato
            new_contract_name = f"{original_contract_name}_{i + 1}"
            content = original_content.replace(
                f"contract {original_contract_name}",
                f"contract {new_contract_name}",
                1  # Solo primera ocurrencia
            )
        else:
            content = original_content

        # Escribir archivo
        output_file.write_text(content)
        generated += 1

        # Mostrar progreso
        if (i + 1) % batch_size == 0:
            print(f"   ✓ Generados: {i + 1:,}/{count:,} ({(i + 1) / count * 100:.1f}%)")

    print(f"\n✅ Completado!")
    print(f"   Total generados: {generated:,} archivos")
    print(f"   Tamaño aproximado: {(input_file.stat().st_size * generated / 1024 / 1024):.1f} MB")

    return generated


def main():
    parser = argparse.ArgumentParser(
        description="Contract Replicator - Genera múltiples copias de un contrato .sol",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:

  # Generar 10,000 copias
  python replicate_contract.py MyContract.sol --count 10000

  # Generar 100 copias sin modificar nombres
  python replicate_contract.py MyContract.sol --count 100 --no-modify

  # Usar directorio específico
  python replicate_contract.py MyContract.sol --output ./test_contracts/

  # Cambiar prefijo de archivos
  python replicate_contract.py MyContract.sol --prefix "Test"
        """
    )

    parser.add_argument(
        "input",
        help="Archivo .sol de entrada"
    )
    parser.add_argument(
        "--count",
        type=int,
        default=10000,
        help="Número de copias a generar (default: 10000)"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="./replicated_contracts/",
        help="Directorio de salida (default: ./replicated_contracts/)"
    )
    parser.add_argument(
        "--prefix",
        type=str,
        default="Contract",
        help="Prefijo para archivos generados (default: Contract)"
    )
    parser.add_argument(
        "--no-modify",
        action="store_true",
        help="No modificar nombres de contratos (copias exactas)"
    )

    args = parser.parse_args()

    # Ejecutar replicación
    input_file = Path(args.input)
    output_dir = Path(args.output)

    generated = replicate_contract(
        input_file=input_file,
        output_dir=output_dir,
        count=args.count,
        modify_name=not args.no_modify,
        prefix=args.prefix
    )

    if generated > 0:
        print(f"\n🚀 Listo para testing con SENTINEL:")
        print(f"\n   Opción 1: CLI")
        print(f"   python sentinel.py batch {output_dir} --mode quick")
        print(f"\n   Opción 2: Hardcoded (edita sentinel.py línea 23)")
        print(f"   BATCH_DIR = \"{output_dir}\"")
        print(f"   python sentinel.py")

    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())