#!/usr/bin/env python3
"""
SENTINEL CLI - Análisis Batch Paralelo

Configurar abajo y ejecutar:
    python sentinel.py
"""

import asyncio
import json
import sys
from pathlib import Path
from datetime import datetime

# ═══════════════════════════════════════════════════════════════════════════
# CONFIGURACIÓN - MODIFICAR AQUÍ
# ═══════════════════════════════════════════════════════════════════════════

CONTRACTS_DIR = "/home/walter/contracts/contractos_vulnerables"  # Directorio con archivos .sol
WORKERS = 8  # Contratos en paralelo
MODE = "normal"  # quick | normal | deep
RECURSIVE = False  # Buscar en subdirectorios
PATTERN = "*.sol"  # Patrón de archivos


# ═══════════════════════════════════════════════════════════════════════════


def print_banner():
    print("""
███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     
██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     
███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     
╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     
███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
                Smart Contract Security Analyzer - Distributed
    """)


def print_batch_summary(reports, output_dir: Path, elapsed_time: float):
    """Imprime y guarda resumen de batch"""

    total_findings = sum(len(r.all_findings) for r in reports)
    severity_totals = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    sequential_time = sum(r.summary.get("execution_time", 0) for r in reports)

    for r in reports:
        for sev, count in r.summary.get("severity_breakdown", {}).items():
            severity_totals[sev] += count

    # Cálculos de tiempo
    contracts_per_sec = len(reports) / elapsed_time if elapsed_time > 0 else 0
    avg_time = elapsed_time / len(reports) if reports else 0
    speedup = sequential_time / elapsed_time if elapsed_time > 0 else 1

    print(f"\n{'=' * 70}")
    print(f"{'RESUMEN BATCH':^70}")
    print(f"{f'{len(reports)} CONTRATOS ANALIZADOS EN PARALELO':^70}")
    print(f"{'=' * 70}")

    print(f"\n⏱️  TIEMPOS:")
    print(f"  Tiempo total:      {elapsed_time:>10.1f}s ({elapsed_time / 60:.1f} min)")
    print(f"  Tiempo secuencial: {sequential_time:>10.1f}s ({sequential_time / 60:.1f} min)")
    print(f"  Speedup:           {speedup:>10.1f}x")
    print(f"  Promedio/contrato: {avg_time:>10.1f}s")
    print(f"  Contratos/segundo: {contracts_per_sec:>10.2f}")

    print(f"\n📊 FINDINGS:")
    print(f"  Total Findings: {total_findings}")
    print(f"  🔴 Critical: {severity_totals['critical']}")
    print(f"  🟠 High: {severity_totals['high']}")
    print(f"  🟡 Medium: {severity_totals['medium']}")
    print(f"  🔵 Low: {severity_totals['low']}")

    # Findings por herramienta (extraer de los reportes)
    tool_findings = {"slither": 0, "echidna": 0, "mythril": 0, "hevm": 0}
    all_vulns = []  # Todas las vulnerabilidades
    vuln_types = {}  # Conteo por tipo

    for r in reports:
        for f in r.all_findings:
            tool = f.tool.lower() if hasattr(f, 'tool') else ""
            if tool in tool_findings:
                tool_findings[tool] += 1

            # Recopilar info de vuln
            title = f.title if hasattr(f, 'title') else "Unknown"
            sev = f.severity.value if hasattr(f, 'severity') else "info"
            all_vulns.append({
                "contract": r.contract_name,
                "title": title,
                "severity": sev,
                "tool": tool,
                "description": f.description[:80] if hasattr(f, 'description') else ""
            })

            # Contar tipos
            if title not in vuln_types:
                vuln_types[title] = {"count": 0, "severity": sev, "tool": tool}
            vuln_types[title]["count"] += 1

    print(f"\n🔧 FINDINGS POR HERRAMIENTA:")
    print("┌" + "─" * 40 + "┐")
    print(f"│ {'Herramienta':<15} │ {'Findings':>10} │ {'%':>8} │")
    print("├" + "─" * 40 + "┤")
    for tool, count in tool_findings.items():
        pct = (count / total_findings * 100) if total_findings > 0 else 0
        print(f"│ {tool.capitalize():<15} │ {count:>10} │ {pct:>7.1f}% │")
    print("└" + "─" * 40 + "┘")

    # Tipos de vulnerabilidades
    if vuln_types:
        print(f"\n🐛 TIPOS DE VULNERABILIDADES ({len(vuln_types)} tipos únicos):")
        print("┌" + "─" * 80 + "┐")
        print(f"│ {'Sev':<8} │ {'Vulnerabilidad':<40} │ {'#':>5} │ {'Tool':<12} │")
        print("├" + "─" * 80 + "┤")

        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_vulns = sorted(vuln_types.items(), key=lambda x: (sev_order.get(x[1]["severity"], 5), -x[1]["count"]))

        for title, data in sorted_vulns[:15]:
            sev = data["severity"].upper()[:8]
            tool = data["tool"].capitalize()[:12]
            print(f"│ {sev:<8} │ {title[:40]:<40} │ {data['count']:>5} │ {tool:<12} │")

        if len(sorted_vulns) > 15:
            print(f"│ {'...':<8} │ {'... +' + str(len(sorted_vulns) - 15) + ' tipos más':<40} │ {'':>5} │ {'':>12} │")
        print("└" + "─" * 80 + "┘")

    # Detalle de vulnerabilidades críticas y high
    critical_high = [v for v in all_vulns if v["severity"] in ["critical", "high"]]
    if critical_high:
        print(f"\n⚠️  VULNERABILIDADES CRÍTICAS Y HIGH ({len(critical_high)}):")
        print("┌" + "─" * 95 + "┐")
        print(f"│ {'Sev':<8} │ {'Contrato':<20} │ {'Vulnerabilidad':<35} │ {'Tool':<10} │")
        print("├" + "─" * 95 + "┤")

        for v in critical_high[:20]:
            sev = v["severity"].upper()[:8]
            contract = v["contract"][:20]
            title = v["title"][:35]
            tool = v["tool"].capitalize()[:10]
            print(f"│ {sev:<8} │ {contract:<20} │ {title:<35} │ {tool:<10} │")

        if len(critical_high) > 20:
            print(f"│ {'...':<8} │ {'... +' + str(len(critical_high) - 20) + ' más':<20} │ {'':>35} │ {'':>10} │")
        print("└" + "─" * 95 + "┘")

    sorted_reports = sorted(reports, key=lambda r: r.summary.get("risk_score", 0), reverse=True)

    print(f"\nCONTRATOS POR RIESGO:")
    print("┌" + "─" * 68 + "┐")
    for r in sorted_reports:
        s = r.summary
        risk = s.get("risk_level", "N/A")
        score = s.get("risk_score", 0)
        findings = s.get("total_findings", 0)
        name = (r.contract_name or r.address)[:25]
        time_s = s.get("execution_time", 0)
        print(f"│ {risk:8} │ Score: {score:3} │ {findings:3} findings │ {time_s:5.1f}s │ {name:25} │")
    print("└" + "─" * 68 + "┘")

    batch_data = {
        "timestamp": datetime.now().isoformat(),
        "total_contracts": len(reports),
        "total_findings": total_findings,
        "severity_totals": severity_totals,
        "timing": {
            "elapsed_seconds": round(elapsed_time, 2),
            "elapsed_minutes": round(elapsed_time / 60, 2),
            "sequential_seconds": round(sequential_time, 2),
            "sequential_minutes": round(sequential_time / 60, 2),
            "speedup": round(speedup, 2),
            "avg_per_contract": round(avg_time, 2),
            "contracts_per_second": round(contracts_per_sec, 3)
        },
        "tool_findings": tool_findings,
        "vulnerability_types": [
            {
                "title": title,
                "count": data["count"],
                "severity": data["severity"],
                "tool": data["tool"]
            }
            for title, data in sorted(vuln_types.items(), key=lambda x: -x[1]["count"])
        ],
        "critical_high_findings": [
            {
                "contract": v["contract"],
                "title": v["title"],
                "severity": v["severity"],
                "tool": v["tool"],
                "description": v["description"]
            }
            for v in critical_high[:50]  # Top 50
        ],
        "contracts": [
            {
                "name": r.contract_name,
                "address": r.address,
                "risk_level": r.summary.get("risk_level"),
                "risk_score": r.summary.get("risk_score"),
                "findings": r.summary.get("total_findings"),
                "execution_time": r.summary.get("execution_time")
            }
            for r in sorted_reports
        ]
    }

    summary_path = output_dir / "batch_summary.json"
    with open(summary_path, 'w') as f:
        json.dump(batch_data, f, indent=2)

    print(f"\n📊 Resumen: {summary_path}")
    print("=" * 70)


async def main():
    print_banner()

    from src.engine import SentinelEngine
    import time

    batch_dir = Path(CONTRACTS_DIR)
    if not batch_dir.exists():
        print(f"❌ Directorio no encontrado: {batch_dir}")
        return 1

    config_path = Path("config/tools.yaml") if Path("config/tools.yaml").exists() else None
    engine = SentinelEngine(config_path=config_path, num_workers=WORKERS)

    start_time = time.time()

    reports = await engine.analyze_batch(
        batch_dir=batch_dir,
        mode=MODE,
        recursive=RECURSIVE,
        pattern=PATTERN,
        parallel=WORKERS
    )

    elapsed_time = time.time() - start_time

    if reports:
        print_batch_summary(reports, engine.reports_dir, elapsed_time)

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))