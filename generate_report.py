#!/usr/bin/env python3
"""
SENTINEL Report Generator
Genera un reporte HTML interactivo desde batch_summary.json
"""

import json
import sys
from pathlib import Path
from datetime import datetime


def generate_html(data: dict) -> str:
    """Genera el HTML del reporte"""

    timestamp = data.get("timestamp", "")
    total_contracts = data.get("total_contracts", 0)
    total_findings = data.get("total_findings", 0)
    severity = data.get("severity_totals", {})
    timing = data.get("timing", {})
    tool_findings = data.get("tool_findings", {})
    vuln_types = data.get("vulnerability_types", [])
    critical_high = data.get("critical_high_findings", [])
    contracts = data.get("contracts", [])

    # Calcular totales de herramientas
    total_tool_findings = sum(tool_findings.values())

    html = f'''<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SENTINEL Security Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            min-height: 100vh;
            color: #e4e4e4;
            padding: 20px;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}

        header {{
            text-align: center;
            padding: 30px 0;
            border-bottom: 2px solid #e94560;
            margin-bottom: 30px;
        }}

        header h1 {{
            font-size: 3em;
            color: #e94560;
            text-shadow: 0 0 20px rgba(233, 69, 96, 0.5);
            margin-bottom: 10px;
        }}

        header .subtitle {{
            color: #888;
            font-size: 1.1em;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}

        .stat-card {{
            background: rgba(255, 255, 255, 0.05);
            border-radius: 15px;
            padding: 25px;
            text-align: center;
            border: 1px solid rgba(255, 255, 255, 0.1);
            transition: transform 0.3s, box-shadow 0.3s;
        }}

        .stat-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(233, 69, 96, 0.2);
        }}

        .stat-card .number {{
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }}

        .stat-card .label {{
            color: #888;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}

        .stat-card.critical .number {{ color: #e94560; }}
        .stat-card.high .number {{ color: #ff9f43; }}
        .stat-card.medium .number {{ color: #feca57; }}
        .stat-card.low .number {{ color: #54a0ff; }}
        .stat-card.safe .number {{ color: #26de81; }}
        .stat-card.info .number {{ color: #a55eea; }}

        .section {{
            background: rgba(255, 255, 255, 0.03);
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 30px;
            border: 1px solid rgba(255, 255, 255, 0.05);
        }}

        .section h2 {{
            color: #e94560;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 1px solid rgba(233, 69, 96, 0.3);
            display: flex;
            align-items: center;
            gap: 10px;
        }}

        .section h2 .icon {{
            font-size: 1.2em;
        }}

        .charts-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 30px;
            margin-bottom: 30px;
        }}

        .chart-container {{
            background: rgba(255, 255, 255, 0.03);
            border-radius: 15px;
            padding: 20px;
            border: 1px solid rgba(255, 255, 255, 0.05);
        }}

        .chart-container h3 {{
            color: #fff;
            margin-bottom: 15px;
            text-align: center;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }}

        th, td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }}

        th {{
            background: rgba(233, 69, 96, 0.2);
            color: #e94560;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 1px;
        }}

        tr:hover {{
            background: rgba(255, 255, 255, 0.05);
        }}

        .severity-badge {{
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }}

        .severity-critical {{ background: rgba(233, 69, 96, 0.3); color: #e94560; }}
        .severity-high {{ background: rgba(255, 159, 67, 0.3); color: #ff9f43; }}
        .severity-medium {{ background: rgba(254, 202, 87, 0.3); color: #feca57; }}
        .severity-low {{ background: rgba(84, 160, 255, 0.3); color: #54a0ff; }}
        .severity-info {{ background: rgba(165, 94, 234, 0.3); color: #a55eea; }}

        .tool-badge {{
            padding: 3px 10px;
            border-radius: 10px;
            font-size: 0.75em;
            background: rgba(255, 255, 255, 0.1);
            color: #fff;
        }}

        .tool-slither {{ background: rgba(46, 213, 115, 0.3); color: #2ed573; }}
        .tool-mythril {{ background: rgba(255, 107, 107, 0.3); color: #ff6b6b; }}
        .tool-hevm {{ background: rgba(116, 185, 255, 0.3); color: #74b9ff; }}
        .tool-echidna {{ background: rgba(162, 155, 254, 0.3); color: #a29bfe; }}

        .timing-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
        }}

        .timing-item {{
            text-align: center;
            padding: 15px;
            background: rgba(255, 255, 255, 0.03);
            border-radius: 10px;
        }}

        .timing-item .value {{
            font-size: 1.8em;
            font-weight: bold;
            color: #54a0ff;
        }}

        .timing-item .label {{
            font-size: 0.8em;
            color: #888;
            margin-top: 5px;
        }}

        .risk-bar {{
            height: 8px;
            background: #333;
            border-radius: 4px;
            overflow: hidden;
            margin-top: 5px;
        }}

        .risk-bar-fill {{
            height: 100%;
            border-radius: 4px;
            transition: width 0.3s;
        }}

        .risk-critical {{ background: linear-gradient(90deg, #e94560, #ff6b6b); }}
        .risk-high {{ background: linear-gradient(90deg, #ff9f43, #feca57); }}
        .risk-medium {{ background: linear-gradient(90deg, #feca57, #f9ca24); }}
        .risk-low {{ background: linear-gradient(90deg, #54a0ff, #74b9ff); }}
        .risk-safe {{ background: linear-gradient(90deg, #26de81, #20bf6b); }}

        .description {{
            font-size: 0.85em;
            color: #888;
            max-width: 400px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }}

        footer {{
            text-align: center;
            padding: 30px;
            color: #666;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
            margin-top: 30px;
        }}

        .filter-buttons {{
            display: flex;
            gap: 10px;
            margin-bottom: 15px;
            flex-wrap: wrap;
        }}

        .filter-btn {{
            padding: 8px 16px;
            border: none;
            border-radius: 20px;
            cursor: pointer;
            font-size: 0.85em;
            transition: all 0.3s;
            background: rgba(255, 255, 255, 0.1);
            color: #fff;
        }}

        .filter-btn:hover {{
            background: rgba(233, 69, 96, 0.3);
        }}

        .filter-btn.active {{
            background: #e94560;
        }}

        @media (max-width: 768px) {{
            header h1 {{
                font-size: 2em;
            }}

            .charts-grid {{
                grid-template-columns: 1fr;
            }}

            table {{
                font-size: 0.85em;
            }}

            th, td {{
                padding: 8px 10px;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ SENTINEL</h1>
            <p class="subtitle">Smart Contract Security Analysis Report</p>
            <p class="subtitle" style="margin-top: 10px; color: #666;">Generated: {timestamp}</p>
        </header>

        <!-- Stats Overview -->
        <div class="stats-grid">
            <div class="stat-card info">
                <div class="number">{total_contracts}</div>
                <div class="label">Contracts Analyzed</div>
            </div>
            <div class="stat-card critical">
                <div class="number">{severity.get('critical', 0)}</div>
                <div class="label">Critical</div>
            </div>
            <div class="stat-card high">
                <div class="number">{severity.get('high', 0)}</div>
                <div class="label">High</div>
            </div>
            <div class="stat-card medium">
                <div class="number">{severity.get('medium', 0)}</div>
                <div class="label">Medium</div>
            </div>
            <div class="stat-card low">
                <div class="number">{severity.get('low', 0)}</div>
                <div class="label">Low</div>
            </div>
            <div class="stat-card safe">
                <div class="number">{total_findings}</div>
                <div class="label">Total Findings</div>
            </div>
        </div>

        <!-- Timing Section -->
        <div class="section">
            <h2><span class="icon">⏱️</span> Performance Metrics</h2>
            <div class="timing-grid">
                <div class="timing-item">
                    <div class="value">{timing.get('elapsed_seconds', 0):.1f}s</div>
                    <div class="label">Total Time</div>
                </div>
                <div class="timing-item">
                    <div class="value">{timing.get('speedup', 0):.1f}x</div>
                    <div class="label">Speedup</div>
                </div>
                <div class="timing-item">
                    <div class="value">{timing.get('contracts_per_second', 0):.2f}</div>
                    <div class="label">Contracts/sec</div>
                </div>
                <div class="timing-item">
                    <div class="value">{timing.get('avg_per_contract', 0):.1f}s</div>
                    <div class="label">Avg per Contract</div>
                </div>
                <div class="timing-item">
                    <div class="value">{timing.get('sequential_minutes', 0):.1f}m</div>
                    <div class="label">Sequential Est.</div>
                </div>
            </div>
        </div>

        <!-- Charts -->
        <div class="charts-grid">
            <div class="chart-container">
                <h3>Findings by Severity</h3>
                <canvas id="severityChart"></canvas>
            </div>
            <div class="chart-container">
                <h3>Findings by Tool</h3>
                <canvas id="toolChart"></canvas>
            </div>
        </div>

        <!-- Vulnerability Types -->
        <div class="section">
            <h2><span class="icon">🐛</span> Vulnerability Types ({len(vuln_types)} unique)</h2>
            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Vulnerability</th>
                        <th>Count</th>
                        <th>Tool</th>
                    </tr>
                </thead>
                <tbody>'''

    for vuln in vuln_types[:15]:
        sev = vuln.get('severity', 'info')
        html += f'''
                    <tr>
                        <td><span class="severity-badge severity-{sev}">{sev.upper()}</span></td>
                        <td>{vuln.get('title', 'Unknown')}</td>
                        <td><strong>{vuln.get('count', 0)}</strong></td>
                        <td><span class="tool-badge tool-{vuln.get('tool', '').lower()}">{vuln.get('tool', '').capitalize()}</span></td>
                    </tr>'''

    html += '''
                </tbody>
            </table>
        </div>

        <!-- Critical/High Findings -->
        <div class="section">
            <h2><span class="icon">⚠️</span> Critical & High Severity Findings</h2>
            <div class="filter-buttons">
                <button class="filter-btn active" onclick="filterFindings('all')">All</button>
                <button class="filter-btn" onclick="filterFindings('critical')">Critical</button>
                <button class="filter-btn" onclick="filterFindings('high')">High</button>
            </div>
            <table id="findingsTable">
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Contract</th>
                        <th>Vulnerability</th>
                        <th>Tool</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>'''

    for finding in critical_high[:30]:
        sev = finding.get('severity', 'info')
        desc = finding.get('description', '')[:80] + '...' if len(finding.get('description', '')) > 80 else finding.get(
            'description', '')
        html += f'''
                    <tr data-severity="{sev}">
                        <td><span class="severity-badge severity-{sev}">{sev.upper()}</span></td>
                        <td><strong>{finding.get('contract', 'Unknown')}</strong></td>
                        <td>{finding.get('title', 'Unknown')}</td>
                        <td><span class="tool-badge tool-{finding.get('tool', '').lower()}">{finding.get('tool', '').capitalize()}</span></td>
                        <td class="description" title="{finding.get('description', '')}">{desc}</td>
                    </tr>'''

    html += '''
                </tbody>
            </table>
        </div>

        <!-- Contracts Table -->
        <div class="section">
            <h2><span class="icon">📄</span> Analyzed Contracts</h2>
            <table>
                <thead>
                    <tr>
                        <th>Contract</th>
                        <th>Risk Level</th>
                        <th>Risk Score</th>
                        <th>Findings</th>
                        <th>Time</th>
                    </tr>
                </thead>
                <tbody>'''

    for contract in contracts:
        risk = contract.get('risk_level', 'SAFE').lower()
        score = contract.get('risk_score', 0)
        max_score = 50  # Para la barra de progreso
        bar_width = min(100, (score / max_score) * 100)

        html += f'''
                    <tr>
                        <td><strong>{contract.get('name', 'Unknown')}</strong></td>
                        <td><span class="severity-badge severity-{risk}">{contract.get('risk_level', 'SAFE')}</span></td>
                        <td>
                            {score}
                            <div class="risk-bar">
                                <div class="risk-bar-fill risk-{risk}" style="width: {bar_width}%"></div>
                            </div>
                        </td>
                        <td>{contract.get('findings', 0)}</td>
                        <td>{contract.get('execution_time', 0):.1f}s</td>
                    </tr>'''

    html += f'''
                </tbody>
            </table>
        </div>

        <footer>
            <p>🛡️ SENTINEL - Smart Contract Security Analyzer</p>
            <p style="margin-top: 5px; font-size: 0.9em;">Powered by Slither, Mythril, Echidna & Hevm</p>
        </footer>
    </div>

    <script>
        // Severity Chart
        const severityCtx = document.getElementById('severityChart').getContext('2d');
        new Chart(severityCtx, {{
            type: 'doughnut',
            data: {{
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{{
                    data: [{severity.get('critical', 0)}, {severity.get('high', 0)}, {severity.get('medium', 0)}, {severity.get('low', 0)}],
                    backgroundColor: ['#e94560', '#ff9f43', '#feca57', '#54a0ff'],
                    borderWidth: 0
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{
                        position: 'bottom',
                        labels: {{ color: '#e4e4e4' }}
                    }}
                }}
            }}
        }});

        // Tool Chart
        const toolCtx = document.getElementById('toolChart').getContext('2d');
        new Chart(toolCtx, {{
            type: 'bar',
            data: {{
                labels: ['Slither', 'Mythril', 'Hevm', 'Echidna'],
                datasets: [{{
                    label: 'Findings',
                    data: [{tool_findings.get('slither', 0)}, {tool_findings.get('mythril', 0)}, {tool_findings.get('hevm', 0)}, {tool_findings.get('echidna', 0)}],
                    backgroundColor: ['#2ed573', '#ff6b6b', '#74b9ff', '#a29bfe'],
                    borderRadius: 5
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{ display: false }}
                }},
                scales: {{
                    y: {{
                        beginAtZero: true,
                        ticks: {{ color: '#888' }},
                        grid: {{ color: 'rgba(255,255,255,0.1)' }}
                    }},
                    x: {{
                        ticks: {{ color: '#888' }},
                        grid: {{ display: false }}
                    }}
                }}
            }}
        }});

        // Filter function
        function filterFindings(severity) {{
            const rows = document.querySelectorAll('#findingsTable tbody tr');
            const buttons = document.querySelectorAll('.filter-btn');

            buttons.forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');

            rows.forEach(row => {{
                if (severity === 'all' || row.dataset.severity === severity) {{
                    row.style.display = '';
                }} else {{
                    row.style.display = 'none';
                }}
            }});
        }}
    </script>
</body>
</html>'''

    return html


def main():
    # Buscar el archivo JSON
    if len(sys.argv) > 1:
        json_path = Path(sys.argv[1])
    else:
        # Buscar en ubicaciones comunes
        possible_paths = [
            Path("reports/batch_summary.json"),
            Path("batch_summary.json"),
            Path.cwd() / "reports" / "batch_summary.json"
        ]
        json_path = None
        for p in possible_paths:
            if p.exists():
                json_path = p
                break

        if not json_path:
            print("❌ No se encontró batch_summary.json")
            print("   Uso: python generate_report.py <path_to_batch_summary.json>")
            sys.exit(1)

    if not json_path.exists():
        print(f"❌ Archivo no encontrado: {json_path}")
        sys.exit(1)

    print(f"📄 Leyendo: {json_path}")

    with open(json_path, 'r') as f:
        data = json.load(f)

    print(f"📊 Procesando {data.get('total_contracts', 0)} contratos, {data.get('total_findings', 0)} findings...")

    html = generate_html(data)

    output_path = json_path.parent / "sentinel_report.html"
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)

    print(f"✅ Reporte generado: {output_path}")
    print(f"   Abrilo en el navegador para ver el dashboard interactivo")


if __name__ == "__main__":
    main()