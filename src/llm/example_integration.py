"""
Ejemplo de integración de nuevos agentes con SENTINEL

Este ejemplo muestra cómo integrar los 3 nuevos agentes en el pipeline existente.
"""

import asyncio
from typing import List, Dict, Any

from src.llm import CorrelatorAgent, AttackChainAgent, ExploitValidatorAgent
# Imports existentes de SENTINEL
from src.llm.base import create_llm_client
from src.llm.agents import LLMPipeline, TriageAgent, AnalysisAgent, PoCAgent
from src.analyzers.base import Finding, Severity



async def enhanced_analysis_pipeline(
    findings: List[Finding],
    source_code: str,
    address: str = "",
    contract_name: str = "Unknown"
) -> Dict[str, Any]:
    """
    Pipeline mejorado que integra:
    1. Análisis tradicional de SENTINEL
    2. Correlación de findings
    3. Detección de attack chains
    4. Validación de exploits
    """
    
    # Configurar LLM (GPT-4o)
    llm_config = {
        "provider": "openai",
        "model": "gpt-4o",
        "timeout": 180
    }
    
    client = create_llm_client(llm_config)
    
    print("\n" + "="*60)
    print("🛡️  SENTINEL - Enhanced Analysis Pipeline")
    print("="*60)
    print(f"Contract: {contract_name}")
    print(f"Address: {address}")
    print(f"Initial findings: {len(findings)}")
    
    # ========================================================================
    # FASE 1: CORRELACIÓN
    # ========================================================================
    print("\n" + "="*60)
    print("FASE 1: CORRELACIÓN DE FINDINGS")
    print("="*60)
    
    correlator = CorrelatorAgent(client)
    correlation_result = await correlator.correlate(findings, source_code)
    
    correlated_findings = correlator.get_consolidated_findings(
        correlation_result.correlated_findings,
        min_confidence=0.6
    )
    
    print(f"\n📊 Resultados de Correlación:")
    print(f"  • Findings originales: {correlation_result.original_count}")
    print(f"  • Duplicados eliminados: {correlation_result.duplicates_removed}")
    print(f"  • Confidence mejorado: {correlation_result.confidence_increased}")
    print(f"  • Findings consolidados: {len(correlated_findings)}")
    
    # ========================================================================
    # FASE 2: DETECCIÓN DE ATTACK CHAINS
    # ========================================================================
    print("\n" + "="*60)
    print("FASE 2: DETECCIÓN DE ATTACK CHAINS")
    print("="*60)
    
    chain_detector = AttackChainAgent(client)
    chain_result = await chain_detector.detect_chains(
        correlated_findings,
        source_code
    )
    
    print(f"\n⚔️  Resultados de Attack Chains:")
    print(f"  • Chains detectados: {len(chain_result.chains_found)}")
    print(f"  • Risk Score: {chain_result.risk_score:.1f}/10.0")
    
    if chain_result.chains_found:
        print(f"\n  ⚠️  CRITICAL ATTACK CHAINS:")
        for chain in chain_result.chains_found:
            print(f"    🔗 {chain.name} ({chain.chain_type.value})")
            print(f"       Severity: {chain.severity.value}")
            print(f"       Components: {len(chain.components)} vulnerabilities")
            print(f"       Exploitability: {chain.exploitability}")
            print(f"       Priority: {chain.mitigation_priority}")
    
    # Usar findings mejorados con info de chains
    enhanced_findings = chain_result.enhanced_findings
    
    # ========================================================================
    # FASE 3: PIPELINE TRADICIONAL (TRIAGE + ANALYSIS + POC)
    # ========================================================================
    print("\n" + "="*60)
    print("FASE 3: ANÁLISIS PROFUNDO Y GENERACIÓN DE POCS")
    print("="*60)
    
    # Usar el LLMPipeline existente
    pipeline = LLMPipeline({"enabled": True, **llm_config})
    
    pipeline_result = await pipeline.process(
        findings=enhanced_findings,
        source_code=source_code,
        address=address,
        contract_name=contract_name,
        generate_pocs=True,
        generate_remediations=True
    )
    
    # ========================================================================
    # FASE 4: VALIDACIÓN DE EXPLOITS
    # ========================================================================
    print("\n" + "="*60)
    print("FASE 4: VALIDACIÓN DE EXPLOITS")
    print("="*60)
    
    validator = ExploitValidatorAgent(
        client,
        rpc_url="https://eth.llamarpc.com"
    )
    
    # Validar solo PoCs generados para findings críticos
    exploits_to_validate = [
        (poc.finding, poc.poc_code)
        for poc in pipeline_result["pocs"]
        if poc.finding.severity in [Severity.CRITICAL, Severity.HIGH]
    ]
    
    if exploits_to_validate:
        print(f"\n🧪 Validando {len(exploits_to_validate)} exploits...")
        
        validation_results = await validator.validate_batch(
            exploits_to_validate,
            concurrency=1  # Serial para no sobrecargar
        )
        
        metrics = validator.generate_metrics(validation_results)
        
        print(f"\n📊 Métricas de Validación:")
        print(f"  • Total testeados: {metrics.total_tested}")
        print(f"  • Exploits exitosos: {metrics.successful_exploits}")
        print(f"  • Exploits fallidos: {metrics.failed_exploits}")
        print(f"  • Errores de compilación: {metrics.compilation_errors}")
        print(f"  • Errores de ejecución: {metrics.execution_errors}")
        print(f"  • Severidad confirmada: {metrics.estimated_severity_confirmed}")
        
        if metrics.total_gas_used > 0:
            print(f"  • Gas total usado: {metrics.total_gas_used:,}")
    else:
        validation_results = []
        metrics = None
        print(f"\n  ℹ️  No hay exploits críticos para validar")
    
    # ========================================================================
    # RESULTADO FINAL CONSOLIDADO
    # ========================================================================
    print("\n" + "="*60)
    print("RESUMEN FINAL")
    print("="*60)
    
    final_result = {
        # Correlación
        "correlation": {
            "original_count": correlation_result.original_count,
            "duplicates_removed": correlation_result.duplicates_removed,
            "confidence_increased": correlation_result.confidence_increased,
            "correlated_findings": correlation_result.correlated_findings
        },
        
        # Attack Chains
        "attack_chains": {
            "chains_found": chain_result.chains_found,
            "risk_score": chain_result.risk_score,
            "high_priority_chains": chain_detector.get_high_priority_chains(
                chain_result.chains_found
            )
        },
        
        # Pipeline tradicional
        "analysis": {
            "triage_results": pipeline_result["triage_results"],
            "filtered_findings": pipeline_result["filtered_findings"],
            "analyses": pipeline_result["analyses"],
            "pocs": pipeline_result["pocs"],
            "remediations": pipeline_result["remediations"],
            "summary": pipeline_result["summary"]
        },
        
        # Validación
        "validation": {
            "results": validation_results,
            "metrics": metrics
        }
    }
    
    # Estadísticas finales
    print(f"\n✅ Análisis Completo:")
    print(f"  • Findings finales: {len(pipeline_result['filtered_findings'])}")
    print(f"  • Attack chains: {len(chain_result.chains_found)}")
    print(f"  • PoCs generados: {len(pipeline_result['pocs'])}")
    print(f"  • PoCs validados: {len(validation_results)}")
    print(f"  • Security Score: {pipeline_result['summary'].get('security_score', 'N/A')}")
    print(f"  • Risk Score: {chain_result.risk_score:.1f}/10.0")
    
    return final_result


async def main():
    """Ejemplo de uso"""
    
    # Ejemplo con findings simulados
    example_findings = [
        Finding(
            tool="slither",
            severity=Severity.HIGH,
            title="Reentrancy in withdraw()",
            description="Function withdraw() makes external call before updating balance",
            location="VulnerableContract.sol:45",
            function="withdraw",
            contract="VulnerableContract"
        ),
        Finding(
            tool="mythril",
            severity=Severity.HIGH,
            title="SWC-107: Reentrancy",
            description="External call in withdraw() line 47",
            location="VulnerableContract.sol:45",
            function="withdraw",
            contract="VulnerableContract"
        ),
        Finding(
            tool="slither",
            severity=Severity.MEDIUM,
            title="Unchecked return value",
            description="Return value of call not checked",
            location="VulnerableContract.sol:50",
            function="withdraw",
            contract="VulnerableContract"
        )
    ]
    
    example_code = """
    contract VulnerableContract {
        mapping(address => uint256) public balances;
        
        function withdraw() public {
            uint256 amount = balances[msg.sender];
            (bool success, ) = msg.sender.call{value: amount}("");
            balances[msg.sender] = 0;
        }
    }
    """
    
    result = await enhanced_analysis_pipeline(
        findings=example_findings,
        source_code=example_code,
        address="0x1234...",
        contract_name="VulnerableContract"
    )
    
    return result


if __name__ == "__main__":
    asyncio.run(main())
