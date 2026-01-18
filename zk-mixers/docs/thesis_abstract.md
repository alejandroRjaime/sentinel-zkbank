# Abstract - Tesis de Investigación

## Diseño e Implementación de un Sistema Bancario Privado usando ZK-SNARKs

### Resumen
Esta investigación presenta el diseño, implementación y evaluación de un sistema bancario descentralizado que garantiza privacidad mediante el uso de Zero-Knowledge Succinct Non-Interactive Arguments of Knowledge (ZK-SNARKs). El sistema permite operaciones de depósito y retiro anónimas mientras mantiene la solvencia y previene el doble gasto.

### Contribuciones Principales
1. **Diseño de circuitos optimizados**: Circuitos Circom especializados para operaciones bancarias con balance entre seguridad y eficiencia.
2. **Arquitectura modular**: Sistema compuesto por componentes reutilizables y verificables.
3. **Análisis de seguridad formal**: Verificación de propiedades críticas como prevención de doble gasto y consistencia del estado.
4. **Benchmark exhaustivo**: Evaluación de performance comparada con soluciones existentes.

### Metodología
- Uso del lenguaje de dominio específico Circom 2.1.5
- Implementación de Sparse Merkle Trees para gestión eficiente del estado
- Protocolos Groth16 y PLONK para generación y verificación de pruebas
- Testing exhaustivo con casos límite

### Resultados Esperados
- Circuitos con menos de 1M constraints
- Tiempos de verificación sub-segundo
- Pruebas de menos de 5KB
- Costo en gas competitivo para implementación en Ethereum

### Implicaciones
Este trabajo contribuye al campo de las finanzas descentralizadas privadas, proporcionando un marco para aplicaciones que requieren privacidad por diseño sin sacrificar la transparencia auditiva.