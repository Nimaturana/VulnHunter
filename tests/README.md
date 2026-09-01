# Estrategia de pruebas

- `unit/`: reglas de dominio sin red ni base de datos.

Por ahora solo existe esta categoría porque es la única que contiene pruebas
reales. Las pruebas de integración, contrato, seguridad y extremo a extremo se
agregarán cuando esas capacidades sean implementadas.

Los scanners activos deben usar exclusivamente aplicaciones de laboratorio
controladas. Nunca se ejecutan contra objetivos públicos en CI.
