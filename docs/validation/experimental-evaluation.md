# Evaluación experimental de VulnHunter

El objetivo no es afirmar que VulnHunter encuentra todo, sino medir qué detecta,
con qué evidencia y cuántas alertas incorrectas genera.

## Entorno controlado

Usar OWASP Juice Shop, WebGoat o bWAPP únicamente en una red Docker local y
aislada. No ejecutar la comparación contra sitios públicos. Registrar versiones
del laboratorio, VulnHunter y OWASP ZAP, además de CPU, memoria y límites.

## Diseño

1. Preparar vulnerabilidades conocidas (*ground truth*) y separar las que están
   dentro del alcance real de los scanners actuales.
2. Dar a VulnHunter y ZAP el mismo origen, tiempo, autenticación, URLs y alcance.
3. Ejecutar al menos tres repeticiones limpias por herramienta.
4. Revisar cada alerta como verdadero positivo (TP), falso positivo (FP) o
   hallazgo no detectado (FN).
5. Conservar evidencia sin contraseñas, cookies ni datos personales.

## Métricas

- Precisión: `TP / (TP + FP)`.
- Cobertura: `TP / (TP + FN)`.
- F1: media armónica entre precisión y cobertura.
- Tiempo, solicitudes, severidad y confianza.
- Porcentaje reproducible en las tres ejecuciones.

No se cuenta como falso negativo una vulnerabilidad que VulnHunter no afirma
cubrir. La comparación con ZAP es una línea base, no una competencia. Para el
proyecto de título conviene priorizar pocos detectores con evidencia sólida y
explicar con transparencia falsos positivos, falsos negativos y limitaciones.

Registrar los resultados en `docs/validation/results-template.csv` y anexar
capturas del laboratorio, versiones, configuración y reportes.
