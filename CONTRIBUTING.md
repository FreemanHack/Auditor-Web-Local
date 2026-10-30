# Cómo contribuir

Gracias por tu interés en mejorar el Auditor de Seguridad Web Local. Esta guía explica qué tipo de aportes encajan en el proyecto y qué se espera de cada uno.

## Antes de empezar

- **Vulnerabilidades de la herramienta:** no abras un issue público; sigue el procedimiento de [SECURITY.md](SECURITY.md).
- **Errores y propuestas:** abre un issue describiendo el problema o la idea antes de escribir código. Así se puede acordar el enfoque y evitar trabajo que luego no se incorpore.

## Proponer una verificación nueva

Una verificación nueva debe cumplir estas condiciones:

1. **Estar dentro del alcance:** debilidades de la superficie de ataque web del propio equipo. Los análisis de hosts remotos quedan fuera.
2. **Estar respaldada por una fuente técnica reconocida:** RFC, CVE, CWE, OWASP, MITRE ATT&CK, CIS o documentación oficial del fabricante. La referencia se cita en un comentario junto al código.
3. **Justificar el nivel de riesgo** según los criterios de [Clasificación del riesgo](README.md#clasificación-del-riesgo).
4. **Evitar falsos positivos:** confirmar el hallazgo con más de una señal cuando sea posible (por ejemplo, validar el contenido de una respuesta y no solo su código de estado).
5. **Ser de solo lectura:** la verificación no debe modificar el equipo. Los cambios pertenecen a la remediación.

## Proponer una remediación

- Debe poder revertirse. Si modifica el registro, la clave tiene que estar incluida en el respaldo (`New-Respaldo`), y el procedimiento de reversión debe documentarse en el README.
- Debe ser idempotente: aplicarla dos veces no debe producir errores ni efectos adicionales.
- Debe indicar si requiere privilegios de administrador (`RequiereAdmin`).
- Antes de enviarla, ejecútala en la prueba de Windows Sandbox (`pruebas\Iniciar-PruebaSandbox.ps1`) y, si corresponde, amplía `Probar-Remediaciones.ps1` para cubrirla.

## Estilo de código

- Compatible con Windows PowerShell 5.1: sin operadores ternarios, `??` ni `?.`.
- Archivos `.ps1` en UTF-8 **con BOM**; sin él, PowerShell 5.1 interpreta mal las tildes.
- Funciones con verbos aprobados de PowerShell (`Get-Verb`) y ayuda integrada (`.SYNOPSIS` como mínimo).
- Comentarios que expliquen el porqué, no lo que el código ya dice.
- Todo dato que proceda del equipo auditado debe pasar por `Esc` antes de escribirse en el informe HTML.

## Estilo de redacción

Los textos que ve el usuario (hallazgos, recomendaciones, documentación) se escriben en español, con un registro técnico pero natural:

- Usar la terminología habitual del sector (*commit*, *downgrade*, *MIME sniffing*) en lugar de traducciones forzadas.
- Evitar tanto el tono coloquial como la rigidez burocrática («con capacidad de», «constituye»).
- Explicar la consecuencia concreta de cada hallazgo, no solo su nombre.

## Antes de enviar un pull request

- [ ] El script no tiene errores de sintaxis y se ejecuta con `-SoloEscaneo` sin fallos.
- [ ] La prueba de Windows Sandbox termina con todas las remediaciones correctas y la reversión completa.
- [ ] El README y el CHANGELOG reflejan el cambio.
- [ ] No se incluyen informes, respaldos ni otros datos de un equipo real.
