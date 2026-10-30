# Política de seguridad

## Versiones con soporte

| Versión | Soporte |
|---|---|
| 1.0.x | Sí |

## Cómo informar una vulnerabilidad

Si encuentras una vulnerabilidad en la propia herramienta, **no abras un issue público**. Infórmala de forma privada desde la pestaña **Security** del repositorio, con la opción **Report a vulnerability**.

Para que el análisis sea ágil, incluye:

- la versión del script y del sistema operativo;
- una descripción del problema y su impacto;
- los pasos para reproducirlo o una prueba de concepto;
- si es posible, una propuesta de corrección.

## Qué esperar

- Acuse de recibo en un plazo de 7 días.
- Evaluación del alcance y, si se confirma, una corrección publicada como nueva versión.
- Mención en las notas de la versión, salvo que prefieras mantenerte en el anonimato.

Se pide no divulgar públicamente el problema hasta que exista una versión corregida.

## Alcance

**Dentro del alcance:**

- Inyección de código en el informe HTML a partir de datos del equipo auditado (cabeceras HTTP, entradas del archivo `hosts`, nombres de procesos).
- Ejecución de código no prevista durante la remediación.
- Remediaciones que debiliten la seguridad del equipo o que no puedan revertirse con el procedimiento documentado.
- Exposición de datos del equipo fuera de los archivos de salida locales.
- Falsos negativos que oculten una vulnerabilidad grave que la herramienta declara verificar.

**Fuera del alcance:**

- Los hallazgos sobre el equipo auditado: detectarlos es precisamente la función de la herramienta.
- El uso de `-ExecutionPolicy Bypass`, que es una decisión de quien ejecuta el script.
- Vulnerabilidades en Windows, PowerShell o software de terceros, que deben informarse a su fabricante.
