# Arquitectura

Este documento describe la estructura interna de `AuditorWebLocal.ps1`. Está pensado para quien quiera revisar el código, entender una decisión concreta o agregar una verificación nueva. Para el funcionamiento general, consulta la sección [Cómo funciona](../README.md#cómo-funciona) del README.

Cada función del script tiene ayuda integrada en el formato estándar de PowerShell (`.SYNOPSIS`, `.DESCRIPTION`, `.NOTES`), con el detalle de su comportamiento y las referencias técnicas que lo justifican.

## Organización del archivo

El script es un único archivo dividido en seis bloques, en este orden:

| Bloque | Contenido |
|---|---|
| Parámetros y ayuda | Bloque de ayuda general y parámetros (`-SoloEscaneo`, `-SinConexion`, `-RutaInforme`, `-NoAbrir`). |
| Estado global y utilidades | Variables compartidas, tablas de configuración y funciones auxiliares. |
| Verificaciones | Una función por área auditada. |
| Resultados | Cálculo del riesgo, resumen en consola y generación del informe. |
| Corrección asistida | Respaldo y menú de remediación. |
| Programa principal | Llamadas a las verificaciones en orden y flujo final. |

## Estado global

| Variable | Contenido |
|---|---|
| `$script:Hallazgos` | Lista de todos los hallazgos registrados, vulnerables o no. |
| `$script:ServiciosWeb` | Servicios web detectados por `Test-PuertosWeb`, que después analiza `Test-ServidoresWeb`. |
| `$script:Niveles`, `$script:Orden`, `$script:Peso` | Niveles de riesgo, su orden de presentación y su peso en la puntuación. |
| `$script:PuertosWeb`, `$script:PuertosDatos` | Puertos considerados servicios web y bases de datos. |
| `$script:RutasSensibles` | Rutas que se solicitan a cada servidor web, con el patrón que confirma el hallazgo, su riesgo y su referencia CWE u OWASP. |
| `$script:EsAdmin`, `$script:TieneWinget` | Capacidades de la sesión, que determinan qué se puede verificar y remediar. |

## Modelo de hallazgo

Todas las verificaciones registran sus resultados con `Add-Hallazgo`, que crea un objeto con esta estructura:

| Campo | Tipo | Descripción |
|---|---|---|
| `Id` | Entero | Número correlativo, usado para elegir remediaciones en la consola. |
| `Categoria` | Texto | Área del hallazgo (Sistema, Red, Cifrado, Servidores web…). |
| `Titulo` | Texto | Descripción breve que se muestra en la consola y en el informe. |
| `Riesgo` | Texto | `Crítico`, `Alto`, `Medio`, `Bajo` o `Info`. |
| `Vulnerable` | Booleano | `$false` para los controles superados. |
| `Detalle` | Texto | Explicación técnica y consecuencia concreta. |
| `Recomendacion` | Texto | Cómo resolverlo. |
| `Correccion` | Texto | Código PowerShell de la remediación. Vacío si la corrección es manual. |
| `RequiereAdmin` | Booleano | Si la remediación necesita permisos de administrador. |
| `Estado` | Texto | `Pendiente`, `OK`, `Corregido`, `Omitido…` o `Error: …`. |

La remediación se guarda como texto y no como bloque de código, para que se pueda mostrar sin cambios en la consola, en el informe y en el JSON. Lo que se ve es exactamente lo que se ejecuta.

## Funciones

### Utilidades

| Función | Responsabilidad |
|---|---|
| `Write-Paso` | Muestra en consola la verificación en curso. |
| `Add-Hallazgo` | Registra un hallazgo y normaliza los controles superados a riesgo `Info` y estado `OK`. |
| `Add-Correcto` | Atajo para registrar un control superado. |
| `Get-RiesgoReducido` | Devuelve el nivel inmediatamente inferior; se aplica a servicios que solo escuchan en loopback. |
| `ConvertTo-Version` | Convierte cadenas de versión en objetos comparables, descartando sufijos. |
| `Invoke-Sonda` | Envía una petición HTTP sin seguir redirecciones ni usar proxy, y devuelve código, cabeceras y hasta 64 KB del cuerpo. |

### Verificaciones

| Función | Área | Fuente de datos |
|---|---|---|
| `Test-SistemaOperativo` | Soporte de Windows y actualizaciones | `Win32_OperatingSystem`, `Get-HotFix` |
| `Test-Firewall` | Perfiles del firewall | `Get-NetFirewallProfile` |
| `Test-Antivirus` | Defender y antivirus de terceros | `Get-MpComputerStatus`, `root/SecurityCenter2` |
| `Test-PuertosWeb` | Puertos en escucha y exposición a la red | `Get-NetTCPConnection` |
| `Test-ServidoresWeb` | Recorre los servicios web detectados | `$script:ServiciosWeb` |
| `Test-ServidorWeb` | Cabeceras, CORS, cookies, listado y archivos sensibles de un servidor | `Invoke-Sonda` |
| `Test-ProtocolosTLS` | SChannel y criptografía de .NET | Registro (`SCHANNEL`, `.NETFramework`) |
| `Test-ResolucionNombres` | LLMNR y NetBIOS | Registro (`DNSClient`), `Win32_NetworkAdapterConfiguration` |
| `Get-UltimasVersiones` | Última versión estable de cada navegador | API de Google, Mozilla y Microsoft |
| `Test-Navegadores` | Versión instalada frente a la publicada | Archivos ejecutables, `Get-UltimasVersiones` |
| `Test-SoftwareObsoleto` | Programas sin soporte, Internet Explorer 11 y XAMPP | Registro (`Uninstall`), `Get-WindowsOptionalFeature` |
| `Test-ArchivoHosts` | Redirecciones y bloqueos | `%SystemRoot%\System32\drivers\etc\hosts` |
| `Test-Proxy` | Proxy manual y script PAC | Registro (`Internet Settings`) |

Las verificaciones son independientes entre sí, con una excepción: `Test-ServidoresWeb` usa los servicios que detectó antes `Test-PuertosWeb`, así que ese orden debe mantenerse.

### Resultados

| Función | Responsabilidad |
|---|---|
| `Get-Activos` | Devuelve los hallazgos pendientes ordenados por severidad. |
| `Get-NivelGlobal` | Devuelve la severidad más alta entre los pendientes. |
| `Show-Resumen` | Muestra en consola el recuento por nivel y la lista de hallazgos. |
| `Esc` | Codifica texto para insertarlo en HTML de forma segura. |
| `Get-ClaseRiesgo` | Traduce un nivel de riesgo a su clase CSS. |
| `Export-Informe` | Genera el HTML autocontenido y el JSON. |
| `Format-HallazgoHtml` | Genera el bloque desplegable de un hallazgo. |

### Remediación

| Función | Responsabilidad |
|---|---|
| `New-Respaldo` | Exporta las claves de registro y la política de firewall que pueden modificarse. |
| `Invoke-MenuCorreccion` | Lista las remediaciones, gestiona la elevación, pide confirmación, ejecuta y registra. |

## Agregar una verificación

1. **Crear la función** `Test-<Área>` en el bloque de verificaciones, con su ayuda integrada (`.SYNOPSIS` y, si corresponde, `.DESCRIPTION` y `.NOTES` con la referencia técnica).
2. **Leer sin modificar.** La función solo consulta el estado del equipo.
3. **Registrar el resultado** con `Add-Hallazgo` si hay un problema, o con `Add-Correcto` si el control se supera. Si la consulta falla, registrar un hallazgo de nivel `Info` y continuar.
4. **Definir la remediación**, si existe, en el campo `Correccion`. Debe ser idempotente y reversible, y su clave de registro debe estar incluida en `New-Respaldo`.
5. **Llamar a la función** desde el programa principal.
6. **Documentarla** en la tabla de verificaciones del README y, si tiene remediación, en la sección de reversión.
7. **Probarla** con la prueba de Windows Sandbox y, si corresponde, ampliar `pruebas\Probar-Remediaciones.ps1` para que introduzca la configuración insegura y valide su corrección.

Los criterios completos para aceptar una verificación están en [CONTRIBUTING.md](../CONTRIBUTING.md).
