# Registro de cambios

El formato sigue [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y el proyecto utiliza [versionado semántico](https://semver.org/lang/es/).

## [1.0.0] - 2026-10-30

### Añadido

- Verificaciones del sistema: soporte de Windows, antigüedad de actualizaciones, Microsoft Defender y firewall.
- Detección de servicios web y bases de datos en escucha, con evaluación de exposición fuera de loopback.
- Sondas HTTP/HTTPS sobre servidores locales: cabeceras de seguridad, CORS, cookies, listado de directorios y recursos sensibles. Cada servidor se analiza en la dirección del propio equipo donde escucha (IPv4, IPv6 o IP de red).
- Auditoría de SChannel (SSL 3.0, TLS 1.0, 1.1 y 1.2) y de `SchUseStrongCrypto` en .NET Framework.
- Detección de LLMNR y NetBIOS sobre TCP/IP.
- Comparación de versiones de Chrome, Edge y Firefox con la última versión estable publicada.
- Detección de software web obsoleto, del componente Internet Explorer 11 y de MySQL de XAMPP sin contraseña.
- Análisis del archivo `hosts` y de la configuración de proxy/PAC.
- Informe HTML autocontenido y exportación JSON.
- Estilos de impresión del informe: al imprimir o exportar a PDF se despliegan todos los hallazgos y se ocultan los controles interactivos.
- Nota de vigencia en el informe con la fecha y hora del análisis.
- README en inglés, guía de contribución (`CONTRIBUTING.md`) e instrucciones de firma del script.
- Menú de remediación con confirmación individual, relanzamiento elevado, respaldo previo del registro y del firewall, y registro de acciones.
- Ayuda integrada en cada función, en el formato estándar de PowerShell.
- Sección «Cómo funciona» en el README y documentación de la arquitectura interna (`docs/arquitectura.md`).
- Prueba de extremo a extremo en Windows Sandbox (`pruebas/`) que valida la detección, la remediación y la reversión.
- Política de seguridad para informar vulnerabilidades de la herramienta (`SECURITY.md`).
- Comentarios en el código que justifican los criterios de detección y clasificación, con referencias a RFC, CVE, CWE, OWASP WSTG y MITRE ATT&CK.
