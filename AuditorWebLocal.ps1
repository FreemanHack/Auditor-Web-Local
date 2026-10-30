#requires -Version 5.1
<#
.SYNOPSIS
    Auditor de Seguridad Web Local: análisis de vulnerabilidades web en equipos Windows, con
    informe visual por nivel de riesgo y corrección asistida.

.DESCRIPTION
    Analiza el equipo en busca de debilidades relacionadas con la navegación y los servicios web:
      - Servidores web y bases de datos en escucha, y su exposición a la red.
      - Servidores web locales: cabeceras de seguridad, CORS, cookies, listado de directorios
        y archivos sensibles publicados (.env, .git, phpinfo, phpMyAdmin, etc.).
      - Protocolos TLS/SSL obsoletos y configuración criptográfica de .NET.
      - Navegadores desactualizados (comparación en línea con la última versión estable).
      - Software web al final de su vida útil (Flash, Silverlight, QuickTime, Java...).
      - Firewall, antivirus, soporte del sistema operativo, actualizaciones.
      - Archivo hosts, proxy del sistema y protocolos LLMNR/NetBIOS (envenenamiento WPAD).

    Cada hallazgo recibe un nivel de riesgo (Crítico, Alto, Medio, Bajo, Info). Al finalizar se
    genera un informe HTML y un JSON, y se ofrece un menú para aplicar las correcciones
    disponibles, con confirmación individual y respaldo previo del registro.

.PARAMETER SoloEscaneo
    Ejecuta el análisis y genera el informe sin ofrecer correcciones.

.PARAMETER SinConexion
    Omite la consulta en línea de las últimas versiones de los navegadores.

.PARAMETER RutaInforme
    Carpeta de salida de informes y respaldos. Por defecto: .\informes junto al script.

.PARAMETER NoAbrir
    No abre el informe en el navegador al finalizar.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\AuditorWebLocal.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\AuditorWebLocal.ps1 -SoloEscaneo -SinConexion

.NOTES
    Autor:   FreemanHack
    Versión: 1.0.0

.LINK
    README.md
#>
[CmdletBinding()]
param(
    [switch]$SoloEscaneo,
    [switch]$SinConexion,
    [string]$RutaInforme,
    [switch]$NoAbrir
)

if (-not $RutaInforme) { $RutaInforme = Join-Path $PSScriptRoot 'informes' }

# ---------------------------------------------------------------------------
# Estado global y utilidades
# ---------------------------------------------------------------------------

$script:Version       = '1.0.0'
$script:Hallazgos     = New-Object System.Collections.Generic.List[object]
$script:ServiciosWeb  = New-Object System.Collections.Generic.List[object]
$script:Contador      = 0
$script:FechaEscaneo  = Get-Date
$script:EsAdmin       = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$script:TieneWinget   = [bool](Get-Command winget -ErrorAction SilentlyContinue)
$script:RutaSchannel  = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'

# Orden: prioridad de presentación. Peso: aporte de cada hallazgo a la puntuación de exposición.
# La escala no es lineal a propósito: un hallazgo crítico debe pesar más que varios de nivel bajo.
$script:Niveles       = 'Crítico', 'Alto', 'Medio', 'Bajo', 'Info'
$script:Orden         = @{ 'Crítico' = 0; 'Alto' = 1; 'Medio' = 2; 'Bajo' = 3; 'Info' = 4 }
$script:Peso          = @{ 'Crítico' = 10; 'Alto' = 6; 'Medio' = 3; 'Bajo' = 1; 'Info' = 0 }
$script:ColorConsola  = @{ 'Crítico' = 'Red'; 'Alto' = 'DarkYellow'; 'Medio' = 'Yellow'; 'Bajo' = 'Cyan'; 'Info' = 'Gray' }

# Puertos que se sondean por HTTP. Incluye los de los servidores de desarrollo más comunes, que
# suelen quedar escuchando en 0.0.0.0 sin que el usuario lo sepa.
$script:PuertosWeb = @{
    80 = 'HTTP'; 443 = 'HTTPS'; 8080 = 'HTTP alternativo / proxy'; 8000 = 'Servidor de desarrollo'
    8008 = 'HTTP alternativo'; 8081 = 'HTTP alternativo'; 8443 = 'HTTPS alternativo'; 8888 = 'HTTP / Jupyter'
    3000 = 'Node.js / React (desarrollo)'; 4200 = 'Angular (desarrollo)'; 5000 = 'Flask / ASP.NET (desarrollo)'
    5173 = 'Vite (desarrollo)'; 9000 = 'PHP-FPM / Portainer'; 9090 = 'Consola web de administración'
}
# Bases de datos y cachés: no se sondean (no hablan HTTP), pero su exposición a la red es más grave
# porque varias de ellas (Redis, MongoDB, Elasticsearch, Memcached) no exigen autenticación por defecto.
$script:PuertosDatos = @{
    3306 = 'MySQL / MariaDB'; 5432 = 'PostgreSQL'; 1433 = 'SQL Server'; 27017 = 'MongoDB'
    6379 = 'Redis'; 9200 = 'Elasticsearch'; 11211 = 'Memcached'; 5984 = 'CouchDB'
}

# Rutas que no deberían ser públicas en un servidor web. El patrón se valida contra el contenido
# para evitar falsos positivos en servidores que devuelven la misma página para cualquier ruta
# (aplicaciones SPA, servidores de desarrollo con fallback a index.html).
# SinHtml descarta además las respuestas que empiezan con una etiqueta HTML, para los archivos
# que nunca deberían contener HTML (.git/HEAD, .env, .htaccess).
# Referencias: OWASP WSTG-CONF-04 (Review Old Backup and Unreferenced Files) y WSTG-CONF-05
# (Enumerate Infrastructure and Application Admin Interfaces).
$script:RutasSensibles = @(
    # CWE-527: Exposure of Version-Control Repository to an Unauthorized Control Sphere
    @{ Ruta = '/.git/HEAD'; Patron = '^ref:\s'; SinHtml = $true; Riesgo = 'Alto'
       Titulo = 'Repositorio Git publicado (/.git/)'
       Descripcion = 'Permite reconstruir el código fuente con todo su historial de commits, incluidas las credenciales que se hayan subido alguna vez.'
       Recomendacion = 'Retirar la carpeta .git del directorio público o bloquear en el servidor el acceso a las rutas que empiezan por «/.».' }
    # CWE-538: Insertion of Sensitive Information into Externally-Accessible File or Directory
    @{ Ruta = '/.env'; Patron = '(?m)^[A-Z][A-Z0-9_]*\s*='; SinHtml = $true; Riesgo = 'Crítico'
       Titulo = 'Archivo .env accesible'
       Descripcion = 'Suele contener contraseñas de base de datos, claves de API y secretos de la aplicación.'
       Recomendacion = 'Mover el archivo fuera del directorio público, bloquear el acceso a él en el servidor y rotar todos los secretos que contenga.' }
    # CWE-530: Exposure of Backup File to an Unauthorized Control Sphere
    @{ Ruta = '/backup.sql'; Patron = '(?i)CREATE TABLE|INSERT INTO'; Riesgo = 'Crítico'
       Titulo = 'Volcado SQL descargable'
       Descripcion = 'Expone la base de datos completa, incluidos usuarios y contraseñas.'
       Recomendacion = 'Eliminar el volcado de la raíz pública y almacenar los respaldos fuera del servidor web.' }
    # CWE-530. El .bak se sirve como texto plano porque el servidor no lo interpreta como PHP.
    @{ Ruta = '/wp-config.php.bak'; Patron = 'DB_PASSWORD'; Riesgo = 'Crítico'
       Titulo = 'Copia de wp-config.php descargable'
       Descripcion = 'Expone las credenciales de la base de datos de WordPress en texto claro.'
       Recomendacion = 'Eliminar las copias de seguridad de archivos de configuración de la raíz pública y cambiar la contraseña de la base de datos.' }
    # CWE-538
    @{ Ruta = '/web.config'; Patron = '<configuration'; Riesgo = 'Alto'
       Titulo = 'web.config descargable'
       Descripcion = 'Puede revelar cadenas de conexión, claves de máquina y la configuración interna de IIS/ASP.NET.'
       Recomendacion = 'Verificar que el manejador de archivos estáticos no sirva archivos .config.' }
    # OWASP WSTG-CONF-05
    @{ Ruta = '/phpmyadmin/'; Patron = 'phpMyAdmin'; Riesgo = 'Alto'
       Titulo = 'Panel phpMyAdmin accesible'
       Descripcion = 'Es la interfaz de administración de las bases de datos y uno de los objetivos más habituales de los ataques de fuerza bruta.'
       Recomendacion = 'Restringir el acceso a 127.0.0.1 («Require local» en Apache) y exigir contraseña al usuario root.' }
    # CWE-200: Exposure of Sensitive Information to an Unauthorized Actor (también aplica a info.php y server-status)
    @{ Ruta = '/phpinfo.php'; Patron = 'phpinfo\(\)|PHP Version'; Riesgo = 'Medio'
       Titulo = 'Página phpinfo() publicada'
       Descripcion = 'Revela versiones, rutas internas, módulos y variables de entorno útiles para un atacante.'
       Recomendacion = 'Eliminar el archivo phpinfo.php del servidor.' }
    @{ Ruta = '/info.php'; Patron = 'phpinfo\(\)|PHP Version'; Riesgo = 'Medio'
       Titulo = 'Página phpinfo() publicada (info.php)'
       Descripcion = 'Revela versiones, rutas internas, módulos y variables de entorno útiles para un atacante.'
       Recomendacion = 'Eliminar el archivo info.php del servidor.' }
    @{ Ruta = '/server-status'; Patron = 'Apache Server Status'; Riesgo = 'Medio'
       Titulo = 'Estado del servidor Apache (mod_status) accesible'
       Descripcion = 'Muestra las peticiones en curso, direcciones IP de clientes y URLs internas.'
       Recomendacion = 'Limitar /server-status a «Require local» o deshabilitar mod_status.' }
    # CWE-538
    @{ Ruta = '/.htaccess'; Patron = '(?m)^\s*(RewriteEngine|Deny from|Require all|Options )'; SinHtml = $true; Riesgo = 'Medio'
       Titulo = 'Archivo .htaccess legible'
       Descripcion = 'Revela reglas de reescritura y de control de acceso del sitio.'
       Recomendacion = 'Agregar «<Files ".ht*"> Require all denied </Files>» a la configuración de Apache.' }
    # CWE-1188: Initialization of a Resource with an Insecure Default
    @{ Ruta = '/dashboard/'; Patron = 'XAMPP'; Riesgo = 'Bajo'
       Titulo = 'Panel de bienvenida de XAMPP accesible'
       Descripcion = 'Indica una instalación de XAMPP con la configuración por defecto, orientada a desarrollo y no a producción.'
       Recomendacion = 'Eliminar la carpeta htdocs\dashboard o restringir su acceso a localhost.' }
)

function Write-Paso {
    <#
    .SYNOPSIS
        Muestra en consola la verificación que está en curso.
    #>
    param([string]$Texto)
    Write-Host "  > $Texto..." -ForegroundColor DarkCyan
}

function Add-Hallazgo {
    <#
    .SYNOPSIS
        Registra un hallazgo en la lista global con un identificador correlativo.
    .DESCRIPTION
        Recibe una tabla hash para que cada verificación declare solo los campos que necesita.
        Los controles superados (Vulnerable = $false) se normalizan a riesgo Info y estado OK,
        de modo que no suman a la puntuación de exposición.
    .PARAMETER D
        Claves admitidas: Categoria, Titulo, Riesgo, Vulnerable, Detalle, Recomendacion,
        Correccion (código PowerShell; vacío indica corrección manual) y RequiereAdmin.
    #>
    param([Parameter(Mandatory)][hashtable]$D)
    $script:Contador++
    $obj = [ordered]@{
        Id            = $script:Contador
        Categoria     = [string]$D.Categoria
        Titulo        = [string]$D.Titulo
        Riesgo        = if ($D.Riesgo) { [string]$D.Riesgo } else { 'Info' }
        Vulnerable    = if ($D.ContainsKey('Vulnerable')) { [bool]$D.Vulnerable } else { $true }
        Detalle       = [string]$D.Detalle
        Recomendacion = [string]$D.Recomendacion
        Correccion    = [string]$D.Correccion      # código PowerShell; vacío = corrección manual
        RequiereAdmin = [bool]$D.RequiereAdmin
        Estado        = 'Pendiente'
    }
    if (-not $obj.Vulnerable) { $obj.Riesgo = 'Info'; $obj.Estado = 'OK' }
    $script:Hallazgos.Add([pscustomobject]$obj)
}

function Add-Correcto {
    <#
    .SYNOPSIS
        Registra un control superado. Atajo de Add-Hallazgo con Vulnerable = $false.
    #>
    param([string]$Categoria, [string]$Titulo, [string]$Detalle = '')
    Add-Hallazgo @{ Categoria = $Categoria; Titulo = $Titulo; Detalle = $Detalle; Vulnerable = $false }
}

function Get-RiesgoReducido {
    <#
    .SYNOPSIS
        Devuelve el nivel de riesgo inmediatamente inferior.
    .DESCRIPTION
        Se aplica a los hallazgos de servidores que solo escuchan en loopback: el problema existe,
        pero un atacante necesita acceso previo al equipo para explotarlo.
    #>
    param([string]$Riesgo)
    switch ($Riesgo) {
        'Crítico' { 'Alto' }
        'Alto'    { 'Medio' }
        'Medio'   { 'Bajo' }
        default   { $Riesgo }
    }
}

function ConvertTo-Version {
    <#
    .SYNOPSIS
        Convierte una cadena de versión en [version], o devuelve $null si no es válida.
    .DESCRIPTION
        Descarta sufijos como «b3» o « (64-bit)» y completa las versiones de un solo número
        («131» -> «131.0»), porque [version] exige al menos dos componentes.
    #>
    param([string]$Texto)
    $limpio = ($Texto -replace '[^\d\.].*$', '').Trim('.')
    if ($limpio -notmatch '\.') { $limpio += '.0' }
    try { [version]$limpio } catch { $null }
}

function Invoke-Sonda {
    <#
    .SYNOPSIS
        Envía una petición GET y devuelve código de estado, cabeceras y hasta 64 KB del cuerpo.
    .DESCRIPTION
        Usa HttpWebRequest en lugar de Invoke-WebRequest porque en PowerShell 5.1 este último lanza
        excepciones en respuestas 3xx/4xx/5xx y no permite leerlas de forma uniforme.
        Devuelve $null si no hay respuesta (puerto cerrado, tiempo agotado o protocolo distinto).
    .PARAMETER Url
        URL completa a solicitar.
    .PARAMETER Origen
        Valor del encabezado Origin. Se usa para comprobar si el servidor refleja orígenes en CORS.
    .PARAMETER TimeoutMs
        Tiempo máximo de conexión y de lectura, en milisegundos.
    .OUTPUTS
        PSCustomObject con Url, Codigo, Headers (claves en minúsculas) y Contenido.
    #>
    param([string]$Url, [string]$Origen, [int]$TimeoutMs = 4000)
    try {
        $req = [System.Net.HttpWebRequest]::Create($Url)
        $req.Method = 'GET'
        $req.Timeout = $TimeoutMs
        $req.ReadWriteTimeout = $TimeoutMs
        # Sin redirecciones: interesa la respuesta del recurso pedido, no la de la página de destino
        # (por ejemplo, un 302 hacia /login haría pasar por válida cualquier ruta sensible).
        $req.AllowAutoRedirect = $false
        # Sin proxy: las sondas son locales y no deben salir del equipo, ni siquiera hacia un proxy
        # configurado en el sistema que podría registrarlas.
        $req.Proxy = $null
        $req.UserAgent = "AuditorWebLocal/$script:Version"
        if ($Origen) { $req.Headers.Add('Origin', $Origen) }

        $resp = $null
        try { $resp = $req.GetResponse() }
        catch {
            # Las respuestas de error HTTP llegan como WebException, a veces envueltas en otra
            # excepción. Se busca la WebException para recuperar igualmente la respuesta.
            $ex = $_.Exception
            while ($ex -and -not ($ex -is [System.Net.WebException])) { $ex = $ex.InnerException }
            if ($ex -and $ex.Response) { $resp = $ex.Response } else { return $null }
        }

        $cabeceras = @{}
        foreach ($k in $resp.Headers.AllKeys) { $cabeceras[$k.ToLower()] = $resp.Headers[$k] }
        # Se leen como máximo 64 KB: alcanza para validar los patrones y evita descargar volcados grandes.
        $contenido = ''
        try {
            $lector = New-Object System.IO.StreamReader($resp.GetResponseStream())
            $buffer = New-Object char[] 65536
            $n = $lector.Read($buffer, 0, $buffer.Length)
            if ($n -gt 0) { $contenido = [string]::new($buffer, 0, $n) }
            $lector.Close()
        } catch {}
        $codigo = [int]$resp.StatusCode
        $resp.Close()
        [pscustomobject]@{ Url = $Url; Codigo = $codigo; Headers = $cabeceras; Contenido = $contenido }
    } catch { $null }
}

# ---------------------------------------------------------------------------
# Verificaciones
# ---------------------------------------------------------------------------

function Test-SistemaOperativo {
    <#
    .SYNOPSIS
        Comprueba si el sistema operativo tiene soporte de seguridad y cuándo se actualizó por última vez.
    .NOTES
        Ciclo de vida de Windows 10: https://learn.microsoft.com/lifecycle/products/windows-10-home-and-pro
        Los umbrales de 35 y 60 días equivalen a uno y dos ciclos mensuales de parches perdidos.
    #>
    Write-Paso 'Sistema operativo y actualizaciones'
    $os = Get-CimInstance Win32_OperatingSystem
    $build = [int]$os.BuildNumber

    # Windows 11 comienza en la compilación 22000; cualquier compilación anterior es Windows 10 o previa.
    if ($build -lt 22000 -and (Get-Date) -ge [datetime]'2025-10-14') {
        Add-Hallazgo @{
            Categoria     = 'Sistema'
            Titulo        = 'Windows 10 fuera del soporte de seguridad'
            Riesgo        = 'Alto'
            Detalle       = "$($os.Caption) (compilación $build). El soporte general de Windows 10 finalizó el 14/10/2025 y el programa ESU para consumidores cubrió hasta el 13/10/2026. Sin ESU vigente, las nuevas vulnerabilidades del sistema, incluidas las de los componentes de red y web, quedan sin parchear."
            Recomendacion = 'Actualizar a Windows 11 si el hardware lo admite, o verificar la inscripción del equipo en las Actualizaciones de Seguridad Extendidas (ESU) comerciales o educativas.'
            Correccion    = "Start-Process 'ms-settings:windowsupdate'"
        }
    } else {
        Add-Correcto 'Sistema' 'Sistema operativo con soporte de seguridad' "$($os.Caption) (compilación $build)."
    }

    $ultima = Get-HotFix -ErrorAction SilentlyContinue | Where-Object { $_.InstalledOn } |
        Sort-Object InstalledOn -Descending | Select-Object -First 1
    if ($ultima) {
        $dias = [int]((Get-Date) - $ultima.InstalledOn).TotalDays
        $detalle = "Última actualización instalada: $($ultima.HotFixID) el $($ultima.InstalledOn.ToString('dd/MM/yyyy')) (hace $dias días)."
        if ($dias -gt 35) {
            Add-Hallazgo @{
                Categoria     = 'Sistema'
                Titulo        = 'Actualizaciones de Windows pendientes'
                Riesgo        = if ($dias -gt 60) { 'Alto' } else { 'Medio' }
                Detalle       = "$detalle Microsoft publica parches de seguridad cada mes (Patch Tuesday)."
                Recomendacion = 'Buscar e instalar las actualizaciones disponibles en Windows Update.'
                Correccion    = "Start-Process 'ms-settings:windowsupdate'"
            }
        } else {
            Add-Correcto 'Sistema' 'Actualizaciones de Windows recientes' $detalle
        }
    }
}

function Test-Firewall {
    <#
    .SYNOPSIS
        Verifica que el firewall de Windows esté habilitado en los perfiles de dominio, privado y público.
    .NOTES
        CIS Microsoft Windows Benchmark, sección «Windows Defender Firewall with Advanced Security».
    #>
    Write-Paso 'Firewall de Windows'
    try { $perfiles = Get-NetFirewallProfile -ErrorAction Stop }
    catch {
        Add-Hallazgo @{ Categoria = 'Red'; Titulo = 'No se pudo consultar el firewall'; Riesgo = 'Info'; Detalle = $_.Exception.Message }
        return
    }
    foreach ($p in $perfiles) {
        # Enabled es de tipo GpoBoolean (True, False o NotConfigured); se compara como texto para
        # tratar NotConfigured como habilitado, que es el valor efectivo por defecto.
        if ("$($p.Enabled)" -eq 'False') {
            Add-Hallazgo @{
                Categoria     = 'Red'
                Titulo        = "Firewall deshabilitado en el perfil $($p.Name)"
                Riesgo        = 'Crítico'
                Detalle       = "El perfil $($p.Name) no filtra conexiones entrantes: cualquier servicio web o base de datos en escucha queda accesible desde la red."
                Recomendacion = 'Habilitar el firewall en todos los perfiles.'
                Correccion    = "Set-NetFirewallProfile -Profile $($p.Name) -Enabled True"
                RequiereAdmin = $true
            }
        } else {
            Add-Correcto 'Red' "Firewall habilitado en el perfil $($p.Name)"
        }
    }
}

function Test-Antivirus {
    <#
    .SYNOPSIS
        Comprueba la protección en tiempo real de Microsoft Defender y la antigüedad de sus firmas.
    .DESCRIPTION
        Cuando hay un antivirus de terceros registrado en el Centro de seguridad, Defender pasa a
        modo pasivo de forma automática. En ese caso, su desactivación no se informa como hallazgo.
    .NOTES
        MITRE ATT&CK T1562.001 (Impair Defenses: Disable or Modify Tools): desactivar el antivirus
        es uno de los primeros pasos habituales tras comprometer un equipo.
    #>
    Write-Paso 'Protección antivirus'
    $otros = @()
    try {
        $otros = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop |
            Where-Object { $_.displayName -notmatch 'Windows Defender|Microsoft Defender' } |
            ForEach-Object { $_.displayName })
    } catch {}

    try { $mp = Get-MpComputerStatus -ErrorAction Stop }
    catch {
        if ($otros.Count) { Add-Correcto 'Sistema' "Antivirus de terceros registrado: $($otros -join ', ')" }
        else { Add-Hallazgo @{ Categoria = 'Sistema'; Titulo = 'No se pudo verificar Microsoft Defender'; Riesgo = 'Info'; Detalle = $_.Exception.Message } }
        return
    }

    if (-not $mp.RealTimeProtectionEnabled) {
        if ($otros.Count) {
            Add-Correcto 'Sistema' "Protección en tiempo real provista por: $($otros -join ', ')"
        } else {
            Add-Hallazgo @{
                Categoria     = 'Sistema'
                Titulo        = 'Protección en tiempo real de Microsoft Defender desactivada'
                Riesgo        = 'Alto'
                Detalle       = 'No hay otro antivirus activo, por lo que las descargas y los scripts que llegan desde sitios web se ejecutan sin análisis previo.'
                Recomendacion = 'Reactivar la protección en tiempo real. Si la protección contra alteraciones está activa, hacerlo desde Seguridad de Windows.'
                Correccion    = 'Set-MpPreference -DisableRealtimeMonitoring $false'
                RequiereAdmin = $true
            }
        }
    } else {
        Add-Correcto 'Sistema' 'Protección en tiempo real de Microsoft Defender activa'
        if ($mp.AntivirusSignatureAge -gt 7) {
            Add-Hallazgo @{
                Categoria     = 'Sistema'
                Titulo        = 'Firmas de Microsoft Defender desactualizadas'
                Riesgo        = 'Medio'
                Detalle       = "Las definiciones tienen $($mp.AntivirusSignatureAge) días de antigüedad."
                Recomendacion = 'Actualizar las definiciones de seguridad.'
                Correccion    = 'Update-MpSignature'
                RequiereAdmin = $true
            }
        }
    }
}

function Test-PuertosWeb {
    <#
    .SYNOPSIS
        Enumera los puertos TCP en escucha y evalúa si los servicios web o de datos están expuestos a la red.
    .DESCRIPTION
        Un servicio se considera expuesto si escucha en alguna dirección distinta de loopback
        (0.0.0.0, :: o una IP de la red local). Los servicios web detectados se guardan en
        $script:ServiciosWeb para que Test-ServidoresWeb los sondee después.
    .NOTES
        CWE-1327: Binding to an Unrestricted IP Address.
    #>
    Write-Paso 'Servicios web y bases de datos en escucha'
    try { $escuchas = @(Get-NetTCPConnection -State Listen -ErrorAction Stop) }
    catch {
        Add-Hallazgo @{ Categoria = 'Servicios expuestos'; Titulo = 'No se pudieron enumerar los puertos en escucha'; Riesgo = 'Info'; Detalle = $_.Exception.Message }
        return
    }

    $encontrados = 0
    foreach ($g in ($escuchas | Group-Object -Property { [int]$_.LocalPort })) {
        $puerto  = [int]$g.Name
        $esWeb   = $script:PuertosWeb.ContainsKey($puerto)
        $esDatos = $script:PuertosDatos.ContainsKey($puerto)
        if (-not ($esWeb -or $esDatos)) { continue }
        $encontrados++

        $direcciones = @($g.Group | ForEach-Object { $_.LocalAddress } | Sort-Object -Unique)
        $expuesto = @($direcciones | Where-Object { $_ -notmatch '^(127\.|::1$)' }).Count -gt 0
        # El PID 4 corresponde al kernel: el puerto lo atiende HTTP.sys en nombre de IIS, WinRM,
        # WSDAPI u otro servicio que comparta el controlador HTTP de Windows.
        $procId = ($g.Group | Select-Object -First 1).OwningProcess
        $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
        $nombreProc = if ($procId -eq 4) { 'System / HTTP.sys (PID 4: IIS u otro servicio HTTP de Windows)' }
                      elseif ($proc) { "$($proc.ProcessName) (PID $procId)" } else { "PID $procId" }
        $servicio = if ($esWeb) { $script:PuertosWeb[$puerto] } else { $script:PuertosDatos[$puerto] }
        if ($esWeb) {
            $script:ServiciosWeb.Add([pscustomobject]@{ Puerto = $puerto; Expuesto = $expuesto; Proceso = $nombreProc })
        }

        $desc = "Puerto TCP $puerto ($servicio) en escucha por $nombreProc en: $($direcciones -join ', ')."
        if ($expuesto) {
            # La regla de bloqueo solo afecta al tráfico entrante desde la red: el firewall de
            # Windows no filtra loopback, así que el servicio sigue disponible en 127.0.0.1.
            # Las reglas de bloqueo tienen prioridad sobre las de permiso existentes.
            $regla = "AuditorWebLocal - Bloquear TCP $puerto"
            Add-Hallazgo @{
                Categoria     = 'Servicios expuestos'
                Titulo        = "$servicio accesible desde la red (puerto $puerto)"
                Riesgo        = if ($esDatos) { 'Alto' } else { 'Medio' }
                Detalle       = "$desc El servicio acepta conexiones en interfaces distintas de loopback, por lo que otros equipos de la red pueden acceder a él si el firewall lo permite."
                Recomendacion = 'Configurar el servicio para escuchar solo en 127.0.0.1, o bloquear el puerto en el firewall si no debe ser accesible desde otros equipos. La corrección automática agrega una regla de bloqueo de entrada (el acceso local no se ve afectado).'
                Correccion    = "if (-not (Get-NetFirewallRule -DisplayName '$regla' -ErrorAction SilentlyContinue)) { New-NetFirewallRule -DisplayName '$regla' -Direction Inbound -Protocol TCP -LocalPort $puerto -Action Block -Profile Any | Out-Null }"
                RequiereAdmin = $true
            }
        } else {
            Add-Correcto 'Servicios expuestos' "$servicio solo accesible desde este equipo (puerto $puerto)" $desc
        }
    }
    if ($encontrados -eq 0) {
        Add-Correcto 'Servicios expuestos' 'No hay servicios web ni bases de datos en escucha en los puertos habituales'
    }
}

function Test-ServidorWeb {
    <#
    .SYNOPSIS
        Analiza un servidor web local: cabeceras, CORS, cookies, listado de directorios y archivos sensibles.
    .DESCRIPTION
        Primero determina si el puerto habla HTTP o HTTPS. Después evalúa la respuesta de la raíz y
        solicita cada ruta de $script:RutasSensibles. Si el servicio solo escucha en loopback, el
        riesgo de los hallazgos baja un nivel, excepto en CORS (ver comentario en esa sección).
    .PARAMETER Servicio
        Objeto con Puerto, Expuesto y Proceso, generado por Test-PuertosWeb.
    #>
    param($Servicio)
    $p = $Servicio.Puerto
    # Dominio reservado (RFC 2606): nunca puede coincidir con un origen legítimo configurado.
    $origenPrueba = 'https://origen-externo.example'
    $esquemas = if ($p -eq 443 -or $p -eq 8443) { 'https', 'http' } else { 'http', 'https' }

    # Un 400 suele indicar que se habló HTTP a un puerto HTTPS (o al revés). Se guarda como reserva
    # y se prueba el otro esquema antes de darlo por válido.
    $resp = $null; $reserva = $null
    foreach ($e in $esquemas) {
        $r = Invoke-Sonda -Url "${e}://127.0.0.1:$p/" -Origen $origenPrueba
        if (-not $r) { continue }
        if ($r.Codigo -ne 400) { $resp = $r; break }
        if (-not $reserva) { $reserva = $r }
    }
    if (-not $resp) { $resp = $reserva }
    if (-not $resp) {
        Add-Hallazgo @{ Categoria = 'Servidores web'; Titulo = "El servicio del puerto $p no respondió a HTTP/HTTPS"; Riesgo = 'Info'; Detalle = "Proceso: $($Servicio.Proceso). Puede tratarse de un servicio que no utiliza HTTP." }
        return
    }

    $base = $resp.Url.TrimEnd('/')
    $esHttps = $base.StartsWith('https')
    $h = $resp.Headers
    $exp = $Servicio.Expuesto
    $ambito = if ($exp) { 'El servicio es accesible desde la red local.' } else { 'El servicio solo es accesible desde este equipo, lo que reduce el riesgo.' }
    $infoSrv = "Servidor: $base (HTTP $($resp.Codigo)), proceso $($Servicio.Proceso). $ambito"
    $problemas = 0

    # Divulgación de versión. CWE-200; OWASP WSTG-INFO-02 (Fingerprint Web Server).
    # Solo se informa si la cabecera incluye números: «Server: nginx» no revela la versión.
    $software = (@($h['server'], $h['x-powered-by'], $h['x-aspnet-version']) | Where-Object { $_ }) -join ' | '
    if ($software -match '\d') {
        $problemas++
        Add-Hallazgo @{
            Categoria     = 'Servidores web'
            Titulo        = "Divulgación de versión del software en $base"
            Riesgo        = 'Bajo'
            Detalle       = "Cabeceras devueltas: $software. Conocer la versión exacta permite buscar directamente vulnerabilidades públicas para ese software. $infoSrv"
            Recomendacion = 'Ocultar la versión. Apache: «ServerTokens Prod» y «ServerSignature Off». nginx: «server_tokens off;». PHP: «expose_php = Off». IIS: «removeServerHeader="true"» en requestFiltering.'
        }
    }

    # Cabeceras de seguridad. OWASP Secure Headers Project; CWE-1021 (clickjacking).
    # frame-ancestors en CSP sustituye a X-Frame-Options, por eso cualquiera de las dos es suficiente.
    # HSTS solo se exige bajo HTTPS: los navegadores ignoran esa cabecera si llega por HTTP.
    $faltan = @()
    if (-not $h['x-content-type-options']) { $faltan += 'X-Content-Type-Options' }
    if (-not $h['content-security-policy']) { $faltan += 'Content-Security-Policy' }
    if (-not $h['x-frame-options'] -and ([string]$h['content-security-policy']) -notmatch 'frame-ancestors') { $faltan += 'X-Frame-Options' }
    if (-not $h['referrer-policy']) { $faltan += 'Referrer-Policy' }
    if ($esHttps -and -not $h['strict-transport-security']) { $faltan += 'Strict-Transport-Security' }
    if ($faltan.Count) {
        $problemas++
        Add-Hallazgo @{
            Categoria     = 'Servidores web'
            Titulo        = "Cabeceras de seguridad ausentes en $base"
            Riesgo        = if ($exp) { 'Medio' } else { 'Bajo' }
            Detalle       = "Faltan: $($faltan -join ', '). Sin ellas, el navegador no activa las protecciones contra clickjacking, MIME sniffing y parte de los ataques XSS. $infoSrv"
            Recomendacion = 'Agregar las cabeceras en el servidor o en el framework. Ejemplo para Apache (mod_headers): Header always set X-Content-Type-Options "nosniff" | Header always set X-Frame-Options "SAMEORIGIN" | Header always set Referrer-Policy "strict-origin-when-cross-origin" | Header always set Content-Security-Policy "default-src ''self''".'
        }
    }

    # CORS. CWE-942 (Permissive Cross-domain Policy with Untrusted Domains); OWASP WSTG-CLNT-07.
    # A diferencia del resto, este riesgo no se reduce para servicios locales: el ataque lo ejecuta
    # el navegador del propio usuario al visitar un sitio malicioso, que sí alcanza 127.0.0.1.
    # Reflejar el origen junto con Allow-Credentials permite leer respuestas autenticadas, de ahí el nivel Alto.
    $acao = [string]$h['access-control-allow-origin']
    $acac = [string]$h['access-control-allow-credentials']
    if ($acao -eq $origenPrueba) {
        $problemas++
        Add-Hallazgo @{
            Categoria     = 'Servidores web'
            Titulo        = "CORS refleja cualquier origen en $base"
            Riesgo        = if ($acac -match 'true') { 'Alto' } else { 'Medio' }
            Detalle       = "El servidor devolvió Access-Control-Allow-Origin: $acao (origen arbitrario de prueba) y Access-Control-Allow-Credentials: $(if ($acac) { $acac } else { 'ausente' }). Un sitio malicioso abierto en el navegador de este equipo puede leer las respuestas del servidor local, aunque no esté expuesto a la red."
            Recomendacion = 'Definir una lista explícita de orígenes permitidos en lugar de reflejar el encabezado Origin, y no combinarla con Allow-Credentials salvo que sea imprescindible.'
        }
    } elseif ($acao -eq '*') {
        $problemas++
        Add-Hallazgo @{
            Categoria     = 'Servidores web'
            Titulo        = "CORS abierto a cualquier origen (*) en $base"
            Riesgo        = 'Bajo'
            Detalle       = "Cualquier sitio web visitado desde este equipo puede leer las respuestas públicas del servidor local. $infoSrv"
            Recomendacion = 'Restringir Access-Control-Allow-Origin a los orígenes que realmente consumen la API.'
        }
    }

    # Cookies. CWE-1004 (sin HttpOnly), CWE-614 (sin Secure bajo HTTPS), CWE-1275 (SameSite inadecuado).
    # .NET une varias cabeceras Set-Cookie en una sola cadena, así que la comprobación es global:
    # basta con que una cookie tenga el atributo para que no se informe su ausencia.
    $cookies = [string]$h['set-cookie']
    if ($cookies) {
        $faltanAtrib = @()
        if ($cookies -notmatch '(?i)httponly') { $faltanAtrib += 'HttpOnly' }
        if ($esHttps -and $cookies -notmatch '(?i);\s*secure') { $faltanAtrib += 'Secure' }
        if ($cookies -notmatch '(?i)samesite') { $faltanAtrib += 'SameSite' }
        if ($faltanAtrib.Count) {
            $problemas++
            Add-Hallazgo @{
                Categoria     = 'Servidores web'
                Titulo        = "Cookies sin atributos de seguridad en $base"
                Riesgo        = 'Bajo'
                Detalle       = "Atributos ausentes: $($faltanAtrib -join ', '). Las cookies de sesión quedan más expuestas a robo por XSS y a ataques CSRF. $infoSrv"
                Recomendacion = 'Emitir las cookies de sesión con HttpOnly, SameSite=Lax (o Strict) y, bajo HTTPS, Secure.'
            }
        }
    }

    # Listado de directorios. CWE-548 (Exposure of Information Through Directory Listing).
    # Los títulos corresponden a Apache/nginx («Index of /») y a «python -m http.server».
    if ($resp.Contenido -match '(?i)<title>\s*(Index of /|Directory listing for /)') {
        $problemas++
        Add-Hallazgo @{
            Categoria     = 'Servidores web'
            Titulo        = "Listado de directorios habilitado en $base"
            Riesgo        = if ($exp) { 'Alto' } else { 'Medio' }
            Detalle       = "La raíz del servidor muestra el contenido de la carpeta, lo que permite descubrir y descargar archivos no enlazados. $infoSrv"
            Recomendacion = 'Deshabilitar el listado: Apache «Options -Indexes»; nginx «autoindex off;»; IIS directoryBrowse enabled="false". En «python -m http.server», no servir carpetas con información privada.'
        }
    }

    foreach ($ruta in $script:RutasSensibles) {
        $r = Invoke-Sonda -Url ($base + $ruta.Ruta)
        if (-not $r -or $r.Codigo -ne 200 -or $r.Contenido -notmatch $ruta.Patron) { continue }
        if ($ruta.SinHtml -and $r.Contenido -match '^\s*<') { continue }
        $problemas++
        Add-Hallazgo @{
            Categoria     = 'Servidores web'
            Titulo        = "$($ruta.Titulo) en $base"
            Riesgo        = if ($exp) { $ruta.Riesgo } else { Get-RiesgoReducido $ruta.Riesgo }
            Detalle       = "URL: $base$($ruta.Ruta). $($ruta.Descripcion) $infoSrv"
            Recomendacion = $ruta.Recomendacion
        }
    }

    if ($problemas -eq 0) {
        Add-Correcto 'Servidores web' "Sin problemas detectados en $base" $infoSrv
    }
}

function Test-ServidoresWeb {
    <#
    .SYNOPSIS
        Ejecuta Test-ServidorWeb sobre cada servicio web detectado por Test-PuertosWeb.
    #>
    if ($script:ServiciosWeb.Count -eq 0) { return }
    Write-Paso "Análisis HTTP de $($script:ServiciosWeb.Count) servidor(es) web local(es)"
    # Los servidores de desarrollo suelen usar certificados autofirmados; se aceptan solo durante el
    # análisis. La validación se restaura en el bloque finally aunque ocurra un error, porque el
    # callback es global para todo el proceso de PowerShell.
    $callbackAnterior = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    try {
        foreach ($s in $script:ServiciosWeb) { Test-ServidorWeb -Servicio $s }
    } finally {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $callbackAnterior
    }
}

function Test-ProtocolosTLS {
    <#
    .SYNOPSIS
        Revisa los protocolos habilitados en SChannel y la configuración criptográfica de .NET Framework.
    .DESCRIPTION
        SChannel es la pila TLS de Windows. La usan IIS, .NET Framework, WinHTTP, el modo IE de Edge
        y los clientes de correo, pero no Chrome ni Firefox, que incluyen su propia implementación.
        Un protocolo se considera habilitado si lo está para el rol cliente o para el rol servidor.
    .NOTES
        RFC 7568: deprecación de SSL 3.0. RFC 8996: deprecación de TLS 1.0 y TLS 1.1.
        CVE-2014-3566 (POODLE), CVE-2011-3389 (BEAST).
        Configuración de SChannel: https://learn.microsoft.com/windows-server/security/tls/tls-registry-settings
    #>
    Write-Paso 'Protocolos TLS/SSL del sistema (SChannel)'
    # PorDefecto indica el estado que aplica Windows 10 cuando la clave no existe en el registro.
    # SSL 2.0 no se revisa porque Windows 10 ya no lo implementa.
    $protocolos = @(
        @{ Nombre = 'SSL 3.0'; PorDefecto = $false; Riesgo = 'Alto';  Motivo = 'es vulnerable a POODLE' }
        @{ Nombre = 'TLS 1.0'; PorDefecto = $true;  Riesgo = 'Medio'; Motivo = 'está obsoleto (RFC 8996) y es vulnerable a BEAST y a ataques de downgrade' }
        @{ Nombre = 'TLS 1.1'; PorDefecto = $true;  Riesgo = 'Medio'; Motivo = 'está obsoleto (RFC 8996) y no admite suites de cifrado AEAD' }
    )
    foreach ($pr in $protocolos) {
        $habilitado = $false
        foreach ($rol in 'Client', 'Server') {
            $k = "$script:RutaSchannel\$($pr.Nombre)\$rol"
            $valor = $null
            if (Test-Path $k) { $valor = (Get-ItemProperty -Path $k -Name Enabled -ErrorAction SilentlyContinue).Enabled }
            # Sin valor explícito rige el comportamiento por defecto. Cualquier valor distinto de 0
            # (incluido 0xFFFFFFFF, que algunas guías usan) significa habilitado.
            if ($null -eq $valor) { if ($pr.PorDefecto) { $habilitado = $true } }
            elseif ($valor -ne 0) { $habilitado = $true }
        }
        if ($habilitado) {
            # La corrección fija Enabled = 0 y DisabledByDefault = 1. Con solo DisabledByDefault, una
            # aplicación podría seguir pidiendo el protocolo de forma explícita.
            $nombre = $pr.Nombre
            Add-Hallazgo @{
                Categoria     = 'Cifrado'
                Titulo        = "Protocolo $nombre habilitado"
                Riesgo        = $pr.Riesgo
                Detalle       = "$nombre $($pr.Motivo). Mientras siga habilitado, cualquier aplicación que use SChannel (Edge en modo IE, IIS, .NET, clientes de correo) puede terminar negociándolo si un servidor o un atacante en la red lo fuerza."
                Recomendacion = "Deshabilitar $nombre para cliente y servidor. Requiere reiniciar el equipo. Aplicaciones muy antiguas que dependan de él pueden dejar de conectarse."
                Correccion    = @"
foreach (`$rol in 'Client', 'Server') {
    `$k = '$script:RutaSchannel\$nombre\' + `$rol
    if (-not (Test-Path `$k)) { New-Item -Path `$k -Force | Out-Null }
    New-ItemProperty -Path `$k -Name Enabled -Value 0 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path `$k -Name DisabledByDefault -Value 1 -PropertyType DWord -Force | Out-Null
}
"@
                RequiereAdmin = $true
            }
        } else {
            Add-Correcto 'Cifrado' "Protocolo $($pr.Nombre) deshabilitado"
        }
    }

    $tls12Off = $false
    foreach ($rol in 'Client', 'Server') {
        $k = "$script:RutaSchannel\TLS 1.2\$rol"
        if ((Test-Path $k) -and (Get-ItemProperty -Path $k -Name Enabled -ErrorAction SilentlyContinue).Enabled -eq 0) { $tls12Off = $true }
    }
    if ($tls12Off) {
        Add-Hallazgo @{
            Categoria     = 'Cifrado'
            Titulo        = 'TLS 1.2 deshabilitado'
            Riesgo        = 'Alto'
            Detalle       = 'TLS 1.2 está desactivado explícitamente en el registro, lo que obliga a usar protocolos más débiles o impide conexiones seguras.'
            Recomendacion = 'Habilitar TLS 1.2 para cliente y servidor y reiniciar el equipo.'
            Correccion    = @"
foreach (`$rol in 'Client', 'Server') {
    `$k = '$script:RutaSchannel\TLS 1.2\' + `$rol
    if (-not (Test-Path `$k)) { New-Item -Path `$k -Force | Out-Null }
    New-ItemProperty -Path `$k -Name Enabled -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path `$k -Name DisabledByDefault -Value 0 -PropertyType DWord -Force | Out-Null
}
"@
            RequiereAdmin = $true
        }
    }

    # Las aplicaciones compiladas para .NET Framework anterior a 4.6 usan por defecto SSL 3.0 y TLS 1.0
    # aunque el sistema admita TLS 1.2. SchUseStrongCrypto y SystemDefaultTlsVersions las obligan a
    # usar los protocolos del sistema. Se revisan las vistas de 64 y 32 bits del registro.
    # Referencia: https://learn.microsoft.com/dotnet/framework/network-programming/tls
    $rutasNet = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319'
    $faltan = @($rutasNet | Where-Object { (Test-Path $_) -and ((Get-ItemProperty $_ -Name SchUseStrongCrypto -ErrorAction SilentlyContinue).SchUseStrongCrypto -ne 1) })
    if ($faltan.Count) {
        $lista = ($faltan | ForEach-Object { "'$_'" }) -join ', '
        Add-Hallazgo @{
            Categoria     = 'Cifrado'
            Titulo        = '.NET Framework sin criptografía fuerte forzada'
            Riesgo        = 'Bajo'
            Detalle       = 'SchUseStrongCrypto no está activado. Aplicaciones .NET antiguas pueden conectarse a sitios web con TLS 1.0 o cifrados débiles.'
            Recomendacion = 'Activar SchUseStrongCrypto y SystemDefaultTlsVersions para que .NET use los protocolos del sistema.'
            Correccion    = @"
foreach (`$k in $lista) {
    New-ItemProperty -Path `$k -Name SchUseStrongCrypto -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path `$k -Name SystemDefaultTlsVersions -Value 1 -PropertyType DWord -Force | Out-Null
}
"@
            RequiereAdmin = $true
        }
    } else {
        Add-Correcto 'Cifrado' '.NET Framework con criptografía fuerte'
    }
}

function Test-ResolucionNombres {
    <#
    .SYNOPSIS
        Comprueba si LLMNR y NetBIOS sobre TCP/IP están habilitados.
    .DESCRIPTION
        Ambos protocolos resuelven nombres por difusión en la red local cuando DNS falla, y
        aceptan la primera respuesta sin autenticarla. Herramientas como Responder los usan para
        suplantar el host WPAD, interceptar tráfico web y capturar hashes NTLMv2.
    .NOTES
        MITRE ATT&CK T1557.001 (LLMNR/NBT-NS Poisoning and SMB Relay).
    #>
    Write-Paso 'LLMNR y NetBIOS (envenenamiento de nombres / WPAD)'
    # LLMNR solo se desactiva por directiva. Sin el valor EnableMulticast = 0, está habilitado.
    $k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
    $llmnr = (Get-ItemProperty -Path $k -Name EnableMulticast -ErrorAction SilentlyContinue).EnableMulticast
    if ($llmnr -ne 0) {
        Add-Hallazgo @{
            Categoria     = 'Red'
            Titulo        = 'LLMNR habilitado'
            Riesgo        = 'Medio'
            Detalle       = 'Si un nombre no se resuelve por DNS, Windows lo consulta por multidifusión en la red local. Cualquier equipo de la red puede responder haciéndose pasar por el destino (por ejemplo, «wpad») para redirigir el tráfico web o capturar hashes NTLM.'
            Recomendacion = 'Deshabilitar LLMNR mediante la directiva del cliente DNS.'
            Correccion    = "if (-not (Test-Path '$k')) { New-Item -Path '$k' -Force | Out-Null }; New-ItemProperty -Path '$k' -Name EnableMulticast -Value 0 -PropertyType DWord -Force | Out-Null"
            RequiereAdmin = $true
        }
    } else {
        Add-Correcto 'Red' 'LLMNR deshabilitado'
    }

    # TcpipNetbiosOptions: 0 = según DHCP (en la práctica, habilitado), 1 = habilitado, 2 = deshabilitado.
    $adaptadores = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' -ErrorAction SilentlyContinue |
        Where-Object { $_.TcpipNetbiosOptions -ne 2 })
    if ($adaptadores.Count) {
        Add-Hallazgo @{
            Categoria     = 'Red'
            Titulo        = 'NetBIOS sobre TCP/IP habilitado'
            Riesgo        = 'Bajo'
            Detalle       = "Adaptadores afectados: $(($adaptadores | ForEach-Object { $_.Description }) -join '; '). NBT-NS permite el mismo tipo de suplantación que LLMNR."
            Recomendacion = 'Deshabilitar NetBIOS en los adaptadores. Puede afectar el acceso a recursos compartidos en redes con equipos muy antiguos.'
            Correccion    = "Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' | ForEach-Object { Invoke-CimMethod -InputObject `$_ -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = [uint32]2 } | Out-Null }"
            RequiereAdmin = $true
        }
    } else {
        Add-Correcto 'Red' 'NetBIOS sobre TCP/IP deshabilitado'
    }
}

function Get-UltimasVersiones {
    <#
    .SYNOPSIS
        Obtiene la última versión estable publicada de Chrome, Firefox y Edge.
    .DESCRIPTION
        Consulta las API públicas de cada fabricante. Si una consulta falla, ese navegador queda
        sin comparar y se informa como Info. Con -SinConexion devuelve una tabla vacía.
    .OUTPUTS
        Hashtable con el nombre del navegador como clave y la versión como texto.
    #>
    $v = @{}
    if ($SinConexion) { return $v }
    try {
        $r = Invoke-RestMethod 'https://versionhistory.googleapis.com/v1/chrome/platforms/win64/channels/stable/versions' -TimeoutSec 8 -UseBasicParsing
        $v['Google Chrome'] = ($r.versions | Sort-Object { [version]$_.version } -Descending | Select-Object -First 1).version
    } catch {}
    try {
        $r = Invoke-RestMethod 'https://product-details.mozilla.org/1.0/firefox_versions.json' -TimeoutSec 8 -UseBasicParsing
        $v['Mozilla Firefox'] = $r.LATEST_FIREFOX_VERSION
    } catch {}
    try {
        $r = Invoke-RestMethod 'https://edgeupdates.microsoft.com/api/products' -TimeoutSec 8 -UseBasicParsing
        $rel = ($r | Where-Object { $_.Product -eq 'Stable' }).Releases |
            Where-Object { $_.Platform -eq 'Windows' -and $_.Architecture -eq 'x64' }
        $v['Microsoft Edge'] = ($rel | Sort-Object { [version]$_.ProductVersion } -Descending | Select-Object -First 1).ProductVersion
    } catch {}
    $v
}

function Test-Navegadores {
    <#
    .SYNOPSIS
        Compara la versión instalada de cada navegador con la última versión estable publicada.
    .DESCRIPTION
        La versión se toma del ejecutable y no del registro, porque el registro puede reflejar una
        actualización descargada que todavía no se aplicó. Un atraso de versión mayor se informa
        como Alto; un atraso dentro de la misma versión mayor, como Medio.
    .NOTES
        Los navegadores aparecen con frecuencia en el catálogo CISA Known Exploited Vulnerabilities
        (https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
    #>
    Write-Paso 'Versiones de los navegadores'
    $navegadores = @(
        @{ Nombre = 'Google Chrome'; Winget = 'Google.Chrome'; Pagina = 'chrome://settings/help'
           Rutas = "$env:ProgramFiles\Google\Chrome\Application\chrome.exe", "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe", "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe" }
        @{ Nombre = 'Microsoft Edge'; Winget = 'Microsoft.Edge'; Pagina = 'edge://settings/help'
           Rutas = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe", "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe" }
        @{ Nombre = 'Mozilla Firefox'; Winget = 'Mozilla.Firefox'; Pagina = ''
           Rutas = "$env:ProgramFiles\Mozilla Firefox\firefox.exe", "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe" }
        @{ Nombre = 'Brave'; Winget = 'Brave.Brave'; Pagina = 'brave://settings/help'
           Rutas = "$env:ProgramFiles\BraveSoftware\Brave-Browser\Application\brave.exe", "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\Application\brave.exe" }
        @{ Nombre = 'Opera'; Winget = 'Opera.Opera'; Pagina = ''
           Rutas = "$env:LOCALAPPDATA\Programs\Opera\opera.exe", "$env:ProgramFiles\Opera\opera.exe" }
    )
    $ultimas = Get-UltimasVersiones

    foreach ($n in $navegadores) {
        $exe = $n.Rutas | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
        if (-not $exe) { continue }
        $textoVersion = (Get-Item $exe).VersionInfo.ProductVersion
        $instalada = ConvertTo-Version $textoVersion
        $correccion = if ($script:TieneWinget) { "winget upgrade --id $($n.Winget) --exact" }
                      elseif ($n.Pagina) { "Start-Process '$exe' '$($n.Pagina)'" }
                      else { "Start-Process '$exe'" }
        $ultimaTexto = $ultimas[$n.Nombre]
        $ultima = if ($ultimaTexto) { ConvertTo-Version $ultimaTexto } else { $null }

        if (-not $ultima -or -not $instalada) {
            Add-Hallazgo @{
                Categoria     = 'Navegadores'
                Titulo        = "$($n.Nombre) $textoVersion instalado (sin comparación en línea)"
                Riesgo        = 'Info'
                Detalle       = "Ejecutable: $exe. No se pudo obtener la última versión publicada para compararla."
                Recomendacion = 'Verificar manualmente que el navegador esté actualizado (menú Ayuda > Acerca de).'
                Correccion    = $correccion
            }
        } elseif ($instalada -lt $ultima) {
            $atrasoMayor = $instalada.Major -lt $ultima.Major
            Add-Hallazgo @{
                Categoria     = 'Navegadores'
                Titulo        = "$($n.Nombre) desactualizado ($textoVersion; última $ultimaTexto)"
                Riesgo        = if ($atrasoMayor) { 'Alto' } else { 'Medio' }
                Detalle       = "Ejecutable: $exe. El navegador es la principal superficie de ataque web y cada versión corrige vulnerabilidades que, con frecuencia, ya se están explotando. $(if ($atrasoMayor) { 'La versión instalada pertenece a una rama anterior. Si se trata de una edición ESR o administrada por la organización, el atraso puede ser intencional.' } else { 'Si la actualización ya se descargó, basta con reiniciar el navegador.' })"
                Recomendacion = "Actualizar $($n.Nombre) y reiniciarlo."
                Correccion    = $correccion
            }
        } else {
            Add-Correcto 'Navegadores' "$($n.Nombre) actualizado ($textoVersion)"
        }
    }
}

function Test-SoftwareObsoleto {
    <#
    .SYNOPSIS
        Detecta complementos web sin soporte, el componente Internet Explorer 11 y MySQL de XAMPP sin contraseña.
    .DESCRIPTION
        Los programas se identifican por el nombre que registran en las claves de desinstalación
        de 64 bits, de 32 bits y del usuario actual.
    .NOTES
        QuickTime: alerta US-CERT TA16-105A. MSHTML: CVE-2021-40444.
        Contraseña vacía de XAMPP: CWE-1393 (Use of Default Password).
    #>
    Write-Paso 'Software web obsoleto'
    $claves = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
              'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
              'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    $programas = @(Get-ItemProperty $claves -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName })

    $obsoletos = @(
        @{ Patron = 'Adobe Flash Player'; Riesgo = 'Crítico'; Motivo = 'Sin soporte desde el 31/12/2020. Acumula vulnerabilidades de ejecución remota de código explotables desde sitios web.' }
        @{ Patron = 'Microsoft Silverlight'; Riesgo = 'Alto'; Motivo = 'Sin soporte desde el 12/10/2021.' }
        @{ Patron = 'Adobe Shockwave'; Riesgo = 'Alto'; Motivo = 'Sin soporte desde 2019.' }
        @{ Patron = '^QuickTime'; Riesgo = 'Alto'; Motivo = 'Apple discontinuó QuickTime para Windows en 2016 con vulnerabilidades sin corregir.' }
        @{ Patron = '^Java(\(TM\))? \d+ Update|^Java 8'; Riesgo = 'Medio'; Motivo = 'Java 8 de Oracle requiere actualizaciones trimestrales; versiones antiguas tienen vulnerabilidades explotables mediante applets y archivos JAR descargados.' }
    )
    $hubo = $false
    foreach ($o in $obsoletos) {
        foreach ($p in ($programas | Where-Object { $_.DisplayName -match $o.Patron })) {
            $hubo = $true
            Add-Hallazgo @{
                Categoria     = 'Software obsoleto'
                Titulo        = "$($p.DisplayName) $($p.DisplayVersion) instalado"
                Riesgo        = $o.Riesgo
                Detalle       = $o.Motivo
                Recomendacion = 'Desinstalar el programa desde Programas y características si no es imprescindible; de lo contrario, actualizarlo a la última versión disponible.'
                Correccion    = 'Start-Process appwiz.cpl'
            }
        }
    }
    if (-not $hubo) { Add-Correcto 'Software obsoleto' 'No se encontraron complementos web obsoletos (Flash, Silverlight, Shockwave, QuickTime, Java 8)' }

    # Get-WindowsOptionalFeature requiere elevación; sin ella, la verificación se omite.
    if ($script:EsAdmin) {
        $ie = Get-WindowsOptionalFeature -Online -FeatureName 'Internet-Explorer-Optional-amd64' -ErrorAction SilentlyContinue
        if ($ie -and "$($ie.State)" -eq 'Enabled') {
            Add-Hallazgo @{
                Categoria     = 'Software obsoleto'
                Titulo        = 'Componente Internet Explorer 11 habilitado'
                Riesgo        = 'Bajo'
                Detalle       = 'Internet Explorer 11 está retirado desde 2022, pero el componente opcional conserva el motor MSHTML, que todavía puede invocarse desde documentos y enlaces maliciosos.'
                Recomendacion = 'Deshabilitar la característica opcional de Internet Explorer 11. El modo IE de Edge no depende de ella. Requiere reiniciar.'
                Correccion    = "Disable-WindowsOptionalFeature -Online -FeatureName 'Internet-Explorer-Optional-amd64' -NoRestart | Out-Null"
                RequiereAdmin = $true
            }
        }
    }

    # La configuración por defecto de XAMPP (auth_type «config», usuario root y contraseña vacía)
    # da acceso a phpMyAdmin sin autenticación. Se revisa la ruta de instalación por defecto.
    $configPma = 'C:\xampp\phpMyAdmin\config.inc.php'
    if (Test-Path $configPma) {
        $txt = Get-Content $configPma -Raw -ErrorAction SilentlyContinue
        if ($txt -match "\['password'\]\s*=\s*''" -and $txt -match "\['AllowNoPassword'\]\s*=\s*true") {
            Add-Hallazgo @{
                Categoria     = 'Servidores web'
                Titulo        = 'MySQL de XAMPP con usuario root sin contraseña'
                Riesgo        = 'Alto'
                Detalle       = "La configuración de phpMyAdmin ($configPma) se conecta como root con contraseña vacía, que es el valor por defecto de XAMPP. Cualquiera que alcance phpMyAdmin o el puerto 3306 obtiene control total de las bases de datos."
                Recomendacion = 'Asignar una contraseña a root (phpMyAdmin > Cuentas de usuario, o «C:\xampp\mysql\bin\mysqladmin.exe -u root password»), cambiar auth_type a «cookie» en config.inc.php y poner AllowNoPassword en false.'
            }
        }
    }
}

function Test-ArchivoHosts {
    <#
    .SYNOPSIS
        Busca en el archivo hosts redirecciones de dominios sensibles y bloqueos de servicios de actualización.
    .DESCRIPTION
        El archivo hosts tiene prioridad sobre DNS. Una entrada que apunte un dominio bancario a una
        IP externa redirige al usuario a un sitio falso aunque escriba la URL correcta, y no deja
        rastro en el navegador. Las entradas hacia 0.0.0.0 o 127.0.0.1 son bloqueos (habituales en
        bloqueadores de publicidad) y solo se informan si afectan a servicios de actualización.
    #>
    Write-Paso 'Archivo hosts'
    $ruta = "$env:SystemRoot\System32\drivers\etc\hosts"
    $entradas = foreach ($l in (Get-Content $ruta -ErrorAction SilentlyContinue)) {
        $l = ($l -replace '#.*$', '').Trim()
        if (-not $l) { continue }
        $partes = $l -split '\s+'
        if ($partes.Count -lt 2) { continue }
        foreach ($nombre in $partes[1..($partes.Count - 1)]) { [pscustomobject]@{ IP = $partes[0]; Nombre = $nombre } }
    }
    $entradas = @($entradas)
    $sensibles = 'google|gmail|microsoft|windowsupdate|live\.com|outlook|office|apple|facebook|instagram|whatsapp|paypal|mercadopago|bank|banco|brou|itau|santander|bbva|scotiabank|ceibal|github|amazon'
    $bloqueoUpdates = 'windowsupdate|update\.microsoft|delivery\.mp\.microsoft|wdcp|defender|smartscreen|mozilla\.(org|net).*update|aus\d\.mozilla|update\.googleapis|tools\.google\.com'
    # Direcciones que no salen del equipo: 127.0.0.0/8, 0.0.0.0, ::1 y ::.
    $esLocal = '^(127\.|0\.0\.0\.0$|::1?$)'
    $correccion = "Start-Process notepad.exe -ArgumentList '$ruta' -Verb RunAs"

    $sospechosas = @($entradas | Where-Object { $_.IP -notmatch $esLocal -and $_.Nombre -match $sensibles })
    $bloqueos = @($entradas | Where-Object { $_.IP -match $esLocal -and $_.Nombre -match $bloqueoUpdates })
    $otras = @($entradas | Where-Object { $_.IP -notmatch $esLocal -and $_.Nombre -notmatch $sensibles })

    if ($sospechosas.Count) {
        Add-Hallazgo @{
            Categoria     = 'Navegación'
            Titulo        = 'Archivo hosts redirige dominios sensibles'
            Riesgo        = 'Alto'
            Detalle       = "Entradas: $(($sospechosas | ForEach-Object { "$($_.Nombre) -> $($_.IP)" }) -join '; '). Esta técnica es habitual en malware para suplantar sitios bancarios, de correo o de actualización."
            Recomendacion = 'Revisar y eliminar las entradas que no se hayan agregado de forma intencional, y analizar el equipo con el antivirus.'
            Correccion    = $correccion
            RequiereAdmin = $true
        }
    }
    if ($bloqueos.Count) {
        Add-Hallazgo @{
            Categoria     = 'Navegación'
            Titulo        = 'Archivo hosts bloquea servicios de actualización o protección'
            Riesgo        = 'Medio'
            Detalle       = "Entradas: $(($bloqueos | ForEach-Object { $_.Nombre }) -join ', '). Impiden que Windows, Defender o los navegadores reciban actualizaciones de seguridad."
            Recomendacion = 'Eliminar estas entradas salvo que exista una razón documentada para mantenerlas.'
            Correccion    = $correccion
            RequiereAdmin = $true
        }
    }
    if ($otras.Count) {
        Add-Hallazgo @{
            Categoria = 'Navegación'
            Titulo    = "Archivo hosts con $($otras.Count) redirección(es) personalizada(s)"
            Riesgo    = 'Info'
            Detalle   = "Entradas: $(($otras | Select-Object -First 15 | ForEach-Object { "$($_.Nombre) -> $($_.IP)" }) -join '; '). Verificar que todas sean conocidas."
        }
    }
    if (-not ($sospechosas.Count -or $bloqueos.Count -or $otras.Count)) {
        Add-Correcto 'Navegación' 'Archivo hosts sin redirecciones sospechosas'
    }
}

function Test-Proxy {
    <#
    .SYNOPSIS
        Detecta un proxy manual o un script de configuración automática (PAC) en la configuración del usuario.
    .DESCRIPTION
        Ambos valores determinan por dónde sale el tráfico web de los navegadores que usan la
        configuración del sistema (Chrome y Edge, entre otros). Se revisa la rama HKCU porque
        es la que aplica a la sesión del usuario actual.
    .NOTES
        MITRE ATT&CK T1557 (Adversary-in-the-Middle).
    #>
    Write-Paso 'Proxy del sistema'
    $k = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    $cfg = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
    $hubo = $false
    if ($cfg.ProxyEnable -eq 1 -and $cfg.ProxyServer) {
        $hubo = $true
        Add-Hallazgo @{
            Categoria     = 'Navegación'
            Titulo        = "Proxy manual configurado: $($cfg.ProxyServer)"
            Riesgo        = 'Medio'
            Detalle       = 'Todo el tráfico web del usuario sale a través de este proxy, que puede inspeccionarlo o modificarlo. Es habitual en redes corporativas o al usar herramientas como Burp Suite o Fiddler, pero también es una técnica frecuente en malware.'
            Recomendacion = 'Confirmar que el proxy sea conocido. En caso contrario, deshabilitarlo y analizar el equipo.'
            Correccion    = "Set-ItemProperty -Path '$k' -Name ProxyEnable -Value 0"
        }
    }
    if ($cfg.AutoConfigURL) {
        $hubo = $true
        Add-Hallazgo @{
            Categoria     = 'Navegación'
            Titulo        = 'Script de configuración automática de proxy (PAC) definido'
            Riesgo        = 'Medio'
            Detalle       = "URL del script: $($cfg.AutoConfigURL). El script define qué proxy se usa para cada sitio; uno malicioso puede desviar solo el tráfico de sitios concretos, lo que dificulta detectarlo."
            Recomendacion = 'Confirmar que la URL pertenezca a la organización. En caso contrario, eliminarla.'
            Correccion    = "Remove-ItemProperty -Path '$k' -Name AutoConfigURL"
        }
    }
    if (-not $hubo) { Add-Correcto 'Navegación' 'Sin proxy ni script PAC configurado' }
}

# ---------------------------------------------------------------------------
# Resultados
# ---------------------------------------------------------------------------

function Get-Activos {
    <#
    .SYNOPSIS
        Devuelve los hallazgos pendientes (vulnerables y no corregidos), ordenados por severidad.
    #>
    @($script:Hallazgos | Where-Object { $_.Vulnerable -and $_.Estado -ne 'Corregido' } |
        Sort-Object { $script:Orden[$_.Riesgo] }, Id)
}

function Get-NivelGlobal {
    <#
    .SYNOPSIS
        Devuelve la severidad más alta entre los hallazgos pendientes, sin contar los informativos.
    .DESCRIPTION
        Se usa la severidad máxima y no un promedio: un único hallazgo crítico basta para
        comprometer el equipo, sin importar cuántos controles se hayan superado.
    #>
    $v = @(Get-Activos | Where-Object { $_.Riesgo -ne 'Info' })
    if (-not $v.Count) { return 'Sin riesgos' }
    $v[0].Riesgo
}

function Show-Resumen {
    <#
    .SYNOPSIS
        Muestra en consola el recuento por nivel y la lista de hallazgos pendientes.
    #>
    $activos = Get-Activos
    Write-Host ''
    Write-Host '=== Resumen ===' -ForegroundColor Cyan
    foreach ($n in $script:Niveles) {
        $c = @($activos | Where-Object { $_.Riesgo -eq $n }).Count
        Write-Host ('  {0,-8} {1,3}' -f $n, $c) -ForegroundColor $script:ColorConsola[$n]
    }
    Write-Host ('  Controles superados: {0}' -f @($script:Hallazgos | Where-Object { -not $_.Vulnerable }).Count) -ForegroundColor Green
    Write-Host ('  Nivel de riesgo global: {0}' -f (Get-NivelGlobal)) -ForegroundColor White
    Write-Host ''
    foreach ($h in $activos) {
        Write-Host ('  [{0,2}] ' -f $h.Id) -NoNewline
        Write-Host ('{0,-8}' -f $h.Riesgo) -ForegroundColor $script:ColorConsola[$h.Riesgo] -NoNewline
        Write-Host " $($h.Titulo)"
    }
}

function Esc {
    <#
    .SYNOPSIS
        Codifica un texto para insertarlo en HTML.
    .DESCRIPTION
        Todo dato que procede del equipo auditado (cabeceras HTTP, entradas del archivo hosts,
        nombres de procesos) pasa por esta función antes de escribirse en el informe. Sin ella,
        un servidor malicioso podría inyectar código en el informe mediante sus propias cabeceras.
    #>
    param([string]$s)
    [System.Net.WebUtility]::HtmlEncode($s)
}

function Get-ClaseRiesgo {
    <#
    .SYNOPSIS
        Traduce un nivel de riesgo al identificador usado en las clases y variables CSS del informe.
    #>
    param([string]$Riesgo)
    switch ($Riesgo) {
        'Crítico' { 'critico' }
        'Alto'    { 'alto' }
        'Medio'   { 'medio' }
        'Bajo'    { 'bajo' }
        'Info'    { 'info' }
        default   { 'ok' }
    }
}

function Export-Informe {
    <#
    .SYNOPSIS
        Genera el informe HTML y la exportación JSON de los hallazgos.
    .DESCRIPTION
        El HTML es autocontenido (CSS y JavaScript en línea, sin recursos externos), para poder
        abrirlo sin conexión y archivarlo sin dependencias. El nombre del archivo usa la fecha del
        análisis, así que regenerarlo tras aplicar correcciones sobrescribe el mismo informe.
    .OUTPUTS
        Ruta del archivo HTML generado.
    #>
    if (-not (Test-Path $RutaInforme)) { New-Item -ItemType Directory -Path $RutaInforme -Force | Out-Null }
    $nombreBase = Join-Path $RutaInforme ('informe-{0}-{1}' -f $env:COMPUTERNAME, $script:FechaEscaneo.ToString('yyyyMMdd-HHmmss'))
    $rutaHtml = "$nombreBase.html"
    $rutaJson = "$nombreBase.json"

    $activos    = Get-Activos
    $corregidos = @($script:Hallazgos | Where-Object { $_.Estado -eq 'Corregido' })
    $correctos  = @($script:Hallazgos | Where-Object { -not $_.Vulnerable })
    $conteo = @{}
    foreach ($n in $script:Niveles) { $conteo[$n] = @($activos | Where-Object { $_.Riesgo -eq $n }).Count }
    $puntos = 0
    foreach ($a in $activos) { $puntos += $script:Peso[$a.Riesgo] }
    $nivel = Get-NivelGlobal
    $clNivel = Get-ClaseRiesgo $nivel
    $os = (Get-CimInstance Win32_OperatingSystem).Caption

    $textoNivel = switch ($nivel) {
        'Crítico' { 'Existen problemas explotables de forma directa. Se recomienda corregirlos de inmediato.' }
        'Alto'    { 'Existen debilidades importantes. Se recomienda corregirlas en los próximos días.' }
        'Medio'   { 'La configuración reduce defensas del equipo. Conviene planificar su corrección.' }
        'Bajo'    { 'Solo se detectaron mejoras de buenas prácticas.' }
        default   { 'No se detectaron riesgos en las verificaciones realizadas.' }
    }

    $css = @'
:root{--bg:#f5f6f8;--panel:#fff;--text:#1d2330;--muted:#5d6878;--border:#e2e5ea;--code:#f2f4f7;
--critico:#b42318;--alto:#c4500a;--medio:#a66a00;--bajo:#1f5fc9;--info:#667085;--ok:#067647}
@media (prefers-color-scheme:dark){:root{--bg:#0f1116;--panel:#171a22;--text:#e5e8ec;--muted:#9aa3b0;--border:#2a2f3b;--code:#11141b;
--critico:#f97066;--alto:#fb8a3c;--medio:#f5b83d;--bajo:#5aa9fa;--info:#98a2b3;--ok:#4ccb8a}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 "Segoe UI",system-ui,sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:28px 16px 56px}
h1{margin:0 0 4px;font-size:24px}
h2{font-size:17px;margin:32px 0 12px}
.meta{color:var(--muted);font-size:13px}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:16px 18px}
.global{display:grid;grid-template-columns:auto 1fr;gap:6px 24px;align-items:center;margin-top:20px}
.global .nivel{font-size:26px;font-weight:700;color:var(--c)}
.global .txt{color:var(--muted);font-size:14px}
.medidor{grid-column:1/-1;display:flex;align-items:center;gap:12px;margin-top:8px;font-size:13px;color:var(--muted)}
.barra{flex:1;height:10px;background:var(--border);border-radius:99px;overflow:hidden}
.barra span{display:block;height:100%;background:var(--c)}
.cards{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));margin-top:16px}
.card{background:var(--panel);border:1px solid var(--border);border-top:3px solid var(--c);border-radius:10px;padding:12px 14px}
.card .n{font-size:28px;font-weight:600;font-variant-numeric:tabular-nums}
.card .l{color:var(--muted);font-size:13px}
.dos{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));margin-top:12px}
.fila{display:grid;grid-template-columns:130px 1fr 28px;gap:10px;align-items:center;margin:8px 0;font-size:14px}
.fila .v{text-align:right;font-variant-numeric:tabular-nums;color:var(--muted)}
.pista{display:flex;height:12px;background:var(--border);border-radius:4px;overflow:hidden;gap:2px}
.pista span{display:block;height:100%}
.leyenda{display:flex;flex-wrap:wrap;gap:12px;font-size:12px;color:var(--muted);margin-top:8px}
.leyenda i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:4px;vertical-align:-1px}
.filtros{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px}
.filtros button{font:inherit;font-size:13px;padding:5px 12px;border-radius:99px;border:1px solid var(--border);background:var(--panel);color:var(--text);cursor:pointer}
.filtros button.on{background:var(--text);color:var(--panel);border-color:var(--text)}
details.h{background:var(--panel);border:1px solid var(--border);border-left:4px solid var(--c);border-radius:8px;margin:8px 0}
details.h summary{cursor:pointer;padding:11px 14px;display:flex;gap:10px;align-items:center;flex-wrap:wrap;list-style:none}
details.h summary::-webkit-details-marker{display:none}
details.h summary .t{flex:1;min-width:200px;font-weight:500}
.cat{font-size:12px;color:var(--muted)}
.badge{display:inline-block;min-width:62px;text-align:center;padding:2px 8px;border-radius:99px;font-size:12px;font-weight:600;color:var(--panel);background:var(--c)}
.estado{font-size:12px;padding:2px 8px;border-radius:99px;border:1px solid var(--border);color:var(--muted)}
.cuerpo{padding:0 14px 14px;font-size:14px}
.cuerpo p{margin:6px 0}
.fix{margin-top:10px}
.fixhead{display:flex;gap:10px;align-items:center;font-size:13px;margin-bottom:4px}
.tag{font-size:11px;padding:1px 7px;border-radius:99px;border:1px solid var(--alto);color:var(--alto)}
.copiar{margin-left:auto;font:inherit;font-size:12px;padding:3px 10px;border-radius:6px;border:1px solid var(--border);background:var(--panel);color:var(--text);cursor:pointer}
pre{margin:0;background:var(--code);border:1px solid var(--border);border-radius:6px;padding:10px;overflow:auto;white-space:pre-wrap;word-break:break-word;font:12.5px/1.5 Consolas,monospace}
.manual{color:var(--muted);font-style:italic}
ul.ok{list-style:none;padding:0;margin:0;columns:2 320px;font-size:14px}
ul.ok li{padding:3px 0 3px 22px;position:relative;break-inside:avoid}
ul.ok li:before{content:"\2713";position:absolute;left:2px;color:var(--ok);font-weight:700}
.niveles dt{font-weight:600;color:var(--c)}
.niveles dd{margin:0 0 8px;color:var(--muted);font-size:14px}
.vacio{color:var(--muted)}
@media (max-width:560px){.global{grid-template-columns:1fr}.fila{grid-template-columns:100px 1fr 24px}}
.validez{margin-top:24px;font-size:13px;color:var(--muted)}
@media print{
:root{--bg:#fff;--panel:#fff;--text:#111;--muted:#555;--border:#ccc;--code:#f4f4f4;
--critico:#b42318;--alto:#c4500a;--medio:#a66a00;--bajo:#1f5fc9;--info:#667085;--ok:#067647}
body{font-size:12px}
.wrap{max-width:none;padding:0}
.filtros,.copiar{display:none}
.panel,.card,details.h,.fila,ul.ok li{break-inside:avoid}
h2{break-after:avoid}
*{-webkit-print-color-adjust:exact;print-color-adjust:exact}
}
'@

    $js = @'
document.querySelectorAll('.filtros button').forEach(function(b){b.addEventListener('click',function(){
  document.querySelectorAll('.filtros button').forEach(function(x){x.classList.remove('on')});b.classList.add('on');
  var f=b.getAttribute('data-f');
  document.querySelectorAll('#lista details.h').forEach(function(d){d.style.display=(f==='todos'||d.getAttribute('data-r')===f)?'':'none'});
})});
document.querySelectorAll('.copiar').forEach(function(b){b.addEventListener('click',function(){
  var t=b.closest('.fix').querySelector('pre').innerText;
  function ok(){b.textContent='Copiado';setTimeout(function(){b.textContent='Copiar'},1500)}
  if(navigator.clipboard){navigator.clipboard.writeText(t).then(ok,function(){})}
  else{var a=document.createElement('textarea');a.value=t;document.body.appendChild(a);a.select();document.execCommand('copy');a.remove();ok()}
})});
// Al imprimir o exportar a PDF se despliegan todos los hallazgos y se quita el filtro activo;
// al terminar se restaura lo que el usuario tenía abierto.
var abiertos=[];
window.addEventListener('beforeprint',function(){
  abiertos=[];
  document.querySelectorAll('details.h').forEach(function(d){abiertos.push(d.open);d.open=true;d.setAttribute('data-display',d.style.display);d.style.display=''});
});
window.addEventListener('afterprint',function(){
  document.querySelectorAll('details.h').forEach(function(d,i){d.open=abiertos[i];d.style.display=d.getAttribute('data-display')||''});
});
'@

    $o = New-Object System.Collections.Generic.List[string]
    $o.Add('<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">')
    $o.Add("<title>Auditor Web Local - $(Esc $env:COMPUTERNAME)</title><style>$css</style></head><body><div class='wrap'>")

    $o.Add("<h1>Informe de vulnerabilidades web</h1>")
    $o.Add("<div class='meta'>Auditor de Seguridad Web Local v$($script:Version) · por FreemanHack</div>")
    $o.Add("<div class='meta'>Equipo <b>$(Esc $env:COMPUTERNAME)</b> · Usuario $(Esc $env:USERNAME) · $(Esc $os) · $($script:FechaEscaneo.ToString('dd/MM/yyyy HH:mm')) · Ejecución $(if ($script:EsAdmin) { 'como administrador' } else { 'sin privilegios de administrador' })$(if ($SinConexion) { ' · Sin comparación en línea' })</div>")

    $porcentaje = [math]::Min(100, $puntos)
    $o.Add("<div class='panel global' style='--c:var(--$clNivel)'>")
    $o.Add("<div class='meta'>Nivel de riesgo global</div><div class='meta'>&nbsp;</div>")
    $o.Add("<div class='nivel'>$(Esc $nivel)</div><div class='txt'>$(Esc $textoNivel)</div>")
    $o.Add("<div class='medidor'><span>Puntuación de exposición</span><div class='barra'><span style='width:$porcentaje%'></span></div><b style='color:var(--text)'>$puntos</b></div>")
    $o.Add('</div>')

    $o.Add("<div class='cards'>")
    foreach ($n in $script:Niveles) {
        $o.Add("<div class='card' style='--c:var(--$(Get-ClaseRiesgo $n))'><div class='n'>$($conteo[$n])</div><div class='l'>$(Esc $n)</div></div>")
    }
    $o.Add("<div class='card' style='--c:var(--ok)'><div class='n'>$($correctos.Count)</div><div class='l'>Controles superados</div></div>")
    if ($corregidos.Count) { $o.Add("<div class='card' style='--c:var(--ok)'><div class='n'>$($corregidos.Count)</div><div class='l'>Corregidos</div></div>") }
    $o.Add('</div>')

    # Distribución por nivel y por categoría
    $maxNivel = [math]::Max(1, ($script:Niveles | ForEach-Object { $conteo[$_] } | Measure-Object -Maximum).Maximum)
    $o.Add("<div class='dos'><div class='panel'><b>Distribución por nivel</b>")
    foreach ($n in $script:Niveles) {
        $ancho = [math]::Round(100 * $conteo[$n] / $maxNivel, 1)
        $o.Add("<div class='fila'><span>$(Esc $n)</span><div class='pista'><span style='width:$ancho%;background:var(--$(Get-ClaseRiesgo $n))'></span></div><span class='v'>$($conteo[$n])</span></div>")
    }
    $o.Add("</div><div class='panel'><b>Hallazgos por categoría</b>")
    $grupos = @($activos | Group-Object Categoria | Sort-Object Count -Descending)
    if ($grupos.Count) {
        $maxCat = ($grupos | Measure-Object Count -Maximum).Maximum
        foreach ($g in $grupos) {
            $segmentos = foreach ($n in $script:Niveles) {
                $c = @($g.Group | Where-Object { $_.Riesgo -eq $n }).Count
                if ($c) { "<span title='$(Esc $n): $c' style='width:$([math]::Round(100 * $c / $maxCat, 1))%;background:var(--$(Get-ClaseRiesgo $n))'></span>" }
            }
            $o.Add("<div class='fila'><span>$(Esc $g.Name)</span><div class='pista' style='background:transparent'>$($segmentos -join '')</div><span class='v'>$($g.Count)</span></div>")
        }
        $o.Add("<div class='leyenda'>$((($script:Niveles | ForEach-Object { "<span><i style='background:var(--$(Get-ClaseRiesgo $_))'></i>$(Esc $_)</span>" }) -join ''))</div>")
    } else {
        $o.Add("<p class='vacio'>Sin hallazgos.</p>")
    }
    $o.Add('</div></div>')

    # Listado de hallazgos
    $o.Add('<h2>Hallazgos</h2>')
    if ($activos.Count) {
        $o.Add("<div class='filtros'><button class='on' data-f='todos'>Todos ($($activos.Count))</button>")
        foreach ($n in $script:Niveles) {
            if ($conteo[$n]) { $o.Add("<button data-f='$(Get-ClaseRiesgo $n)'>$(Esc $n) ($($conteo[$n]))</button>") }
        }
        $o.Add("</div><div id='lista'>")
        foreach ($h in $activos) { $o.Add((Format-HallazgoHtml $h)) }
        $o.Add('</div>')
    } else {
        $o.Add("<p class='vacio'>No hay hallazgos pendientes.</p>")
    }

    if ($corregidos.Count) {
        $o.Add('<h2>Corregidos en esta sesión</h2>')
        foreach ($h in $corregidos) { $o.Add((Format-HallazgoHtml $h)) }
    }

    $o.Add('<h2>Controles superados</h2><div class=''panel''><ul class=''ok''>')
    foreach ($h in $correctos) { $o.Add("<li title='$(Esc $h.Detalle)'>$(Esc $h.Titulo)</li>") }
    $o.Add('</ul></div>')

    $o.Add("<h2>Niveles de riesgo</h2><div class='panel'><dl class='niveles'>")
    $o.Add("<dt style='--c:var(--critico)'>Crítico</dt><dd>Explotable de forma directa con impacto grave (exposición de secretos, sistema sin defensas). Corregir de inmediato.</dd>")
    $o.Add("<dt style='--c:var(--alto)'>Alto</dt><dd>Vulnerabilidad conocida o exposición significativa que un atacante puede aprovechar con poco esfuerzo. Corregir en días.</dd>")
    $o.Add("<dt style='--c:var(--medio)'>Medio</dt><dd>Debilidad que reduce las defensas o facilita otros ataques. Planificar su corrección.</dd>")
    $o.Add("<dt style='--c:var(--bajo)'>Bajo</dt><dd>Mejora de buenas prácticas con impacto limitado.</dd>")
    $o.Add("<dt style='--c:var(--info)'>Info</dt><dd>Dato para revisión manual; no constituye por sí mismo una vulnerabilidad.</dd>")
    $o.Add("</dl><p class='meta'>Puntuación de exposición: suma de pesos de los hallazgos pendientes (Crítico 10, Alto 6, Medio 3, Bajo 1). Para aplicar las correcciones, ejecutar el script sin -SoloEscaneo; también pueden copiarse los comandos y ejecutarse en una consola de PowerShell.</p></div>")

    # Un informe de seguridad describe un momento concreto: se deja constancia para que no se
    # presente como vigente meses después.
    $o.Add("<p class='validez'>Este informe refleja el estado del equipo el $($script:FechaEscaneo.ToString('dd/MM/yyyy')) a las $($script:FechaEscaneo.ToString('HH:mm')). La configuración, el software instalado y las vulnerabilidades conocidas cambian con el tiempo, por lo que se recomienda repetir la auditoría de forma periódica y después de cualquier cambio relevante en el equipo.</p>")
    $o.Add("<script>$js</script></div></body></html>")

    # UTF-8 sin BOM: es la codificación que esperan los navegadores y los analizadores JSON.
    $utf8 = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($rutaHtml, ($o -join "`n"), $utf8)
    [System.IO.File]::WriteAllText($rutaJson, ($script:Hallazgos | ConvertTo-Json -Depth 3), $utf8)
    $rutaHtml
}

function Format-HallazgoHtml {
    <#
    .SYNOPSIS
        Devuelve el bloque HTML desplegable de un hallazgo, con detalle, recomendación y corrección.
    #>
    param($h)
    $cl = Get-ClaseRiesgo $h.Riesgo
    $s = "<details class='h' data-r='$cl' style='--c:var(--$cl)'><summary><span class='badge'>$(Esc $h.Riesgo)</span><span class='t'>$(Esc $h.Titulo)</span><span class='cat'>$(Esc $h.Categoria)</span>"
    if ($h.Estado -ne 'Pendiente') { $s += "<span class='estado'>$(Esc $h.Estado)</span>" }
    $s += "</summary><div class='cuerpo'>"
    if ($h.Detalle) { $s += "<p><b>Detalle.</b> $(Esc $h.Detalle)</p>" }
    if ($h.Recomendacion) { $s += "<p><b>Recomendación.</b> $(Esc $h.Recomendacion)</p>" }
    if ($h.Correccion) {
        $adm = if ($h.RequiereAdmin) { "<span class='tag'>Requiere administrador</span>" } else { '' }
        $s += "<div class='fix'><div class='fixhead'><b>Corrección (ID $($h.Id))</b>$adm<button class='copiar' type='button'>Copiar</button></div><pre>$(Esc $h.Correccion)</pre></div>"
    } else {
        $s += "<p class='manual'>Corrección manual: aplicar la recomendación en la configuración del servicio correspondiente.</p>"
    }
    $s + '</div></details>'
}

# ---------------------------------------------------------------------------
# Corrección asistida
# ---------------------------------------------------------------------------

function New-Respaldo {
    <#
    .SYNOPSIS
        Exporta las claves de registro y la política de firewall que pueden modificar las correcciones.
    .DESCRIPTION
        Se ejecuta una vez, antes de la primera corrección. reg.exe no genera archivo para las
        claves que no existen; la política de firewall solo se exporta con privilegios de administrador.
    .OUTPUTS
        Ruta de la carpeta de respaldo.
    #>
    $dir = Join-Path $RutaInforme ('respaldo-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $claves = [ordered]@{
        'schannel'          = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'
        'dotnet'            = 'HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319'
        'dotnet-wow64'      = 'HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319'
        'dnsclient'         = 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
        'internet-settings' = 'HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    }
    foreach ($n in $claves.Keys) {
        & reg.exe export $claves[$n] (Join-Path $dir "$n.reg") /y *> $null
    }
    if ($script:EsAdmin) { & netsh.exe advfirewall export (Join-Path $dir 'firewall.wfw') *> $null }
    $dir
}

function Invoke-MenuCorreccion {
    <#
    .SYNOPSIS
        Presenta las correcciones disponibles y aplica las que el usuario selecciona y confirma.
    .DESCRIPTION
        Cada corrección muestra el código exacto y exige confirmación individual, incluso al elegir
        todas con «T». Si alguna requiere elevación y la sesión no la tiene, se ofrece relanzar el
        script como administrador.
    .OUTPUTS
        $true si se procesó al menos una corrección (para regenerar el informe); $false en otro caso.
    #>
    $corregibles = @(Get-Activos | Where-Object { $_.Correccion })
    if (-not $corregibles.Count) {
        Write-Host ''
        Write-Host 'No hay correcciones automáticas disponibles. Revisar las recomendaciones manuales en el informe.' -ForegroundColor Green
        return $false
    }

    Write-Host ''
    Write-Host '=== Correcciones disponibles ===' -ForegroundColor Cyan
    foreach ($h in $corregibles) {
        Write-Host ('  [{0,2}] ' -f $h.Id) -NoNewline
        Write-Host ('{0,-8}' -f $h.Riesgo) -ForegroundColor $script:ColorConsola[$h.Riesgo] -NoNewline
        Write-Host " $($h.Titulo)$(if ($h.RequiereAdmin) { ' [admin]' })"
    }

    if (-not $script:EsAdmin -and @($corregibles | Where-Object { $_.RequiereAdmin }).Count) {
        Write-Host ''
        Write-Host 'Las correcciones marcadas [admin] requieren privilegios de administrador.' -ForegroundColor Yellow
        $r = Read-Host '¿Reiniciar el script como administrador? (S/N)'
        if ($r -match '^[sS]') {
            $argumentos = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-NoExit', '-File', "`"$PSCommandPath`"", '-RutaInforme', "`"$RutaInforme`"")
            if ($SinConexion) { $argumentos += '-SinConexion' }
            Start-Process powershell.exe -Verb RunAs -ArgumentList $argumentos
            Write-Host 'Se abrió una nueva ventana elevada. Esta sesión finaliza.' -ForegroundColor Gray
            return $false
        }
    }

    Write-Host ''
    $entrada = (Read-Host "IDs a corregir separados por coma, 'T' para todas, Enter para salir").Trim()
    if (-not $entrada) { return $false }
    if ($entrada -match '^[tT]') { $seleccion = $corregibles }
    else {
        $ids = @($entrada -split '[,;\s]+' | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ })
        $seleccion = @($corregibles | Where-Object { $ids -contains $_.Id })
    }
    if (-not $seleccion.Count) { Write-Host 'No se seleccionó ninguna corrección válida.' -ForegroundColor Yellow; return $false }

    $respaldo = New-Respaldo
    Write-Host "Respaldo del registro y del firewall guardado en: $respaldo" -ForegroundColor Gray
    $log = Join-Path $RutaInforme 'correcciones.log'
    $requiereReinicio = $false
    $cambios = $false

    foreach ($h in $seleccion) {
        Write-Host ''
        Write-Host "[$($h.Id)] $($h.Titulo)" -ForegroundColor Cyan
        Write-Host 'Comando:' -ForegroundColor DarkGray
        Write-Host $h.Correccion -ForegroundColor Gray
        if ($h.RequiereAdmin -and -not $script:EsAdmin) {
            Write-Host 'Omitido: requiere privilegios de administrador.' -ForegroundColor Yellow
            $h.Estado = 'Omitido (requiere administrador)'
            continue
        }
        $c = Read-Host '¿Aplicar esta corrección? (S/N)'
        if ($c -notmatch '^[sS]') { $h.Estado = 'Omitido por el usuario'; continue }

        try {
            # ErrorActionPreference = 'Stop' convierte los errores no terminales de los cmdlets en
            # excepciones, para que un fallo parcial no se registre como «Corregido».
            # LASTEXITCODE cubre los ejecutables externos, como winget.
            $global:LASTEXITCODE = 0
            & ([scriptblock]::Create("`$ErrorActionPreference = 'Stop'`n" + $h.Correccion))
            if ($LASTEXITCODE) { throw "El comando finalizó con código $LASTEXITCODE." }
            $h.Estado = 'Corregido'
            $cambios = $true
            if ($h.Categoria -eq 'Cifrado' -or $h.Titulo -match 'Internet Explorer') { $requiereReinicio = $true }
            Write-Host 'Aplicado.' -ForegroundColor Green
        } catch {
            $h.Estado = "Error: $($_.Exception.Message)"
            Write-Host $h.Estado -ForegroundColor Red
        }
        Add-Content -Path $log -Encoding UTF8 -Value ('{0}  [{1}] {2} -> {3}' -f (Get-Date -Format 's'), $h.Id, $h.Titulo, $h.Estado)
    }

    Write-Host ''
    Write-Host "Registro de acciones: $log" -ForegroundColor Gray
    if ($requiereReinicio) { Write-Host 'Algunos cambios (TLS, características de Windows) se aplican después de reiniciar el equipo.' -ForegroundColor Yellow }
    Write-Host 'Para restaurar el registro, importar los archivos .reg del respaldo. Las reglas de firewall creadas se identifican con el prefijo «AuditorWebLocal -».' -ForegroundColor Gray
    $cambios -or ($seleccion.Count -gt 0)
}

# ---------------------------------------------------------------------------
# Programa principal
# ---------------------------------------------------------------------------

# PowerShell 5.1 puede no ofrecer TLS 1.2 por defecto, y las API de versiones de navegadores lo exigen.
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

Write-Host ''
Write-Host "  Auditor de Seguridad Web Local v$script:Version" -ForegroundColor White -NoNewline
Write-Host '  // by FreemanHack' -ForegroundColor DarkCyan
Write-Host "  Equipo: $env:COMPUTERNAME | Administrador: $(if ($script:EsAdmin) { 'sí' } else { 'no (algunas verificaciones y correcciones se omiten)' })" -ForegroundColor Gray
Write-Host ''

Test-SistemaOperativo
Test-Firewall
Test-Antivirus
Test-PuertosWeb
Test-ServidoresWeb
Test-ProtocolosTLS
Test-ResolucionNombres
Test-Navegadores
Test-SoftwareObsoleto
Test-ArchivoHosts
Test-Proxy

Show-Resumen
$informe = Export-Informe
Write-Host ''
Write-Host "Informe HTML: $informe" -ForegroundColor Green
if (-not $NoAbrir) { Start-Process $informe }

if (-not $SoloEscaneo) {
    if (Invoke-MenuCorreccion) {
        $informe = Export-Informe
        Write-Host "Informe actualizado: $informe" -ForegroundColor Green
        if (-not $NoAbrir) { Start-Process $informe }
    }
}
