#requires -Version 5.1
<#
.SYNOPSIS
    Prueba de extremo a extremo de las remediaciones del Auditor de Seguridad Web Local.

.DESCRIPTION
    Pensado para ejecutarse en un entorno desechable (Windows Sandbox o una máquina virtual con
    instantánea). El flujo es:

      1. Introduce configuraciones inseguras conocidas y levanta servidores web vulnerables de prueba:
         uno en todas las interfaces, otro solo en la IP de la red y otro solo en IPv6 loopback.
      2. Ejecuta el auditor y registra los hallazgos iniciales.
      3. Respalda el registro y el firewall igual que lo hace el auditor.
      4. Aplica cada remediación automatizable tal como figura en el JSON del informe.
      5. Vuelve a auditar para confirmar que cada hallazgo se resolvió.
      6. Aplica el procedimiento de reversión documentado en el README y comprueba que el equipo
         vuelve al estado inicial.

    El resultado se guarda en formato Markdown en la carpeta de salida.

    NO debe ejecutarse en un equipo real: modifica el firewall, el registro, la red y el archivo hosts.

.PARAMETER Salida
    Carpeta donde se guardan los informes de cada etapa, el respaldo y el resultado.

.PARAMETER ConfirmoEntornoDesechable
    Confirma que el equipo es una máquina virtual o un entorno desechable. No es necesario en
    Windows Sandbox, que se detecta automáticamente.

.EXAMPLE
    .\Probar-Remediaciones.ps1 -ConfirmoEntornoDesechable

.NOTES
    Autor: FreemanHack
#>
[CmdletBinding()]
param(
    [string]$Salida = (Join-Path $env:TEMP 'auditor-pruebas'),
    [switch]$ConfirmoEntornoDesechable
)

$ErrorActionPreference = 'Stop'
$auditor = Join-Path (Split-Path $PSScriptRoot -Parent) 'AuditorWebLocal.ps1'
$enSandbox = $env:USERNAME -eq 'WDAGUtilityAccount'
$esAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

New-Item -ItemType Directory -Path $Salida -Force | Out-Null
$archivoEstado = Join-Path $Salida 'estado.txt'
Set-Content -Path $archivoEstado -Value 'en curso' -Encoding UTF8

$script:Registro = New-Object System.Collections.Generic.List[string]

function Write-Registro {
    <#
    .SYNOPSIS
        Escribe una línea en consola y la agrega al resultado en Markdown.
    #>
    param([string]$Texto = '')
    Write-Host $Texto
    $script:Registro.Add($Texto)
}

function Invoke-Comando {
    <#
    .SYNOPSIS
        Ejecuta un comando externo descartando su salida.
    .DESCRIPTION
        reg.exe y netsh.exe escriben mensajes informativos en stderr. En PowerShell 5.1, con
        ErrorActionPreference = 'Stop', eso se interpreta como error; por eso se ejecutan a través
        de cmd.exe con la salida redirigida.
    #>
    param([string]$Linea)
    & cmd.exe /c "$Linea >nul 2>&1"
}

function Invoke-Auditoria {
    <#
    .SYNOPSIS
        Ejecuta el auditor en modo solo lectura y devuelve los hallazgos del JSON generado.
    #>
    param([string]$Etapa)
    $dir = Join-Path $Salida "informes-$Etapa"
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $auditor -SoloEscaneo -NoAbrir -SinConexion -RutaInforme $dir | Out-Null
    $json = Get-ChildItem -Path $dir -Filter '*.json' | Sort-Object LastWriteTime | Select-Object -Last 1
    $datos = Get-Content -Path $json.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
    @($datos | ForEach-Object { $_ })
}

function Get-TitulosVulnerables {
    <#
    .SYNOPSIS
        Devuelve los títulos de los hallazgos vulnerables, sin contar los informativos.
    #>
    param($Hallazgos)
    @($Hallazgos | Where-Object { $_.Vulnerable -and $_.Riesgo -ne 'Info' } | ForEach-Object { $_.Titulo } | Sort-Object)
}

function Get-ClavesRegistro {
    <#
    .SYNOPSIS
        Lista recursivamente las subclaves existentes bajo una ruta del registro.
    #>
    param([string]$Ruta)
    if (-not (Test-Path $Ruta)) { return @() }
    @(Get-ChildItem -Path $Ruta -Recurse | ForEach-Object { $_.PSPath })
}

try {
    if (-not ($enSandbox -or $ConfirmoEntornoDesechable)) {
        throw 'Este script modifica la configuración de seguridad del equipo. Solo debe ejecutarse en Windows Sandbox o en una máquina virtual con instantánea, indicando -ConfirmoEntornoDesechable.'
    }
    if (-not $esAdmin) { throw 'Se requieren privilegios de administrador.' }

    $os = Get-CimInstance Win32_OperatingSystem
    Write-Registro '# Resultado de la prueba de remediaciones'
    Write-Registro ''
    Write-Registro "- Fecha: $(Get-Date -Format 'dd/MM/yyyy HH:mm')"
    Write-Registro "- Sistema: $($os.Caption) (compilación $($os.BuildNumber))"
    Write-Registro "- Entorno: $(if ($enSandbox) { 'Windows Sandbox' } else { 'Máquina virtual declarada por el operador' })"
    Write-Registro ''

    # -----------------------------------------------------------------------
    # 1. Configuraciones inseguras de prueba
    # -----------------------------------------------------------------------
    $rutaSchannel = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
    $rutaInternet = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    $rutaHosts = "$env:SystemRoot\System32\drivers\etc\hosts"

    Set-NetFirewallProfile -Profile Public -Enabled False
    Set-ItemProperty -Path $rutaInternet -Name ProxyEnable -Value 1 -Type DWord
    Set-ItemProperty -Path $rutaInternet -Name ProxyServer -Value '10.255.255.1:3128'
    Set-ItemProperty -Path $rutaInternet -Name AutoConfigURL -Value 'http://10.255.255.1/proxy.pac'
    New-Item -Path "$rutaSchannel\SSL 3.0\Client" -Force | Out-Null
    New-ItemProperty -Path "$rutaSchannel\SSL 3.0\Client" -Name Enabled -Value 1 -PropertyType DWord -Force | Out-Null
    New-Item -Path "$rutaSchannel\TLS 1.2\Client" -Force | Out-Null
    New-ItemProperty -Path "$rutaSchannel\TLS 1.2\Client" -Name Enabled -Value 0 -PropertyType DWord -Force | Out-Null
    Add-Content -Path $rutaHosts -Value "`r`n1.2.3.4 www.brou.com.uy" -Encoding ASCII

    # Servidor web vulnerable de prueba en 0.0.0.0:8080: listado de directorios, CORS que refleja
    # el origen con credenciales, cookie sin atributos, versión visible, .env y .git publicados.
    $servidor = Start-Job -ScriptBlock {
        $l = New-Object System.Net.HttpListener
        $l.Prefixes.Add('http://+:8080/')
        $l.Start()
        while ($l.IsListening) {
            $ctx = $l.GetContext()
            $r = $ctx.Response
            $origen = $ctx.Request.Headers['Origin']
            if ($origen) {
                $r.AddHeader('Access-Control-Allow-Origin', $origen)
                $r.AddHeader('Access-Control-Allow-Credentials', 'true')
            }
            $r.AddHeader('X-Powered-By', 'PHP/7.2.1')
            $r.AddHeader('Set-Cookie', 'PHPSESSID=prueba; path=/')
            switch ($ctx.Request.Url.AbsolutePath) {
                '/'          { $cuerpo = '<html><head><title>Index of /</title></head><body><h1>Index of /</h1></body></html>' }
                '/.env'      { $cuerpo = "APP_KEY=base64:prueba`nDB_PASSWORD=secreto" }
                '/.git/HEAD' { $cuerpo = "ref: refs/heads/main`n" }
                default      { $cuerpo = 'No encontrado'; $r.StatusCode = 404 }
            }
            $bytes = [Text.Encoding]::UTF8.GetBytes($cuerpo)
            $r.ContentLength64 = $bytes.Length
            $r.OutputStream.Write($bytes, 0, $bytes.Length)
            $r.Close()
        }
    }
    # Servidores que no escuchan en 127.0.0.1: uno atado solo a la IP de la red y otro solo a IPv6
    # loopback. Comprueban que el auditor los sondea en la dirección donde escuchan. Se usa
    # TcpListener porque HttpListener (http.sys) escucha siempre en todas las interfaces.
    $servidorTcp = {
        param([string]$Ip, [int]$Puerto)
        $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Parse($Ip), $Puerto)
        $l.Start()
        while ($true) {
            $c = $l.AcceptTcpClient()
            $s = $c.GetStream()
            $buffer = New-Object byte[] 4096
            [void]$s.Read($buffer, 0, $buffer.Length)
            $cuerpo = '<html><head><title>Index of /</title></head><body><h1>Index of /</h1></body></html>'
            $respuesta = "HTTP/1.1 200 OK`r`nContent-Type: text/html`r`nContent-Length: $($cuerpo.Length)`r`nConnection: close`r`n`r`n$cuerpo"
            $bytes = [Text.Encoding]::ASCII.GetBytes($respuesta)
            $s.Write($bytes, 0, $bytes.Length)
            $c.Close()
        }
    }
    $ipRed = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' } | Select-Object -First 1).IPAddress
    $servidorRed = Start-Job -ScriptBlock $servidorTcp -ArgumentList $ipRed, 8081
    $servidorIpv6 = Start-Job -ScriptBlock $servidorTcp -ArgumentList '::1', 8008
    Start-Sleep -Seconds 3

    # -----------------------------------------------------------------------
    # 2. Auditoría inicial
    # -----------------------------------------------------------------------
    $inicial = Invoke-Auditoria 'inicial'
    $vulnInicial = Get-TitulosVulnerables $inicial
    Write-Registro "## 1. Hallazgos iniciales ($($vulnInicial.Count))"
    Write-Registro ''
    foreach ($t in $vulnInicial) { Write-Registro "- $t" }
    Write-Registro ''

    Write-Registro '## 2. Detección del servidor web de prueba'
    Write-Registro ''
    Write-Registro '| Vulnerabilidad introducida | Detectada |'
    Write-Registro '|---|---|'
    $esperadas = [ordered]@{
        'Servicio expuesto en 0.0.0.0:8080' = 'accesible desde la red \(puerto 8080\)'
        'Listado de directorios'            = '^Listado de directorios habilitado en http://(127\.0\.0\.1|\[::1\]):8080'
        'CORS que refleja el origen'        = '^CORS refleja cualquier origen en http://(127\.0\.0\.1|\[::1\]):8080'
        'Cookie sin atributos'              = '^Cookies sin atributos de seguridad en http://(127\.0\.0\.1|\[::1\]):8080'
        'Versión visible (X-Powered-By)'    = '^Divulgación de versión del software en http://(127\.0\.0\.1|\[::1\]):8080'
        'Cabeceras de seguridad ausentes'   = '^Cabeceras de seguridad ausentes en http://(127\.0\.0\.1|\[::1\]):8080'
        'Archivo .env publicado'            = '^Archivo \.env accesible en http://(127\.0\.0\.1|\[::1\]):8080'
        'Repositorio .git publicado'        = '^Repositorio Git publicado .* en http://(127\.0\.0\.1|\[::1\]):8080'
        'Redirección en el archivo hosts'   = '^Archivo hosts redirige dominios sensibles'
        'Servidor solo en la IP de la red (puerto 8081)' = "^Listado de directorios habilitado en http://$([regex]::Escape($ipRed)):8081"
        'Servidor solo en IPv6 loopback (puerto 8008)'   = '^Listado de directorios habilitado en http://\[::1\]:8008'
    }
    foreach ($k in $esperadas.Keys) {
        $ok = @($vulnInicial | Where-Object { $_ -match $esperadas[$k] }).Count -gt 0
        Write-Registro "| $k | $(if ($ok) { 'Sí' } else { '**No**' }) |"
    }
    Write-Registro ''

    # -----------------------------------------------------------------------
    # 3. Respaldo (mismas claves que el auditor) y registro del estado previo
    # -----------------------------------------------------------------------
    $dirRespaldo = Join-Path $Salida 'respaldo'
    New-Item -ItemType Directory -Path $dirRespaldo -Force | Out-Null
    $claves = [ordered]@{
        'schannel'          = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'
        'dotnet'            = 'HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319'
        'dotnet-wow64'      = 'HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319'
        'dnsclient'         = 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
        'internet-settings' = 'HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    }
    foreach ($n in $claves.Keys) { Invoke-Comando "reg.exe export `"$($claves[$n])`" `"$(Join-Path $dirRespaldo "$n.reg")`" /y" }
    $archivoFirewall = Join-Path $dirRespaldo 'firewall.wfw'
    Invoke-Comando "netsh.exe advfirewall export `"$archivoFirewall`""

    $clavesSchannelPrevias = Get-ClavesRegistro $rutaSchannel
    $rutasNet = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319'
    $valoresNetPrevios = @{}
    foreach ($r in $rutasNet) {
        $p = Get-ItemProperty -Path $r -ErrorAction SilentlyContinue
        $valoresNetPrevios[$r] = @('SchUseStrongCrypto', 'SystemDefaultTlsVersions' | Where-Object { $p -and $p.PSObject.Properties[$_] })
    }
    $rutaDns = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
    $dnsExistia = Test-Path $rutaDns
    $netbiosPrevio = @{}
    Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' | ForEach-Object { $netbiosPrevio[$_.Index] = $_.TcpipNetbiosOptions }

    # -----------------------------------------------------------------------
    # 4. Aplicación de las remediaciones automatizables
    # -----------------------------------------------------------------------
    # Se excluyen las que solo abren una interfaz (Start-Process) y las que dependen de winget,
    # que no está disponible en Windows Sandbox.
    $aplicables = @($inicial | Where-Object { $_.Vulnerable -and $_.Correccion -and $_.Correccion -notmatch '^\s*(Start-Process|winget)' })
    $resultados = foreach ($h in $aplicables) {
        $estado = 'Correcta'
        try { & ([scriptblock]::Create("`$ErrorActionPreference = 'Stop'`n" + $h.Correccion)) }
        catch { $estado = "Error: $($_.Exception.Message)" }
        [pscustomobject]@{ Titulo = $h.Titulo; Riesgo = $h.Riesgo; Aplicacion = $estado; Resuelto = '' }
    }
    $resultados = @($resultados)

    # -----------------------------------------------------------------------
    # 5. Nueva auditoría para confirmar la resolución
    # -----------------------------------------------------------------------
    $remediado = Invoke-Auditoria 'remediado'
    $vulnRemediado = Get-TitulosVulnerables $remediado
    foreach ($r in $resultados) {
        if ($r.Titulo -match 'accesible desde la red \(puerto (\d+)\)') {
            # El auditor evalúa la dirección de escucha, que no cambia al bloquear el puerto.
            # La remediación se verifica comprobando que la regla de bloqueo exista y esté activa.
            $regla = Get-NetFirewallRule -DisplayName "AuditorWebLocal - Bloquear TCP $($Matches[1])" -ErrorAction SilentlyContinue
            $r.Resuelto = if ($regla -and "$($regla.Enabled)" -eq 'True' -and "$($regla.Action)" -eq 'Block') { 'Sí (regla de bloqueo activa)' } else { '**No**' }
        } else {
            $r.Resuelto = if ($vulnRemediado -contains $r.Titulo) { '**No**' } else { 'Sí' }
        }
    }

    Write-Registro "## 3. Remediaciones automatizables ($($resultados.Count))"
    Write-Registro ''
    Write-Registro '| Hallazgo | Riesgo | Aplicación | Resuelto al volver a auditar |'
    Write-Registro '|---|---|---|---|'
    foreach ($r in $resultados) { Write-Registro "| $($r.Titulo) | $($r.Riesgo) | $($r.Aplicacion) | $($r.Resuelto) |" }
    Write-Registro ''
    $noAutomatizables = @($inicial | Where-Object { $_.Vulnerable -and $_.Riesgo -ne 'Info' -and -not ($aplicables -contains $_) })
    Write-Registro "Hallazgos sin remediación automatizable (manual o interactiva): $($noAutomatizables.Count)"
    foreach ($h in $noAutomatizables) { Write-Registro "- $($h.Titulo)" }
    Write-Registro ''

    # -----------------------------------------------------------------------
    # 6. Reversión según el procedimiento del README
    # -----------------------------------------------------------------------
    Get-ChildItem -Path $dirRespaldo -Filter '*.reg' | ForEach-Object { Invoke-Comando "reg.exe import `"$($_.FullName)`"" }

    # Importar un .reg no elimina lo que se creó después: se borran las claves y valores nuevos.
    $clavesNuevas = Get-ClavesRegistro $rutaSchannel | Where-Object { $clavesSchannelPrevias -notcontains $_ } |
        Sort-Object { $_.Length } -Descending
    foreach ($k in $clavesNuevas) { if (Test-Path $k) { Remove-Item -Path $k -Recurse -Force } }
    foreach ($r in $rutasNet) {
        foreach ($v in 'SchUseStrongCrypto', 'SystemDefaultTlsVersions') {
            if ($valoresNetPrevios[$r] -notcontains $v) { Remove-ItemProperty -Path $r -Name $v -ErrorAction SilentlyContinue }
        }
    }
    if (-not $dnsExistia -and (Test-Path $rutaDns)) { Remove-Item -Path $rutaDns -Recurse -Force }
    Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' | ForEach-Object {
        if ($netbiosPrevio.ContainsKey($_.Index)) {
            Invoke-CimMethod -InputObject $_ -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = [uint32]$netbiosPrevio[$_.Index] } | Out-Null
        }
    }
    Remove-NetFirewallRule -DisplayName 'AuditorWebLocal - *' -ErrorAction SilentlyContinue
    Invoke-Comando "netsh.exe advfirewall import `"$archivoFirewall`""

    $revertido = Invoke-Auditoria 'revertido'
    $vulnRevertido = Get-TitulosVulnerables $revertido
    $faltan = @($vulnInicial | Where-Object { $vulnRevertido -notcontains $_ })
    $sobran = @($vulnRevertido | Where-Object { $vulnInicial -notcontains $_ })

    Write-Registro '## 4. Reversión'
    Write-Registro ''
    if (-not $faltan.Count -and -not $sobran.Count) {
        Write-Registro 'El equipo volvió exactamente al estado inicial: los hallazgos coinciden con los de la primera auditoría.'
    } else {
        Write-Registro '**El estado final no coincide con el inicial.**'
        foreach ($t in $faltan) { Write-Registro "- No reapareció: $t" }
        foreach ($t in $sobran) { Write-Registro "- Hallazgo nuevo: $t" }
    }
    Write-Registro ''

    $fallos = @($resultados | Where-Object { $_.Aplicacion -ne 'Correcta' -or $_.Resuelto -like '*No*' }).Count
    Write-Registro '## Conclusión'
    Write-Registro ''
    Write-Registro "- Remediaciones correctas: $($resultados.Count - $fallos) de $($resultados.Count)"
    Write-Registro "- Reversión completa: $(if (-not $faltan.Count -and -not $sobran.Count) { 'Sí' } else { 'No' })"

    Stop-Job $servidor, $servidorRed, $servidorIpv6 -ErrorAction SilentlyContinue
    Set-Content -Path $archivoEstado -Value 'completado' -Encoding UTF8
} catch {
    Write-Registro ''
    Write-Registro "**Error:** $($_.Exception.Message) (línea $($_.InvocationInfo.ScriptLineNumber))"
    Set-Content -Path $archivoEstado -Value "error: $($_.Exception.Message)" -Encoding UTF8
} finally {
    $nombre = 'resultado-{0}.md' -f (Get-Date -Format 'yyyyMMdd-HHmmss')
    [IO.File]::WriteAllText((Join-Path $Salida $nombre), ($script:Registro -join "`n"), (New-Object Text.UTF8Encoding $false))
}

# Windows Sandbox se cierra solo para no dejar la ventana abierta; su contenido se descarta.
if ($enSandbox) { Start-Sleep -Seconds 5; Stop-Computer -Force }
