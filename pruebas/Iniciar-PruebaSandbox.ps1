#requires -Version 5.1
<#
.SYNOPSIS
    Ejecuta Probar-Remediaciones.ps1 dentro de Windows Sandbox.

.DESCRIPTION
    Genera un archivo de configuración .wsb que monta el proyecto en modo solo lectura y una
    carpeta de resultados con escritura, y abre Windows Sandbox. La prueba se ejecuta sola al
    iniciar sesión y la ventana se cierra al terminar. Todos los cambios ocurren dentro del
    entorno aislado y se descartan al cerrarlo.

    Requiere Windows 10/11 Pro, Enterprise o Education con la característica opcional
    «Windows Sandbox» habilitada.

.PARAMETER Salida
    Carpeta del equipo anfitrión donde se guardan los resultados. Por defecto: .\resultados.

.EXAMPLE
    .\Iniciar-PruebaSandbox.ps1

.NOTES
    Autor: FreemanHack
#>
[CmdletBinding()]
param(
    [string]$Salida = (Join-Path $PSScriptRoot 'resultados')
)

$ejecutable = "$env:SystemRoot\System32\WindowsSandbox.exe"
if (-not (Test-Path $ejecutable)) {
    throw 'Windows Sandbox no está habilitado. Puede activarse con: Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM'
}

$proyecto = Split-Path $PSScriptRoot -Parent
New-Item -ItemType Directory -Path $Salida -Force | Out-Null
$Salida = (Resolve-Path $Salida).Path

function Esc { param([string]$s) [System.Security.SecurityElement]::Escape($s) }

$wsb = @"
<Configuration>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>$(Esc $proyecto)</HostFolder>
      <SandboxFolder>C:\Auditor</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
    <MappedFolder>
      <HostFolder>$(Esc $Salida)</HostFolder>
      <SandboxFolder>C:\Salida</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Auditor\pruebas\Probar-Remediaciones.ps1 -Salida C:\Salida</Command>
  </LogonCommand>
</Configuration>
"@

$rutaWsb = Join-Path $env:TEMP 'AuditorWebLocal-prueba.wsb'
[IO.File]::WriteAllText($rutaWsb, $wsb, (New-Object Text.UTF8Encoding $false))
Start-Process -FilePath $rutaWsb
Write-Host "Windows Sandbox iniciado. Los resultados se guardarán en: $Salida"
