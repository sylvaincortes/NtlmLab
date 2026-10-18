#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Installe tout ce qu'il faut pour compiler et heberger NtlmLab :
    - .NET 8 SDK                (compilation : dotnet publish)
    - ASP.NET Core 8 Hosting Bundle (module IIS AspNetCoreModuleV2 + runtime)
  Puis publie l'application si on lui donne -Publish.

.DESCRIPTION
  Essaie winget en premier, bascule sur un telechargement direct depuis
  les liens officiels Microsoft si winget est absent ou echoue.
  Le script est idempotent : il ne reinstalle pas ce qui est deja present.

.EXAMPLE
  .\install-dotnet.ps1
  .\install-dotnet.ps1 -Publish
  .\install-dotnet.ps1 -Publish -SourcePath C:\_DATA\NtlmLab -PhysicalPath C:\inetpub\NtlmLab
#>
[CmdletBinding()]
param(
    # Enchaine directement sur "dotnet publish" apres l'installation
    [switch]$Publish,
    # Dossier contenant NtlmLab.csproj
    [string]$SourcePath   = (Split-Path -Parent $PSScriptRoot),
    # Dossier physique du site IIS
    [string]$PhysicalPath = 'C:\inetpub\NtlmLab',
    # Nom du pool a arreter/redemarrer pendant la publication
    [string]$AppPoolName  = 'NtlmLab',
    # Forcer la reinstallation meme si deja present
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Step($m) { Write-Host "`n=== $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "    [ok] $m"   -ForegroundColor Green }
function Warn($m) { Write-Host "    [! ] $m"   -ForegroundColor Yellow }
function Fail($m) { Write-Host "    [X ] $m"   -ForegroundColor Red }

$tmp = Join-Path $env:TEMP "ntlmlab-dotnet-$(Get-Date -Format yyyyMMddHHmmss)"
New-Item -ItemType Directory -Path $tmp -Force | Out-Null

# --------------------------------------------------------------- utilitaires
function Get-ServerFqdn {
    # USERDNSDOMAIN n'existe que pour une session ouverte avec un compte de
    # domaine. On interroge donc la machine elle-meme.
    try {
        $cs = Get-CimInstance Win32_ComputerSystem
        if ($cs.PartOfDomain -and $cs.Domain) {
            return "$($cs.Name).$($cs.Domain)".ToLower()
        }
        Warn "Cette machine n'est PAS jointe a un domaine (PartOfDomain = False)."
        Warn "Le lab NTLM/Kerberos ne peut pas fonctionner en l'etat."
        return $env:COMPUTERNAME.ToLower()
    } catch {
        try   { return ([System.Net.Dns]::GetHostEntry($env:COMPUTERNAME)).HostName.ToLower() }
        catch { return $env:COMPUTERNAME.ToLower() }
    }
}

function Refresh-Path {
    $m = [Environment]::GetEnvironmentVariable('Path','Machine')
    $u = [Environment]::GetEnvironmentVariable('Path','User')
    $env:Path = "$m;$u"
}

function Test-Sdk8 {
    Refresh-Path
    $exe = Get-Command dotnet -ErrorAction SilentlyContinue
    if (-not $exe) { return $false }
    try   { return [bool]((& dotnet --list-sdks 2>$null) -match '^8\.') }
    catch { return $false }
}

function Test-Ancm {
    try {
        Import-Module WebAdministration -ErrorAction SilentlyContinue
        if (Get-WebGlobalModule -Name 'AspNetCoreModuleV2' -ErrorAction SilentlyContinue) { return $true }
    } catch { }
    # Repli : presence du fichier du module
    return (Test-Path "$env:ProgramFiles\IIS\Asp.Net Core Module\V2\aspnetcorev2.dll")
}

function Invoke-Winget {
    param([string]$Id)
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) { return $false }
    Write-Host "    winget install $Id ..." -ForegroundColor DarkGray
    $p = Start-Process -FilePath winget -Wait -PassThru -NoNewWindow -ArgumentList @(
        'install','--id',$Id,'--exact','--silent',
        '--accept-source-agreements','--accept-package-agreements',
        '--disable-interactivity'
    )
    # On ne se fie pas au code de retour de winget (codes variables selon les
    # versions) : la verification reelle est faite par Test-Sdk8 / Test-Ancm.
    if ($p.ExitCode -ne 0) { Warn "winget a renvoye le code $($p.ExitCode)" }
    return ($p.ExitCode -eq 0)
}

function Install-FromUrl {
    param([string]$Url, [string]$FileName, [string]$Label)
    $out = Join-Path $tmp $FileName
    Write-Host "    telechargement : $Url" -ForegroundColor DarkGray
    try {
        Invoke-WebRequest -Uri $Url -OutFile $out -UseBasicParsing -TimeoutSec 600
    } catch {
        Fail "telechargement de $Label impossible : $($_.Exception.Message)"
        return $false
    }
    $size = [math]::Round((Get-Item $out).Length / 1MB, 1)
    if ($size -lt 5) { Fail "fichier recupere trop petit ($size Mo), lien probablement invalide"; return $false }
    Ok "telecharge ($size Mo), installation silencieuse en cours..."
    $p = Start-Process -FilePath $out -Wait -PassThru -ArgumentList '/install','/quiet','/norestart'
    # 3010 = succes, redemarrage conseille
    if ($p.ExitCode -in 0,3010) { return $true }
    Fail "l'installeur $Label a renvoye le code $($p.ExitCode)"
    return $false
}

Write-Host "`n#############################################################" -ForegroundColor Cyan
Write-Host " NtlmLab - installation de la chaine .NET 8" -ForegroundColor Cyan
Write-Host "#############################################################" -ForegroundColor Cyan

# ------------------------------------------------------------------ 1. SDK 8
Step '1. .NET 8 SDK (compilation)'
if ((Test-Sdk8) -and -not $Force) {
    Ok "deja present : $((& dotnet --list-sdks) -match '^8\.' | Select-Object -First 1)"
} else {
    $done = Invoke-Winget -Id 'Microsoft.DotNet.SDK.8'
    if ($done) { Refresh-Path }
    if (-not (Test-Sdk8)) {
        Warn 'winget indisponible ou insuffisant, bascule sur le telechargement direct'
        $done = Install-FromUrl -Url 'https://aka.ms/dotnet/8.0/dotnet-sdk-win-x64.exe' `
                                -FileName 'dotnet-sdk-8-win-x64.exe' -Label 'SDK .NET 8'
        Refresh-Path
    }
    if (Test-Sdk8) { Ok '.NET 8 SDK installe' } else { Fail '.NET 8 SDK toujours absent' }
}

# ------------------------------------------------- 2. ASP.NET Core Hosting Bundle
Step '2. ASP.NET Core 8 Hosting Bundle (module IIS)'
if ((Test-Ancm) -and -not $Force) {
    Ok 'AspNetCoreModuleV2 deja present'
} else {
    $done = Invoke-Winget -Id 'Microsoft.DotNet.HostingBundle.8'
    if (-not (Test-Ancm)) {
        Warn 'winget indisponible ou insuffisant, bascule sur le telechargement direct'
        $done = Install-FromUrl -Url 'https://aka.ms/dotnet/8.0/dotnet-hosting-win.exe' `
                                -FileName 'dotnet-hosting-8-win.exe' -Label 'Hosting Bundle'
    }
    Step '   Redemarrage d''IIS (necessaire pour charger le module)'
    iisreset /restart | Out-Null
    Start-Sleep -Seconds 2
    if (Test-Ancm) { Ok 'Hosting Bundle installe, AspNetCoreModuleV2 charge' }
    else           { Fail 'AspNetCoreModuleV2 introuvable apres installation' }
}

# ------------------------------------------------------------- 3. Publication
if ($Publish) {
    Step '3. Publication de l''application'

    $csproj = Join-Path $SourcePath 'NtlmLab.csproj'
    if (-not (Test-Path $csproj)) {
        Fail "NtlmLab.csproj introuvable dans $SourcePath"
        Warn 'Relancez avec -SourcePath <dossier contenant NtlmLab.csproj>'
    }
    elseif (-not (Test-Sdk8)) {
        Fail 'SDK absent, publication impossible'
    }
    else {
        # Liberer les DLL si le site tourne deja
        Import-Module WebAdministration -ErrorAction SilentlyContinue
        if (Get-ChildItem IIS:\AppPools -ErrorAction SilentlyContinue |
            Where-Object Name -eq $AppPoolName) {
            if ((Get-WebAppPoolState -Name $AppPoolName).Value -eq 'Started') {
                Stop-WebAppPool -Name $AppPoolName
                Start-Sleep -Seconds 3
                Ok "pool '$AppPoolName' arrete"
            }
        }

        New-Item -ItemType Directory -Path $PhysicalPath -Force | Out-Null
        Write-Host "    dotnet publish -c Release -o $PhysicalPath" -ForegroundColor DarkGray
        Push-Location $SourcePath
        try {
            & dotnet publish $csproj -c Release -o $PhysicalPath --nologo
            $code = $LASTEXITCODE
        } finally { Pop-Location }

        if ($code -eq 0 -and (Test-Path (Join-Path $PhysicalPath 'NtlmLab.exe'))) {
            Ok 'application publiee'
            New-Item -ItemType Directory -Path (Join-Path $PhysicalPath 'logs') -Force | Out-Null
            icacls $PhysicalPath /grant "IIS AppPool\${AppPoolName}:(OI)(CI)(RX)" /T | Out-Null
            icacls (Join-Path $PhysicalPath 'logs') /grant "IIS AppPool\${AppPoolName}:(OI)(CI)(M)" /T | Out-Null
            Ok 'ACL remises en place'
        } else {
            Fail "echec de la compilation (code $code)"
            Warn 'Si le serveur n''a pas d''acces a nuget.org, compilez sur une autre'
            Warn "machine puis copiez le contenu de publish\ vers $PhysicalPath"
        }

        if (Get-ChildItem IIS:\AppPools -ErrorAction SilentlyContinue |
            Where-Object Name -eq $AppPoolName) {
            Start-WebAppPool -Name $AppPoolName -ErrorAction SilentlyContinue
            Ok "pool '$AppPoolName' redemarre"
        }
    }
}

# ------------------------------------------------------------------ 4. Bilan
Step 'Bilan'
$sdkOk  = Test-Sdk8
$ancmOk = Test-Ancm
$appOk  = Test-Path (Join-Path $PhysicalPath 'NtlmLab.exe')

Write-Host ("    SDK .NET 8            : {0}" -f $(if($sdkOk){'OK'}else{'MANQUANT'})) -ForegroundColor $(if($sdkOk){'Green'}else{'Red'})
Write-Host ("    AspNetCoreModuleV2    : {0}" -f $(if($ancmOk){'OK'}else{'MANQUANT'})) -ForegroundColor $(if($ancmOk){'Green'}else{'Red'})
Write-Host ("    Application publiee   : {0}" -f $(if($appOk){'OK'}else{'NON'}))      -ForegroundColor $(if($appOk){'Green'}else{'Yellow'})

Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue

if ($sdkOk -and $ancmOk -and $appOk) {
    Write-Host "`n    Test local :" -ForegroundColor Cyan
    Write-Host "      Invoke-RestMethod http://localhost:8080/health"
    $fqdn = Get-ServerFqdn
    Write-Host "    Puis depuis un poste client du domaine :" -ForegroundColor Cyan
    Write-Host "      http://$fqdn`:8080/`n"
} elseif ($sdkOk -and $ancmOk) {
    Write-Host "`n    Relancez avec -Publish pour compiler et deployer l'application.`n" -ForegroundColor Yellow
} else {
    Write-Host "`n    Installation incomplete. Verifiez l'acces Internet du serveur" -ForegroundColor Yellow
    Write-Host "    (proxy, pare-feu) puis relancez le script.`n" -ForegroundColor Yellow
}
