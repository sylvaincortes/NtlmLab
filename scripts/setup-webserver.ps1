#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Prepare un Windows Server (membre du domaine) pour heberger NtlmLab :
  roles IIS, deverrouillage des sections d'authentification, site + pool,
  politique d'audit, forcage NTLMv2 et audit NTLM.

.EXAMPLE
  .\setup-webserver.ps1 -PhysicalPath C:\inetpub\NtlmLab -Port 8080
#>
[CmdletBinding()]
param(
    [string]$SiteName     = 'NtlmLab',
    [string]$AppPoolName  = 'NtlmLab',
    [string]$PhysicalPath = 'C:\inetpub\NtlmLab',
    [int]   $Port         = 8080,
    # Mettre a $false si vous voulez conserver le LmCompatibilityLevel existant
    [bool]  $ForceNtlmV2Only = $true
)

$ErrorActionPreference = 'Stop'
$appcmd = Join-Path $env:windir 'system32\inetsrv\appcmd.exe'

function Step($m) { Write-Host "`n=== $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "    [ok] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "    [! ] $m" -ForegroundColor Yellow }

# ---------------------------------------------------------------- 1. Roles IIS
Step '1. Installation des roles IIS'
$features = @(
    'Web-Server','Web-Common-Http','Web-Default-Doc','Web-Static-Content',
    'Web-Http-Errors','Web-Http-Logging','Web-Windows-Auth',
    'Web-Filtering','Web-Mgmt-Console','Web-Scripting-Tools'
)
foreach ($f in $features) {
    $s = Get-WindowsFeature -Name $f -ErrorAction SilentlyContinue
    if ($s -and -not $s.Installed) { Install-WindowsFeature -Name $f | Out-Null; Ok "installe : $f" }
}
Ok 'roles IIS en place'

Import-Module WebAdministration

# ------------------------------------------- 2. Hosting Bundle ASP.NET Core
Step '2. Verification du ASP.NET Core Hosting Bundle'
$ancm = Get-WebGlobalModule -Name 'AspNetCoreModuleV2' -ErrorAction SilentlyContinue
if (-not $ancm) {
    Warn 'AspNetCoreModuleV2 absent.'
    Warn 'Installez "ASP.NET Core 8 Hosting Bundle" :'
    Warn '  https://dotnet.microsoft.com/download/dotnet/8.0  (section "Hosting Bundle")'
    Warn 'Puis relancez : iisreset'
} else { Ok 'AspNetCoreModuleV2 present' }

# ------------------------- 3. Deverrouillage des sections d'authentification
# Indispensable : sans cela les blocs <location> du web.config sont refuses (500.19).
Step '3. Deverrouillage des sections d''authentification IIS'
& $appcmd unlock config /section:system.webServer/security/authentication/windowsAuthentication  | Out-Null
& $appcmd unlock config /section:system.webServer/security/authentication/anonymousAuthentication | Out-Null
Ok 'windowsAuthentication et anonymousAuthentication deverrouillees'

# ------------------------------------------------------- 4. Pool + site IIS
Step '4. Creation du pool et du site'
New-Item -ItemType Directory -Path $PhysicalPath -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $PhysicalPath 'logs') -Force | Out-Null

if (Test-Path "IIS:\AppPools\$AppPoolName") { Remove-WebAppPool -Name $AppPoolName }
New-WebAppPool -Name $AppPoolName | Out-Null
Set-ItemProperty "IIS:\AppPools\$AppPoolName" -Name managedRuntimeVersion -Value ''   # No Managed Code
Set-ItemProperty "IIS:\AppPools\$AppPoolName" -Name startMode              -Value 'AlwaysRunning'
Ok "pool '$AppPoolName' cree (ApplicationPoolIdentity)"

if (Get-Website -Name $SiteName -ErrorAction SilentlyContinue) { Remove-Website -Name $SiteName }
New-Website -Name $SiteName -Port $Port -PhysicalPath $PhysicalPath -ApplicationPool $AppPoolName | Out-Null
Ok "site '$SiteName' cree sur le port $Port"

# Droits de lecture pour l'identite du pool
icacls $PhysicalPath /grant "IIS AppPool\${AppPoolName}:(OI)(CI)(RX)" /T | Out-Null
icacls (Join-Path $PhysicalPath 'logs') /grant "IIS AppPool\${AppPoolName}:(OI)(CI)(M)" /T | Out-Null
Ok 'ACL positionnees'

# --------------------------- 5. Lecture du journal Securite par l'application
Step '5. Autorisation de lecture du journal Securite'
try {
    net localgroup "Event Log Readers" "IIS APPPOOL\$AppPoolName" /add 2>&1 | Out-Null
    Ok "IIS APPPOOL\$AppPoolName ajoute aux 'Event Log Readers'"
} catch {
    Warn "Ajout impossible. Sinon : basculez le pool sur un compte de service"
    Warn "dedie et ajoutez-le au groupe 'Lecteurs des journaux d'evenements'."
}
Warn 'Le changement de groupe ne prend effet qu''apres recyclage du pool (fait en fin de script).'

# ------------------------------------------------ 6. Politique d'audit locale
Step '6. Politique d''audit (ouverture de session)'
auditpol /set /subcategory:"Logon"             /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Logoff"            /success:enable                  | Out-Null
auditpol /set /subcategory:"Special Logon"     /success:enable                  | Out-Null
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable | Out-Null
Ok '4624 / 4625 / 4634 / 4672 actives'

# Journal Securite plus grand : un lab genere beaucoup d'evenements
wevtutil sl Security /ms:536870912 2>$null
Ok 'journal Securite porte a 512 Mo'

# ----------------------------------------------------- 7. Audit NTLM entrant
Step '7. Audit du trafic NTLM entrant (evenement 8003)'
$msv = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
New-Item -Path $msv -Force | Out-Null
# 2 = auditer tout le trafic NTLM entrant
Set-ItemProperty -Path $msv -Name 'AuditReceivingNTLMTraffic' -Value 2 -Type DWord
# 1 = auditer le NTLM sortant de cette machine (evenement 8001)
Set-ItemProperty -Path $msv -Name 'RestrictSendingNTLMTraffic' -Value 1 -Type DWord
wevtutil sl Microsoft-Windows-NTLM/Operational /e:true 2>$null
wevtutil sl Microsoft-Windows-NTLM/Operational /ms:67108864 2>$null
Ok 'audit NTLM entrant active, journal NTLM/Operational actif'

# --------------------------------------------------- 8. Forcage de NTLMv2
Step '8. Niveau d''authentification LAN Manager'
$lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
if ($ForceNtlmV2Only) {
    # 5 = n'envoyer que des reponses NTLMv2, refuser LM et NTLMv1
    Set-ItemProperty -Path $lsa -Name 'LmCompatibilityLevel' -Value 5 -Type DWord
    Ok 'LmCompatibilityLevel = 5 (NTLMv2 uniquement, LM/NTLMv1 refuses)'
} else {
    Warn 'LmCompatibilityLevel laisse inchange'
}
# Securite de session NTLM : exiger NTLMv2 et le chiffrement 128 bits
$msvSec = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
Set-ItemProperty -Path $msvSec -Name 'NtlmMinServerSec' -Value 0x20080000 -Type DWord
Set-ItemProperty -Path $msvSec -Name 'NtlmMinClientSec' -Value 0x20080000 -Type DWord
Ok 'NtlmMinServerSec / NtlmMinClientSec : NTLMv2 + 128 bits exiges'

# ------------------------------------------------------------ 9. Pare-feu
Step '9. Regle de pare-feu'
if (-not (Get-NetFirewallRule -DisplayName "NtlmLab HTTP $Port" -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName "NtlmLab HTTP $Port" -Direction Inbound `
        -Protocol TCP -LocalPort $Port -Action Allow -Profile Domain | Out-Null
}
Ok "port $Port ouvert (profil Domaine)"

# ------------------------------------------------------------ 10. Redemarrage
Step '10. Redemarrage d''IIS'
iisreset /restart | Out-Null
Ok 'IIS redemarre'

$cs = Get-CimInstance Win32_ComputerSystem
if ($cs.PartOfDomain -and $cs.Domain) {
    $fqdn = "$($cs.Name).$($cs.Domain)".ToLower()
} else {
    $fqdn = $env:COMPUTERNAME.ToLower()
    Warn 'Cette machine n''est PAS jointe a un domaine : le lab ne fonctionnera pas.'
}
Write-Host "`n--------------------------------------------------------------" -ForegroundColor Cyan
Write-Host " Serveur pret." -ForegroundColor Cyan
Write-Host " 1. Publiez l'application dans : $PhysicalPath"
Write-Host "    dotnet publish -c Release -o $PhysicalPath"
Write-Host " 2. Depuis un POSTE CLIENT du domaine, ouvrez :"
Write-Host "      http://$fqdn`:$Port/" -ForegroundColor White
Write-Host "    (le FQDN est indispensable pour que Kerberos fonctionne)"
Write-Host " 3. Suivez les evenements en direct : .\watch-events.ps1"
Write-Host " ATTENTION : LmCompatibilityLevel=5 refuse NTLMv1. Verifiez qu'aucun"
Write-Host "   systeme legacy n'en depend avant de laisser ce reglage en place."
Write-Host "--------------------------------------------------------------`n" -ForegroundColor Cyan
