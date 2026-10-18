#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Collecte en une passe tout ce qui permet de diagnostiquer un echec
  d'authentification NTLM / Kerberos sur le serveur web NtlmLab.

.EXAMPLE
  .\diag.ps1 > C:\diag.txt ; notepad C:\diag.txt
#>
[CmdletBinding()]
param(
    [string]$SiteName = 'NtlmLab',
    [int]   $Port     = 8080,
    [int]   $Minutes  = 30
)

$ErrorActionPreference = 'Continue'
# NB : ne pas nommer cette fonction "H" -> collision avec l'alias h = Get-History
function Section($t) { Write-Host "`n########## $t" -ForegroundColor Cyan }

$fqdn = try {
    $cs = Get-CimInstance Win32_ComputerSystem
    "$($cs.Name).$($cs.Domain)".ToLower()
} catch { $env:COMPUTERNAME.ToLower() }

Section "1. CONTEXTE"
Write-Host "FQDN                 : $fqdn"
Write-Host "Secure channel       : $(Test-ComputerSecureChannel)"
Write-Host "LmCompatibilityLevel : $((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -EA 0).LmCompatibilityLevel)"
$msv = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -EA 0
Write-Host "NtlmMinServerSec     : 0x$('{0:X}' -f $msv.NtlmMinServerSec)"
Write-Host "NtlmMinClientSec     : 0x$('{0:X}' -f $msv.NtlmMinClientSec)"
Write-Host "RestrictReceivingNTLM: $($msv.RestrictReceivingNTLMTraffic)   (2 = BLOQUE tout NTLM entrant)"
Write-Host "RestrictSendingNTLM  : $($msv.RestrictSendingNTLMTraffic)"
Write-Host "AuditReceivingNTLM   : $($msv.AuditReceivingNTLMTraffic)"

Section "2. POLITIQUE D'AUDIT EFFECTIVE"
# Si 'Ouverture de session' est a 'No Auditing', l'absence de 4625 ne prouve rien.
auditpol /get /category:"{69979849-797A-11D9-BED3-505054503030}" 2>$null   # Logon/Logoff (GUID, insensible a la langue)
Write-Host "`n-- Audit herite d'une GPO ? (SCENoApplyLegacyAuditPolicy) --"
$lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -EA 0
Write-Host "SCENoApplyLegacyAuditPolicy : $($lsa.SCENoApplyLegacyAuditPolicy)  (1 = sous-categories prioritaires)"

Section "3. CONFIGURATION IIS EFFECTIVE"
$appcmd = "$env:windir\system32\inetsrv\appcmd.exe"
foreach ($p in @("$SiteName/", "$SiteName/ntlm", "$SiteName/kerberos")) {
    Write-Host "`n-- $p --" -ForegroundColor Yellow
    & $appcmd list config $p -section:system.webServer/security/authentication/windowsAuthentication 2>&1 |
        Where-Object { $_ -notmatch '^\s*$' }
    & $appcmd list config $p -section:system.webServer/security/authentication/anonymousAuthentication 2>&1 |
        Where-Object { $_ -match 'enabled' }
}

Section "4. TEST LOCAL DES ENDPOINTS"
foreach ($path in 'health','ntlm','kerberos') {
    $url = "http://$fqdn`:$Port/$path"
    try {
        $r = Invoke-WebRequest $url -UseDefaultCredentials -UseBasicParsing -TimeoutSec 20
        Write-Host ("{0,-12} -> HTTP {1}  ({2} octets)" -f $path, $r.StatusCode, $r.RawContentLength) -ForegroundColor Green
    } catch {
        $resp = $_.Exception.Response
        $code = if ($resp) { [int]$resp.StatusCode } else { 'n/a' }
        Write-Host ("{0,-12} -> HTTP {1}  {2}" -f $path, $code, $_.Exception.Message) -ForegroundColor Red
    }
}

Section "5. JOURNAL IIS (20 dernieres lignes)"
# On cible le journal DU SITE NtlmLab (W3SVC<id>), pas celui du Default Web Site.
Import-Module WebAdministration -EA 0
$siteId = (Get-Website -Name $SiteName -EA 0).ID
Write-Host "Site '$SiteName' = W3SVC$siteId"
$log = Get-ChildItem "C:\inetpub\logs\LogFiles\W3SVC$siteId" -Filter *.log -EA 0 |
       Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($log) {
    Write-Host "Fichier : $($log.FullName)"
    Write-Host "Rappel : sc-status sc-substatus sc-win32-status"
    Write-Host "         404 0 2 = gestionnaire de fichiers statiques (fichier absent)"
    Write-Host "         404 0 0 = l'application ASP.NET Core n'a pas trouve la route"
    Write-Host "         401 1   = echec d'ouverture de session"
    Write-Host "         401 2   = refus du a la configuration du serveur"
    Get-Content $log.FullName -Tail 25
} else { Write-Host "aucun journal pour W3SVC$siteId (le site n'a peut-etre jamais recu de requete)" }

Section "6. HTTPERR (rejets au niveau HTTP.sys)"
$he = Get-ChildItem "$env:windir\System32\LogFiles\HTTPERR" -Filter *.log -EA 0 |
      Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($he) { Get-Content $he.FullName -Tail 10 } else { Write-Host 'aucun' }

Section "7. EVENEMENTS SECURITE ($Minutes dernieres minutes)"
$ev = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625,4776; StartTime=(Get-Date).AddMinutes(-$Minutes)} -EA 0
if (-not $ev) { Write-Host 'AUCUN evenement 4624/4625/4776 -> audit probablement inactif' -ForegroundColor Red }
foreach ($e in $ev | Select-Object -First 10) {
    $x = [xml]$e.ToXml(); $d = @{}
    foreach ($n in $x.Event.EventData.Data) { if ($n.Name) { $d[$n.Name] = $n.'#text' } }
    Write-Host ("{0}  evt {1}  compte={2}\{3}  pkg={4}/{5}  type={6}  status={7}/{8}  src={9}" -f `
        $e.TimeCreated.ToString('HH:mm:ss'), $e.Id,
        $d['TargetDomainName'], $d['TargetUserName'],
        $d['AuthenticationPackageName'], $d['LmPackageName'],
        $d['LogonType'], $d['Status'], $d['SubStatus'], $d['IpAddress'])
}

Section "8. JOURNAL NTLM OPERATIONAL"
$n = Get-WinEvent -LogName 'Microsoft-Windows-NTLM/Operational' -MaxEvents 10 -EA 0
if (-not $n) { Write-Host 'aucun evenement' } else {
    $n | ForEach-Object { Write-Host ("{0}  evt {1}  {2}" -f $_.TimeCreated.ToString('HH:mm:ss'), $_.Id, ($_.Message -replace '\s+',' ')) }
}

Section "9. JOURNAL APPLICATIF (stdout)"
$s = Get-ChildItem C:\inetpub\NtlmLab\logs -Filter stdout*.log -EA 0 |
     Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($s) { Get-Content $s.FullName -Tail 20 } else { Write-Host 'aucun fichier stdout' }

Write-Host "`n########## FIN`n" -ForegroundColor Cyan
