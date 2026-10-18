<#
.SYNOPSIS
  Affiche en direct les evenements d'authentification generes par le lab.
  A lancer sur le serveur web (ou sur le DC avec -OnDc).

.EXAMPLE
  .\watch-events.ps1
  .\watch-events.ps1 -OnDc
  .\watch-events.ps1 -User jdupont
#>
[CmdletBinding()]
param(
    [switch]$OnDc,
    [string]$User,                 # filtre sur un nom de compte
    [int]$IntervalSeconds = 2
)

$ErrorActionPreference = 'Continue'
$last = (Get-Date).AddSeconds(-5)

function Color($proto) {
    switch -Wildcard ($proto) {
        '*NTLM*'     { 'Yellow' }
        '*Kerberos*' { 'Cyan' }
        default      { 'Gray' }
    }
}

Write-Host "Surveillance demarree. Ctrl+C pour arreter." -ForegroundColor Green
Write-Host ("{0,-12} {1,-6} {2,-22} {3}" -f 'HEURE','ID','PROTOCOLE','DETAIL') -ForegroundColor DarkGray
Write-Host ('-' * 110) -ForegroundColor DarkGray

while ($true) {
    $now = Get-Date
    $events = @()

    # --- Journal Securite ---
    $ids = if ($OnDc) { 4624,4625,4768,4769,4771,4776 } else { 4624,4625,4648 }
    $events += Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = $ids
        StartTime = $last
    } -ErrorAction SilentlyContinue

    # --- Journal NTLM operationnel ---
    #   4020 / 4021 : client, NTLM sortant (info / avertissement)
    #   4022 / 4023 : serveur de ressource, NTLM entrant
    #   4015        : NTLM sortant bloque cote client
    #   8001-8004   : equivalents sur Windows Server 2022 et anterieurs
    $events += Get-WinEvent -FilterHashtable @{
        LogName   = 'Microsoft-Windows-NTLM/Operational'
        StartTime = $last
    } -ErrorAction SilentlyContinue

    # --- Journal Security-Netlogon : evenements NTLM vus par le DC ---
    #   4032 / 4033 : validation d'un compte du propre domaine du DC
    #   4030 / 4031 : authentification traversant une approbation
    $events += Get-WinEvent -FilterHashtable @{
        LogName   = 'Microsoft-Windows-Security-Netlogon/Operational'
        StartTime = $last
    } -ErrorAction SilentlyContinue

    foreach ($e in ($events | Sort-Object TimeCreated)) {
        $x = [xml]$e.ToXml()
        $d = @{}
        foreach ($n in $x.Event.EventData.Data) { if ($n.Name) { $d[$n.Name] = $n.'#text' } }

        $account = $d['TargetUserName']; if (-not $account) { $account = $d['UserName'] }
        if ($User -and $account -notlike "*$User*") { continue }
        # On ignore le bruit des comptes machine et SYSTEM
        if ($account -match '\$$' -or $account -in @('SYSTEM','ANONYMOUS LOGON','-')) { continue }

        switch ($e.Id) {
            4624 {
                $proto = $d['AuthenticationPackageName']
                if ($d['LmPackageName'] -and $d['LmPackageName'] -ne '-') { $proto += " / $($d['LmPackageName'])" }
                $detail = "type=$($d['LogonType']) proc=$($d['LogonProcessName']) compte=$($d['TargetDomainName'])\$account src=$($d['IpAddress']) logonId=$($d['TargetLogonId']) cle=$($d['KeyLength'])"
            }
            4625 { $proto = $d['AuthenticationPackageName']; $detail = "ECHEC compte=$account status=$($d['Status']) sub=$($d['SubStatus']) src=$($d['IpAddress'])" }
            4648 { $proto = 'Explicit'; $detail = "cible=$($d['TargetUserName']) serveur=$($d['TargetServerName'])" }
            4768 { $proto = 'Kerberos TGT'; $detail = "compte=$account status=$($d['Status']) src=$($d['IpAddress'])" }
            4769 { $proto = 'Kerberos TGS'; $detail = "spn=$($d['ServiceName']) compte=$($d['TargetUserName']) status=$($d['Status'])" }
            4771 { $proto = 'Kerberos ECHEC'; $detail = "compte=$account code=$($d['Status'])" }
            4776 { $proto = 'NTLM (validation DC)'; $detail = "compte=$($d['TargetUserName']) station=$($d['Workstation']) erreur=$($d['Status'])" }
            # Windows Server 2025 / Windows 11 : nouveaux evenements detailles
            { $_ -in 4015,4020,4021,4022,4023,4030,4031,4032,4033 } {
                $proto = switch ($e.Id) {
                    4015 { 'NTLM BLOQUE (client)' }
                    4020 { 'NTLM sortant' }
                    4021 { 'NTLM sortant (alerte)' }
                    4022 { 'NTLM entrant' }
                    4023 { 'NTLM entrant ECHEC' }
                    4030 { 'NTLM DC inter-domaines' }
                    4031 { 'NTLM DC inter-domaines ECHEC' }
                    4032 { 'NTLM DC validation' }
                    4033 { 'NTLM DC validation ECHEC' }
                }
                $m = $e.Message -replace '\s+',' '
                $ver = if ($m -match 'NTLM Version:\s*(\S+)')    { $matches[1] } else { '?' }
                $usr = if ($m -match 'Username:\s*(\S+)')         { $matches[1] } else { '?' }
                $dom = if ($m -match 'Domain:\s*(\S+)')           { $matches[1] } else { '?' }
                $ip  = if ($m -match 'Client IP:\s*(\S+)')        { $matches[1] } else { '?' }
                $prc = if ($m -match 'Name of client process:\s*(\S+)') { Split-Path $matches[1] -Leaf }
                       elseif ($m -match 'Process Name:\s*([^ ]+(?: \([^)]*\))?)') { $matches[1] } else { '?' }
                $st  = if ($m -match 'Status:\s*(0x\S+)')         { $matches[1] } else { '?' }
                $tgt = if ($m -match 'Target server:\s*(\S+)')    { $matches[1] } else { '' }
                if ($usr -eq '?' -and $m -match 'Supplied user:\s*(\S+)') { $usr = $matches[1] }
                $detail = "$ver compte=$dom\$usr src=$ip proc=$prc status=$st"
                if ($tgt) { $detail += " cible=$tgt" }
            }
            8001 { $proto = 'NTLM sortant'; $detail = ($d.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ' ' }
            8003 { $proto = 'NTLM entrant (audit)'; $detail = ($d.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ' ' }
            8004 { $proto = 'NTLM domaine (audit)'; $detail = ($d.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ' ' }
            default { $proto = "evt $($e.Id)"; $detail = $e.TaskDisplayName }
        }

        Write-Host ("{0,-12} {1,-6} {2,-22} {3}" -f `
            $e.TimeCreated.ToString('HH:mm:ss.fff'), $e.Id, $proto, $detail) -ForegroundColor (Color $proto)
    }

    $last = $now
    Start-Sleep -Seconds $IntervalSeconds
}
