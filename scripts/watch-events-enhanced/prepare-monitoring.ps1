#Requires -Version 5.1
<#
.SYNOPSIS
  Prepare toutes les machines declarees dans watch-config.json pour la
  surveillance centralisee : transport distant, journaux d'evenements,
  et verification de la politique d'audit.

.DESCRIPTION
  A executer UNE SEULE FOIS depuis le poste de supervision, avec un compte
  administrateur du domaine. Le script traite chaque machine de la liste :

    1. Teste WinRM. S'il ne repond pas, tente de l'activer a distance en
       lancant Enable-PSRemoting via WMI/DCOM, puis re-teste.
    2. Ouvre la regle de pare-feu "Gestion a distance du journal des
       evenements", qui fournit le transport RPC de secours.
    3. Active et dimensionne les journaux Microsoft-Windows-NTLM/Operational
       et Microsoft-Windows-Security-Netlogon/Operational, et agrandit le
       journal Securite.
    4. Releve la politique d'audit et les cles NTLM, et signale ce qui
       manquerait pour que les evenements soient reellement produits.

  Le script ne modifie PAS la politique d'audit ni les cles NTLM : c'est le
  role de setup-webserver.ps1, setup-dc.ps1 et setup-client.ps1. Il se contente
  de verifier et de vous dire quoi lancer.

.PARAMETER ConfigPath
  watch-config.json decrivant les machines. Par defaut a cote du script.

.PARAMETER Credential
  Compte administrateur du domaine. Par defaut, la session courante.

.PARAMETER Check
  Ne modifie rien, se contente du diagnostic.

.PARAMETER GrantAccessTo
  Compte a qui donner le droit de surveiller, sur chaque machine de la liste.
  Il est ajoute aux groupes locaux "Lecteurs des journaux d'evenements"
  (lecture du journal Securite a distance) et "Utilisateurs de gestion a
  distance" (ouverture de session WinRM sans etre administrateur).

  Permet de separer les roles : un administrateur lance ce script UNE FOIS,
  puis un compte d'audit non privilegie fait tourner watch-events-enhanced.ps1
  au quotidien.

  Format DOMAINE\compte, par exemple NEWGEN\svc-audit.

.NOTES
  PRIVILEGES REQUIS POUR CE SCRIPT : administrateur local de chaque machine
  surveillee. Il active WinRM, modifie des regles de pare-feu, redimensionne
  des journaux et, avec -GrantAccessTo, modifie des groupes locaux. Un
  administrateur du domaine remplit ces conditions partout.

  PRIVILEGES REQUIS POUR watch-events-enhanced.ps1 : beaucoup moins. Voir
  -GrantAccessTo ci-dessus.

.EXAMPLE
  .\prepare-monitoring.ps1
.EXAMPLE
  .\prepare-monitoring.ps1 -Check
.EXAMPLE
  .\prepare-monitoring.ps1 -GrantAccessTo NEWGEN\svc-audit
.EXAMPLE
  .\prepare-monitoring.ps1 -Credential (Get-Credential NEWGEN\Administrator)
#>
[CmdletBinding()]
param(
    [string]$ConfigPath,
    [System.Management.Automation.PSCredential]$Credential,
    [switch]$Check,
    [string]$GrantAccessTo
)

$ErrorActionPreference = 'Stop'

function Title($t) { Write-Host "`n$t" -ForegroundColor Cyan; Write-Host ('-' * 78) -ForegroundColor DarkGray }
function Ok($t)    { Write-Host "    [ok]   $t" -ForegroundColor Green }
function Warn($t)  { Write-Host "    [! ]   $t" -ForegroundColor Yellow }
function Bad($t)   { Write-Host "    [X ]   $t" -ForegroundColor Red }
function Info($t)  { Write-Host "           $t" -ForegroundColor DarkGray }

# =====================================================================
# Configuration
# =====================================================================

if (-not $ConfigPath) { $ConfigPath = Join-Path $PSScriptRoot 'watch-config.json' }
if (-not (Test-Path $ConfigPath)) { throw "Configuration introuvable : $ConfigPath" }

$cfg = Get-Content $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
if (-not $cfg.machines) { throw "Aucune machine declaree dans $ConfigPath" }
$empty = @($cfg.machines | Where-Object { -not $_.name -or -not ([string]$_.name).Trim() })
if ($empty.Count) {
    throw ("$($empty.Count) machine(s) sans nom dans $ConfigPath. " +
           "Renseignez le champ 'name' (FQDN de preference), ou supprimez l'entree.")
}

$machines = @(foreach ($m in $cfg.machines) {
    [pscustomobject]@{
        Name  = [string]$m.name
        Short = ([string]$m.name).Split('.')[0].ToUpper()
        Role  = if ($m.role) { [string]$m.role } else { 'server' }
        Label = if ($m.label) { [string]$m.label } else { '' }
    }
})

Write-Host ''
Write-Host '  Preparation des machines pour la surveillance centralisee' -ForegroundColor Cyan
Write-Host "  configuration : $ConfigPath" -ForegroundColor DarkGray
Write-Host "  compte        : $(if ($Credential) { $Credential.UserName } else { "$env:USERDOMAIN\$env:USERNAME" })" -ForegroundColor DarkGray
Write-Host "  mode          : $(if ($Check) { 'verification seule, aucune modification' } else { 'configuration' })" -ForegroundColor DarkGray
if ($GrantAccessTo) {
    Write-Host "  droits pour   : $GrantAccessTo (Event Log Readers + Remote Management Users)" -ForegroundColor DarkGray
}
Write-Host '  Ce script exige des droits d''ADMINISTRATEUR sur chaque machine surveillee.' -ForegroundColor DarkGray

# =====================================================================
# Bloc execute sur chaque machine distante
# =====================================================================

$Configure = {
    param([bool]$ReadOnly, [string]$GrantTo)

    $r = [ordered]@{
        Computer   = $env:COMPUTERNAME
        Os         = (Get-CimInstance Win32_OperatingSystem).Caption
        IsDC       = $false
        Changes    = @()
        Problems   = @()
        Logs       = @{}
        Audit      = @{}
        Ntlm       = @{}
    }

    try {
        # ProductType 2 = controleur de domaine
        $r.IsDC = ((Get-CimInstance Win32_OperatingSystem).ProductType -eq 2)
    } catch { }

    # ---- 1. Regle de pare-feu RPC (transport de secours) ----
    try {
        # On cible les regles par leur NOM interne (invariant) et non par leur
        # libelle, qui est traduit : "Gestion a distance du journal des
        # evenements" sur un Windows francais.
        $grp = Get-NetFirewallRule -Name 'RemoteEventLogSvc*' -ErrorAction SilentlyContinue
        if ($grp) {
            $off = @($grp | Where-Object { $_.Enabled -ne 'True' })
            if ($off.Count -eq 0) {
                $r.Changes += 'pare-feu RPC : deja ouvert'
            } elseif ($ReadOnly) {
                $r.Problems += "pare-feu RPC : $($off.Count) regle(s) desactivee(s)"
            } else {
                $off | Enable-NetFirewallRule
                $r.Changes += "pare-feu RPC : $($off.Count) regle(s) activee(s)"
            }
        } else {
            $r.Problems += 'regles de pare-feu RemoteEventLogSvc introuvables'
        }
    } catch {
        $r.Problems += "pare-feu : $($_.Exception.Message)"
    }

    # ---- 2. Journaux d'evenements ----
    $wanted = @(
        @{ Name = 'Microsoft-Windows-NTLM/Operational';              Size = 67108864 }
        @{ Name = 'Microsoft-Windows-Security-Netlogon/Operational'; Size = 67108864 }
    )
    foreach ($w in $wanted) {
        try {
            $cfgTxt = (& wevtutil gl $w.Name 2>&1) -join "`n"
            if ($LASTEXITCODE -ne 0 -or $cfgTxt -match 'Impossible|not be found|introuvable') {
                $r.Logs[$w.Name] = 'absent sur cette version de Windows'
                continue
            }
            $enabled = ($cfgTxt -match 'enabled:\s*true')
            $size = if ($cfgTxt -match 'maxSize:\s*(\d+)') { [int64]$Matches[1] } else { 0 }

            if ($enabled -and $size -ge $w.Size) {
                $r.Logs[$w.Name] = "actif, $([int]($size/1MB)) Mo"
            } elseif ($ReadOnly) {
                $r.Logs[$w.Name] = "a corriger (actif=$enabled, $([int]($size/1MB)) Mo)"
            } else {
                if (-not $enabled) { & wevtutil sl $w.Name /e:true 2>&1 | Out-Null }
                if ($size -lt $w.Size) { & wevtutil sl $w.Name /ms:$($w.Size) 2>&1 | Out-Null }
                $r.Logs[$w.Name] = 'active et dimensionne'
                $r.Changes += "journal $($w.Name) configure"
            }
        } catch {
            $r.Logs[$w.Name] = "erreur : $($_.Exception.Message)"
        }
    }

    # Journal Securite : 512 Mo, 1 Go sur un DC
    try {
        $target = if ($r.IsDC) { 1073741824 } else { 536870912 }
        $secTxt = (& wevtutil gl Security 2>&1) -join "`n"
        $secSize = if ($secTxt -match 'maxSize:\s*(\d+)') { [int64]$Matches[1] } else { 0 }
        if ($secSize -ge $target) {
            $r.Logs['Security'] = "$([int]($secSize/1MB)) Mo"
        } elseif ($ReadOnly) {
            $r.Logs['Security'] = "$([int]($secSize/1MB)) Mo (a agrandir)"
        } else {
            & wevtutil sl Security /ms:$target 2>&1 | Out-Null
            $r.Logs['Security'] = "porte a $([int]($target/1MB)) Mo"
            $r.Changes += 'journal Securite agrandi'
        }
    } catch {
        $r.Logs['Security'] = "erreur : $($_.Exception.Message)"
    }

    # ---- 2 bis. Droits du compte d'audit ----
    # Les groupes sont designes par leur SID connu, invariant quelle que soit
    # la langue du systeme :
    #   S-1-5-32-573  Lecteurs des journaux d'evenements
    #   S-1-5-32-580  Utilisateurs de gestion a distance (WinRM sans admin)
    # L'acces se fait par le fournisseur WinNT, qui fonctionne aussi bien sur
    # un serveur membre que sur un controleur de domaine, ou ces groupes sont
    # des groupes de domaine local du conteneur Builtin.
    if ($GrantTo) {
        $acct = $GrantTo.Split('\')[-1]
        $adom = if ($GrantTo -match '\\') { $GrantTo.Split('\')[0] } else { $env:USERDOMAIN }

        foreach ($wk in @(
            @{ Sid = 'S-1-5-32-573'; Why = 'lecture du journal Securite a distance' }
            @{ Sid = 'S-1-5-32-580'; Why = 'ouverture de session WinRM sans etre administrateur' }
        )) {
            try {
                $sidObj = New-Object System.Security.Principal.SecurityIdentifier($wk.Sid)
                $gName = ($sidObj.Translate([System.Security.Principal.NTAccount]).Value -split '\\')[-1]
                $grpObj = [ADSI]"WinNT://$env:COMPUTERNAME/$gName,group"

                $members = @()
                try {
                    foreach ($mb in @($grpObj.psbase.Invoke('Members'))) {
                        $members += $mb.GetType().InvokeMember('Name', 'GetProperty', $null, $mb, $null)
                    }
                } catch { }

                if ($members -contains $acct) {
                    $r.Changes += "$gName : $GrantTo deja membre"
                } elseif ($ReadOnly) {
                    $r.Problems += "$gName : $GrantTo n'est pas membre ($($wk.Why))"
                } else {
                    $grpObj.Add("WinNT://$adom/$acct,user")
                    $r.Changes += "$gName : $GrantTo ajoute ($($wk.Why))"
                }
            } catch {
                $r.Problems += "groupe $($wk.Sid) : $($_.Exception.Message)"
            }
        }
    }

    # ---- 3. Releve de la politique d'audit (lecture seule) ----
    # GUID de la categorie Logon/Logoff : insensible a la langue du systeme.
    try {
        # Les sous-categories sont elles aussi designees par GUID, ce qui evite
        # de dependre du libelle traduit.
        #   0CCE9215  Logon                 (Ouverture de session)
        #   0CCE923F  Credential Validation (Validation des informations d'identification)
        $pol = (& auditpol /get /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" 2>&1) -join "`n"
        if ($pol -match '(?m)^\s*\S.*?\s{2,}(\S.*?)\s*$' -and $pol -notmatch 'error|erreur') {
            # Derniere ligne non vide : "<sous-categorie>   <reglage>"
            $last = ($pol -split "`n" | Where-Object { $_ -match '\S' })[-1]
            if ($last -match '\s{2,}(\S.*?)\s*$') { $r.Audit['Logon'] = $Matches[1].Trim() }
        }
        if (-not $r.Audit['Logon']) { $r.Audit['Logon'] = 'indetermine' }
    } catch { $r.Audit['Logon'] = "erreur : $($_.Exception.Message)" }

    if ($r.IsDC) {
        try {
            $pol2 = (& auditpol /get /subcategory:"{0CCE923F-69AE-11D9-BED3-505054503030}" 2>&1) -join "`n"
            $last2 = ($pol2 -split "`n" | Where-Object { $_ -match '\S' })[-1]
            if ($last2 -match '\s{2,}(\S.*?)\s*$') { $r.Audit['CredentialValidation'] = $Matches[1].Trim() }
            if (-not $r.Audit['CredentialValidation']) { $r.Audit['CredentialValidation'] = 'indetermine' }
        } catch { }
    }

    # ---- 4. Releve des cles NTLM (lecture seule) ----
    $msv = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $net = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
    function Reg($p, $n) { try { (Get-ItemProperty $p -Name $n -ErrorAction Stop).$n } catch { $null } }

    $r.Ntlm['LmCompatibilityLevel']       = Reg $lsa 'LmCompatibilityLevel'
    $r.Ntlm['AuditReceivingNTLMTraffic']  = Reg $msv 'AuditReceivingNTLMTraffic'
    $r.Ntlm['RestrictSendingNTLMTraffic'] = Reg $msv 'RestrictSendingNTLMTraffic'
    if ($r.IsDC) { $r.Ntlm['AuditNTLMInDomain'] = Reg $net 'AuditNTLMInDomain' }

    [pscustomobject]$r
}

# =====================================================================
# Helpers de connexion
# =====================================================================

function Test-WinRMUp {
    param([string]$Name)
    try {
        $p = @{ ComputerName = $Name; ErrorAction = 'Stop' }
        if ($Credential) { $p['Credential'] = $Credential }
        Test-WSMan @p | Out-Null
        return $true
    } catch { return $false }
}

function Enable-WinRMViaDcom {
    <#  Amorcage : WinRM est injoignable, on lance Enable-PSRemoting sur la
        cible en creant un processus via WMI/DCOM (ports 135 + dynamiques).
        Necessite des droits d'administrateur sur la machine distante.       #>
    param([string]$Name)
    try {
        $opt = New-CimSessionOption -Protocol Dcom
        $p = @{ ComputerName = $Name; SessionOption = $opt; ErrorAction = 'Stop' }
        if ($Credential) { $p['Credential'] = $Credential }
        $cs = New-CimSession @p

        $cmd = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ' +
               '"Enable-PSRemoting -Force -SkipNetworkProfileCheck; ' +
               'Set-Service WinRM -StartupType Automatic; Start-Service WinRM"'

        $res = Invoke-CimMethod -CimSession $cs -ClassName Win32_Process `
                                -MethodName Create -Arguments @{ CommandLine = $cmd } -ErrorAction Stop
        Remove-CimSession $cs -ErrorAction SilentlyContinue
        return ($res.ReturnValue -eq 0)
    } catch {
        $script:lastDcomError = $_.Exception.Message
        return $false
    }
}

# =====================================================================
# Traitement
# =====================================================================

$report = @()

foreach ($m in $machines) {
    $tag = if ($m.Label) { " - $($m.Label)" } else { '' }
    Title "$($m.Name)   [role: $($m.Role)]$tag"

    # ---- Transport ----
    $up = Test-WinRMUp $m.Name
    if ($up) {
        Ok 'WinRM repond'
    } else {
        Warn 'WinRM ne repond pas'
        if ($Check) {
            Info 'mode -Check : aucune tentative d''activation'
        } else {
            Info 'tentative d''activation a distance via WMI/DCOM...'
            if (Enable-WinRMViaDcom $m.Name) {
                Info 'commande lancee, attente du demarrage du service (20 s)'
                Start-Sleep -Seconds 20
                $up = Test-WinRMUp $m.Name
                if ($up) { Ok 'WinRM active et operationnel' }
                else     { Bad 'WinRM toujours injoignable apres activation' }
            } else {
                Bad "amorcage DCOM impossible : $script:lastDcomError"
            }
        }
    }

    if (-not $up) {
        Bad 'machine non configuree'
        Info 'Pistes :'
        Info '  - la machine est-elle allumee et joignable ? (Test-NetConnection -Port 135)'
        Info '  - le compte est-il administrateur local de la cible ?'
        Info '  - a defaut, ouvrez une session sur la machine et lancez :'
        Info '      Enable-PSRemoting -Force'
        Info '      Enable-NetFirewallRule -DisplayGroup "Remote Event Log Management"'
        $report += [pscustomobject]@{ Machine = $m.Short; Role = $m.Role; Etat = 'INJOIGNABLE'; Detail = '' }
        continue
    }

    # ---- Configuration ----
    try {
        $p = @{ ComputerName = $m.Name; ScriptBlock = $Configure
                ArgumentList = @([bool]$Check, $GrantAccessTo); ErrorAction = 'Stop' }
        if ($Credential) { $p['Credential'] = $Credential }
        $res = Invoke-Command @p
    } catch {
        Bad "execution distante impossible : $($_.Exception.Message)"
        $report += [pscustomobject]@{ Machine = $m.Short; Role = $m.Role; Etat = 'ECHEC'; Detail = $_.Exception.Message }
        continue
    }

    Info "$($res.Os)$(if ($res.IsDC) { '   (controleur de domaine)' })"

    foreach ($c in $res.Changes)  { Ok $c }
    foreach ($pb in $res.Problems) { Warn $pb }

    Write-Host '           Journaux :' -ForegroundColor DarkGray
    foreach ($k in $res.Logs.Keys) {
        $v = $res.Logs[$k]
        $short = $k -replace '^Microsoft-Windows-', ''
        if ($v -match 'erreur|absent|corriger') { Warn "  $short : $v" } else { Info "  $short : $v" }
    }

    # ---- Coherence audit / role ----
    # "Succ" couvre l'anglais "Success" et le francais "Succes", sans accent
    # ni dependance a la langue du systeme surveille.
    $missing = @()
    if ($res.Audit['Logon'] -notmatch 'Succ') {
        $missing += "audit 'Ouverture de session' inactif (pas de 4624)"
    }
    switch ($m.Role) {
        'dc' {
            if ($res.Audit['CredentialValidation'] -notmatch 'Succ') {
                $missing += "audit 'Validation des informations d'identification' inactif (4776)"
            }
            if ($res.Ntlm['AuditNTLMInDomain'] -ne 7) {
                $missing += "AuditNTLMInDomain = $($res.Ntlm['AuditNTLMInDomain']) au lieu de 7"
            }
        }
        'client' {
            if ($res.Ntlm['RestrictSendingNTLMTraffic'] -ne 1) {
                $missing += "RestrictSendingNTLMTraffic = $($res.Ntlm['RestrictSendingNTLMTraffic']) : pas d'evenement 4020 (1 = auditer)"
            }
        }
        default {
            if ($res.Ntlm['AuditReceivingNTLMTraffic'] -ne 2) {
                $missing += "AuditReceivingNTLMTraffic = $($res.Ntlm['AuditReceivingNTLMTraffic']) au lieu de 2 : pas d'evenement 4022"
            }
        }
    }

    if ($missing.Count -eq 0) {
        Ok 'politique d''audit coherente avec le role'
        $etat = 'OK'
    } else {
        foreach ($x in $missing) { Warn $x }
        $hint = switch ($m.Role) {
            'dc'     { '.\setup-dc.ps1 puis Restart-Service Netlogon -Force' }
            'client' { '.\setup-client.ps1 -ServerFqdn <serveur> puis redemarrer' }
            default  { '.\setup-webserver.ps1' }
        }
        Info "-> a lancer SUR la machine : $hint"
        $etat = 'AUDIT INCOMPLET'
    }

    $report += [pscustomobject]@{
        Machine = $m.Short
        Role    = $m.Role
        Etat    = $etat
        Detail  = ($missing -join ' ; ')
    }
}

# =====================================================================
# Recapitulatif
# =====================================================================

Title 'Recapitulatif'
$report | Format-Table -AutoSize | Out-String | Write-Host

$ko = @($report | Where-Object { $_.Etat -ne 'OK' })
if ($ko.Count -eq 0) {
    Write-Host '  Toutes les machines sont pretes.' -ForegroundColor Green
    Write-Host ''
    Write-Host '  Etape suivante :' -ForegroundColor Cyan
    Write-Host '    .\watch-events-enhanced.ps1 -TestOnly'
    Write-Host '    .\watch-events-enhanced.ps1'
    if (-not $GrantAccessTo) {
        Write-Host ''
        Write-Host '  Pour faire tourner la surveillance avec un compte NON administrateur :' -ForegroundColor Cyan
        Write-Host '    .\prepare-monitoring.ps1 -GrantAccessTo DOMAINE\compte-audit'
        Write-Host '  Ce compte n''aura alors que le droit de LIRE les journaux a distance.'
    }
} else {
    Write-Host "  $($ko.Count) machine(s) a reprendre." -ForegroundColor Yellow
    Write-Host '  Les reglages d''audit se font sur la machine elle-meme : ils touchent'
    Write-Host '  a LSA et ne sont effectifs qu''apres redemarrage, ce que ce script ne'
    Write-Host '  declenche pas a votre place.'
}
Write-Host ''
