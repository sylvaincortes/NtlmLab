#Requires -Version 5.1
<#
.SYNOPSIS
  Surveillance centralisee des evenements d'authentification NTLM et Kerberos
  sur plusieurs machines, depuis un seul poste.

.DESCRIPTION
  Lit un fichier de configuration JSON decrivant les controleurs de domaine, les
  serveurs de ressources et les postes clients a surveiller, puis interroge en
  continu leurs journaux d'evenements. Chaque ligne affichee porte la machine
  d'origine, de sorte qu'une authentification peut etre suivie de bout en bout :
  le client qui emet, le serveur qui recoit, le DC qui valide.

  Deux transports sont possibles :
    WinRM  interrogation en parallele via Invoke-Command (port 5985)
    RPC    interrogation sequentielle via Get-WinEvent -ComputerName (port 135)

  Les evenements sont dedupliques par RecordId, ce qui permet de recouvrir les
  fenetres de collecte sans risque de doublon. Les horodatages sont normalises
  en heure locale du poste de supervision.

.PARAMETER ConfigPath
  Fichier JSON de configuration. Par defaut watch-config.json a cote du script.

.PARAMETER TestOnly
  Teste la connectivite et les droits de lecture sur chaque machine, puis sort.

.PARAMETER Backfill
  Nombre de minutes d'historique a afficher au demarrage. Surcharge la valeur
  du fichier de configuration.

.PARAMETER CsvPath
  Si renseigne, chaque evenement est aussi ecrit dans ce fichier CSV.

.PARAMETER User
  N'affiche que les evenements concernant ce compte (correspondance partielle).

.PARAMETER Protocol
  Filtre sur le protocole : NTLM, Kerberos ou Autre.

.PARAMETER Credential
  Compte a utiliser pour interroger les machines distantes. Par defaut, les
  identifiants de la session courante.

.EXAMPLE
  .\watch-events-enhanced.ps1
  Surveillance continue avec la configuration par defaut.

.EXAMPLE
  .\watch-events-enhanced.ps1 -TestOnly
  Verifie que les trois machines repondent et que les journaux sont lisibles.

.EXAMPLE
  .\watch-events-enhanced.ps1 -User userweb -Backfill 30 -CsvPath C:\temp\auth.csv
  Reprend 30 minutes d'historique pour un compte precis et archive en CSV.

.NOTES
  PRIVILEGES REQUIS : ce script est en LECTURE SEULE. Il ne modifie rien, ni
  sur le poste de supervision ni sur les machines surveillees. Il n'a donc pas
  besoin de droits d'administrateur.

  Il faut simplement, sur chaque machine surveillee :

    transport WinRM  le compte doit etre membre des groupes locaux
                     "Lecteurs des journaux d'evenements" ET
                     "Utilisateurs de gestion a distance"
                     (ou, a defaut, etre administrateur local)

    transport RPC    le compte doit etre membre du groupe local
                     "Lecteurs des journaux d'evenements" uniquement

  La mise en place de ces droits se fait une seule fois, par un administrateur :
    .\prepare-monitoring.ps1 -GrantAccessTo DOMAINE\compte-audit

  -TestOnly verifie l'acces machine par machine et affiche la cause de chaque
  echec.
#>
[CmdletBinding()]
param(
    [string]$ConfigPath,
    [switch]$TestOnly,
    [int]$Backfill = -1,
    [string]$CsvPath,
    [string]$User,
    [ValidateSet('NTLM', 'Kerberos', 'Autre')]
    [string]$Protocol,
    [System.Management.Automation.PSCredential]$Credential
)

$ErrorActionPreference = 'Stop'

# =====================================================================
# 1. Configuration
# =====================================================================

if (-not $ConfigPath) {
    $ConfigPath = Join-Path $PSScriptRoot 'watch-config.json'
}
if (-not (Test-Path $ConfigPath)) {
    throw "Fichier de configuration introuvable : $ConfigPath"
}

try {
    $cfg = Get-Content $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
} catch {
    throw "Le fichier de configuration n'est pas un JSON valide : $($_.Exception.Message)"
}

if (-not $cfg.machines -or $cfg.machines.Count -eq 0) {
    throw "Aucune machine declaree dans $ConfigPath"
}
$empty = @($cfg.machines | Where-Object { -not $_.name -or -not ([string]$_.name).Trim() })
if ($empty.Count) {
    throw ("$($empty.Count) machine(s) sans nom dans $ConfigPath. " +
           "Renseignez le champ 'name' (FQDN de preference), ou supprimez l'entree.")
}

$interval       = if ($cfg.intervalSeconds) { [int]$cfg.intervalSeconds } else { 5 }
$backfillMin    = if ($Backfill -ge 0) { $Backfill }
                  elseif ($cfg.backfillMinutes) { [int]$cfg.backfillMinutes }
                  else { 5 }
$defaultTranspt = if ($cfg.transport) { [string]$cfg.transport } else { 'WinRM' }

$flt                  = if ($cfg.filters) { $cfg.filters } else { [pscustomobject]@{} }
$ignoreMachineAccts   = if ($null -ne $flt.ignoreMachineAccounts) { [bool]$flt.ignoreMachineAccounts } else { $true }
$ignoreAccounts       = @(if ($flt.ignoreAccounts) { $flt.ignoreAccounts })
$ignoreLogonTypes     = @(if ($flt.ignoreLogonTypes) { $flt.ignoreLogonTypes | ForEach-Object { [string]$_ } })
$ignoreSourceIps      = @(if ($flt.ignoreSourceIps) { $flt.ignoreSourceIps })
$onlyUsers            = @(if ($flt.onlyUsers) { $flt.onlyUsers })
$onlyProtocols        = @(if ($flt.onlyProtocols) { $flt.onlyProtocols })

if ($User)     { $onlyUsers = @($User) }
if ($Protocol) { $onlyProtocols = @($Protocol) }

# =====================================================================
# 2. Collecteur
#    Execute sur la machine distante (WinRM) ou localement en ciblant la
#    machine distante (RPC). Il renvoie des objets legers deja normalises
#    plutot que des EventRecord complets, ce qui limite fortement le volume
#    transfere sur le reseau.
# =====================================================================

$Collector = {
    param(
        [string]$Role,
        [int]$LookbackSeconds,
        [string]$TargetComputer   # vide = machine locale
    )

    # Journaux et identifiants a interroger selon le role de la machine.
    $plan = switch ($Role) {
        'dc' {
            @(
                @{ Log = 'Security'; Ids = @(4624, 4625, 4768, 4769, 4771, 4776); Msg = $false }
                @{ Log = 'Microsoft-Windows-Security-Netlogon/Operational'; Ids = @(); Msg = $true }
                @{ Log = 'Microsoft-Windows-NTLM/Operational'; Ids = @(); Msg = $true }
            )
        }
        'client' {
            @(
                @{ Log = 'Microsoft-Windows-NTLM/Operational'; Ids = @(); Msg = $true }
                @{ Log = 'Security'; Ids = @(4648, 4624, 4625); Msg = $false }
            )
        }
        'auto' {
            # Union de tous les journaux : les journaux absents sur la machine
            # sont simplement ignores (ErrorAction SilentlyContinue).
            @(
                @{ Log = 'Security'; Ids = @(4624, 4625, 4648, 4672, 4768, 4769, 4771, 4776); Msg = $false }
                @{ Log = 'Microsoft-Windows-Security-Netlogon/Operational'; Ids = @(); Msg = $true }
                @{ Log = 'Microsoft-Windows-NTLM/Operational'; Ids = @(); Msg = $true }
            )
        }
        default {
            @(
                @{ Log = 'Security'; Ids = @(4624, 4625, 4648, 4672); Msg = $false }
                @{ Log = 'Microsoft-Windows-NTLM/Operational'; Ids = @(); Msg = $true }
            )
        }
    }

    # StartTime est calcule SUR la machine interrogee : cela evite tout probleme
    # de decalage d'horloge ou de fuseau entre le superviseur et les cibles.
    $start = (Get-Date).AddSeconds(-$LookbackSeconds)
    $out = New-Object System.Collections.ArrayList

    foreach ($p in $plan) {
        $hash = @{ LogName = $p.Log; StartTime = $start }
        if ($p.Ids.Count -gt 0) { $hash['Id'] = $p.Ids }

        $params = @{ FilterHashtable = $hash; ErrorAction = 'SilentlyContinue'; MaxEvents = 300 }
        if ($TargetComputer) { $params['ComputerName'] = $TargetComputer }

        $events = @(Get-WinEvent @params)

        foreach ($e in $events) {
            # EventData -> table de hachage nom/valeur
            $data = @{}
            try {
                $x = [xml]$e.ToXml()
                foreach ($n in $x.Event.EventData.Data) {
                    if ($n.Name) { $data[$n.Name] = [string]$n.'#text' }
                }
            } catch { }

            # Les journaux operationnels NTLM et Netlogon portent l'information
            # utile dans le texte du message, pas dans EventData.
            $msg = $null
            if ($p.Msg) {
                try { $msg = ($e.Message -replace '\s+', ' ') } catch { }
            }

            [void]$out.Add([pscustomobject]@{
                RecordId = $e.RecordId
                TimeUtc  = $e.TimeCreated.ToUniversalTime()
                Id       = $e.Id
                Log      = $p.Log
                Data     = $data
                Message  = $msg
            })
        }
    }

    $out
}

# =====================================================================
# 3. Normalisation : transformer un evenement brut en ligne affichable
# =====================================================================

function Get-NormalizedRecord {
    param($Raw, [string]$Machine, [string]$Role)

    $d   = $Raw.Data
    $m   = $Raw.Message
    $id  = [int]$Raw.Id

    function Field([string]$k) { if ($d.ContainsKey($k) -and $d[$k]) { $d[$k] } else { '' } }
    function FromMsg([string]$pattern) {
        if ($m -and $m -match $pattern) { $Matches[1] } else { '' }
    }

    $proto  = ''
    $kind   = 'Autre'      # NTLM | Kerberos | Autre
    $ok     = $true
    $user   = ''
    $dom    = ''
    $ip     = ''
    $detail = ''

    switch ($id) {

        # ---------- Journal Securite ----------
        4624 {
            $user = Field 'TargetUserName'; $dom = Field 'TargetDomainName'
            $ip   = Field 'IpAddress'
            $pkg  = Field 'AuthenticationPackageName'
            $lm   = Field 'LmPackageName'
            $lp   = (Field 'LogonProcessName').Trim()
            $type = Field 'LogonType'

            $proto = if ($lm -and $lm -ne '-') { "$pkg / $lm" } else { $pkg }
            $kind  = if ($pkg -match 'NTLM' -or $lp -eq 'NtLmSsp') { 'NTLM' }
                     elseif ($pkg -match 'Kerberos') { 'Kerberos' }
                     else { 'Autre' }
            $detail = "ouverture type=$type proc=$lp logonId=$(Field 'TargetLogonId')"
            if (Field 'KeyLength') { $detail += " cle=$(Field 'KeyLength')" }
            if (Field 'WorkstationName') { $detail += " poste=$(Field 'WorkstationName')" }
        }
        4625 {
            $user = Field 'TargetUserName'; $dom = Field 'TargetDomainName'
            $ip   = Field 'IpAddress'
            $pkg  = Field 'AuthenticationPackageName'
            $proto = $pkg; $ok = $false
            $kind = if ($pkg -match 'NTLM') { 'NTLM' } elseif ($pkg -match 'Kerberos') { 'Kerberos' } else { 'Autre' }
            $detail = "ECHEC type=$(Field 'LogonType') status=$(Field 'Status') sub=$(Field 'SubStatus')"
        }
        4648 {
            $user = Field 'TargetUserName'; $dom = Field 'TargetDomainName'
            $ip   = Field 'IpAddress'
            $proto = 'Identifiants explicites'
            $detail = "vers $(Field 'TargetServerName') par $(Field 'SubjectUserName')"
        }
        4672 {
            $user = Field 'SubjectUserName'; $dom = Field 'SubjectDomainName'
            $proto = 'Privileges speciaux'
            $detail = "logonId=$(Field 'SubjectLogonId')"
        }
        4768 {
            $user = Field 'TargetUserName'; $dom = Field 'TargetDomainName'
            $ip   = Field 'IpAddress'
            $proto = 'Kerberos TGT'; $kind = 'Kerberos'
            $ok = ((Field 'Status') -in @('0x0', '0x00000000', ''))
            $detail = "AS-REQ status=$(Field 'Status') chiffrement=$(Field 'TicketEncryptionType')"
        }
        4769 {
            $user = Field 'TargetUserName'; $dom = Field 'TargetDomainName'
            $ip   = Field 'IpAddress'
            $proto = 'Kerberos TGS'; $kind = 'Kerberos'
            $ok = ((Field 'Status') -in @('0x0', '0x00000000', ''))
            $detail = "service=$(Field 'ServiceName') status=$(Field 'Status')"
        }
        4771 {
            $user = Field 'TargetUserName'
            $ip   = Field 'IpAddress'
            $proto = 'Kerberos pre-auth'; $kind = 'Kerberos'; $ok = $false
            $detail = "ECHEC code=$(Field 'Status')"
        }
        4776 {
            $user = Field 'TargetUserName'
            $proto = 'NTLM validation DC'; $kind = 'NTLM'
            $err = Field 'Status'
            $ok = ($err -in @('0x0', '0x00000000', ''))
            $detail = "poste=$(Field 'Workstation') erreur=$err pkg=$(Field 'PackageName')"
        }

        # ---------- Journaux operationnels : NTLM et Security-Netlogon ----------
        # Server 2025 / Windows 11 : 4015, 4020-4023 (NTLM), 4030-4033 (Netlogon).
        # Versions anterieures : 8001-8004 (NTLM).
        default {
            # "(NULL)" et "Null" sont les marqueurs d'absence de ces journaux.
            function Clean([string]$v) {
                if ($v -in @('(NULL)', 'NULL', 'Null', 'null', '-')) { '' } else { $v }
            }

            $user = Clean (FromMsg 'Supplied user:\s*(\S+)')
            if (-not $user) { $user = Clean (FromMsg 'Username:\s*(\S+)') }
            # Sur un 4015, "Supplied user" est souvent vide alors que l'identite
            # du processus appelant, elle, est connue : c'est elle qui compte.
            if (-not $user) { $user = Clean (FromMsg 'User identity of client process:\s*(\S+)') }
            if (-not $user) { $user = Clean (Field 'UserName') }

            $dom = Clean (FromMsg 'Supplied domain:\s*(\S+)')
            if (-not $dom) { $dom = Clean (FromMsg 'Domain name of user identity of client process:\s*(\S+)') }
            if (-not $dom) { $dom = Clean (FromMsg 'Domain:\s*(\S+)') }
            $ip  = Clean (FromMsg 'Client IP:\s*(\S+)')

            $ver  = FromMsg 'NTLM Version:\s*(\S+)'
            $st   = FromMsg 'Status:\s*(0x\S+)'
            $tgt  = Clean (FromMsg 'Target server:\s*(\S+)')
            # Les chemins de processus contiennent des espaces : on borne la
            # capture sur le libelle suivant plutot que sur le premier espace.
            $proc = FromMsg 'Name of client process:\s*(.+?)\s+LUID of client process:'
            if (-not $proc) { $proc = FromMsg 'Process Name:\s*(.+?)\s+Process PID:' }
            if ($proc) { $proc = ($proc -split '\\')[-1] }

            $kind = 'NTLM'
            switch ($id) {
                4015 { $proto = 'NTLM sortant BLOQUE'; $ok = $false }
                4020 { $proto = 'NTLM sortant' }
                4021 { $proto = 'NTLM sortant (alerte)'; $ok = $false }
                4022 { $proto = 'NTLM entrant' }
                4023 { $proto = 'NTLM entrant ECHEC'; $ok = $false }
                4030 { $proto = 'NTLM DC inter-domaines' }
                4031 { $proto = 'NTLM DC inter-dom. ECHEC'; $ok = $false }
                4032 { $proto = 'NTLM DC validation' }
                4033 { $proto = 'NTLM DC validation ECHEC'; $ok = $false }
                8001 { $proto = 'NTLM sortant (legacy)' }
                8002 { $proto = 'NTLM sortant bloque (legacy)'; $ok = $false }
                8003 { $proto = 'NTLM entrant (legacy)' }
                8004 { $proto = 'NTLM domaine (legacy)' }
                default { $proto = "evt $id"; $kind = 'Autre' }
            }
            if ($st -and $st -notmatch '^0x0+$') { $ok = $false }

            $bits = @()
            if ($ver)  { $bits += $ver }
            if ($tgt)  { $bits += "cible=$tgt" }
            if ($proc) { $bits += "proc=$proc" }
            if ($st)   { $bits += "status=$st" }
            if (-not $bits -and $d.Count) {
                $bits += ($d.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ' '
            }
            $detail = $bits -join ' '
        }
    }

    [pscustomobject]@{
        Time     = $Raw.TimeUtc.ToLocalTime()
        Machine  = $Machine
        Role     = $Role
        Id       = $id
        Protocol = $proto
        Kind     = $kind
        Success  = $ok
        User     = $user
        Domain   = $dom
        Ip       = $ip
        Detail   = $detail
    }
}

# =====================================================================
# 4. Filtrage
# =====================================================================

function Test-Keep {
    param($R)

    $u = $R.User
    if (-not $u -or $u -eq '-') { return $false }
    if ($ignoreMachineAccts -and $u -match '\$$') { return $false }
    foreach ($a in $ignoreAccounts) { if ($u -eq $a) { return $false } }

    if ($ignoreLogonTypes.Count -and $R.Detail -match 'type=(\d+)') {
        if ($Matches[1] -in $ignoreLogonTypes) { return $false }
    }
    # Adresses a masquer : typiquement celle du poste de supervision, dont les
    # connexions d'administration ne sont pas le sujet de l'observation.
    if ($ignoreSourceIps.Count -and $R.Ip) {
        foreach ($x in $ignoreSourceIps) { if ($R.Ip -eq $x) { return $false } }
    }
    if ($onlyUsers.Count) {
        $hit = $false
        foreach ($p in $onlyUsers) { if ($u -like "*$p*") { $hit = $true; break } }
        if (-not $hit) { return $false }
    }
    if ($onlyProtocols.Count -and $R.Kind -notin $onlyProtocols) { return $false }

    return $true
}

# =====================================================================
# 5. Affichage
# =====================================================================

$roleTag = @{ dc = 'DC'; server = 'SRV'; client = 'CLI'; auto = 'AUT' }

function Get-LineColor {
    param($R)
    if (-not $R.Success) { return 'Red' }
    switch ($R.Kind) {
        'NTLM'     { 'Yellow' }
        'Kerberos' { 'Cyan' }
        default    { 'Gray' }
    }
}

function Write-Record {
    param($R)
    $line = '{0,-12} {1,-16} {2,-4} {3,-5} {4,-26} {5}' -f `
        $R.Time.ToString('HH:mm:ss.fff'),
        $R.Machine,
        $roleTag[$R.Role],
        $R.Id,
        $R.Protocol,
        ("$($R.Domain)\$($R.User)".TrimStart('\') + $(if ($R.Ip) { " [$($R.Ip)]" } else { '' }) + '  ' + $R.Detail)
    Write-Host $line -ForegroundColor (Get-LineColor $R)
}

function Write-Header {
    Write-Host ''
    Write-Host ('{0,-12} {1,-16} {2,-4} {3,-5} {4,-26} {5}' -f `
        'HEURE', 'MACHINE', 'ROLE', 'ID', 'PROTOCOLE', 'COMPTE / DETAIL') -ForegroundColor White
    Write-Host ('-' * 150) -ForegroundColor DarkGray
}

# =====================================================================
# 6. Connexion aux machines
# =====================================================================

$machines = @(foreach ($m in $cfg.machines) {
    [pscustomobject]@{
        Name      = [string]$m.name
        Short     = ([string]$m.name).Split('.')[0].ToUpper()
        Role      = if ($m.role) { [string]$m.role } else { 'server' }
        Label     = if ($m.label) { [string]$m.label } else { '' }
        Transport = if ($m.transport) { [string]$m.transport } else { $defaultTranspt }
        Online    = $false
        LastError = ''
        Session   = $null
    }
})

function Get-MachineSession {
    <#  Session WinRM PERSISTANTE, creee une fois et reutilisee a chaque tour.

        Sans cela, chaque interrogation ouvrirait une nouvelle connexion, donc
        une nouvelle ouverture de session reseau sur la cible : un evenement
        4624 toutes les quelques secondes sur chaque machine surveillee. L'outil
        polluerait alors exactement ce qu'il est cense observer.               #>
    param($M)

    if ($M.Session -and $M.Session.State -eq 'Opened') { return $M.Session }
    if ($M.Session) {
        try { Remove-PSSession $M.Session -ErrorAction SilentlyContinue } catch { }
        $M.Session = $null
    }
    $p = @{ ComputerName = $M.Name; ErrorAction = 'Stop' }
    if ($Credential) { $p['Credential'] = $Credential }
    $M.Session = New-PSSession @p
    return $M.Session
}

function Close-MachineSessions {
    foreach ($m in $machines) {
        if ($m.Session) {
            try { Remove-PSSession $m.Session -ErrorAction SilentlyContinue } catch { }
            $m.Session = $null
        }
    }
}

function Invoke-Collect {
    <#  Execute le collecteur contre une machine, quel que soit le transport.

        Renvoie TOUJOURS un tableau en cas de succes, eventuellement vide, et
        $null uniquement en cas d'echec de connexion. Cette distinction est
        essentielle : une machine sans evenement n'est pas une machine
        injoignable.                                                           #>
    param($M, [int]$Lookback)

    $isLocal = ($M.Short -eq $env:COMPUTERNAME.ToUpper())

    try {
        $out = if ($isLocal) {
            & $Collector $M.Role $Lookback ''
        } elseif ($M.Transport -eq 'RPC') {
            & $Collector $M.Role $Lookback $M.Name
        } else {
            $s = Get-MachineSession -M $M
            Invoke-Command -Session $s -ScriptBlock $Collector `
                           -ArgumentList @($M.Role, $Lookback, '') -ErrorAction Stop
        }

        $M.LastError = ''
        # @($null) produirait un tableau d'un element nul : on teste avant.
        if ($null -eq $out) { return , @() }
        return , @($out)
    } catch {
        $M.LastError = $_.Exception.Message
        # La session est peut-etre morte : on la jette pour forcer une
        # reconnexion propre au prochain essai.
        if ($M.Session) {
            try { Remove-PSSession $M.Session -ErrorAction SilentlyContinue } catch { }
            $M.Session = $null
        }
        return $null
    }
}

function Info2($t) { Write-Host "  $t" -ForegroundColor DarkGray }

function Test-Machines {
    Write-Host ''
    Write-Host 'Verification des machines' -ForegroundColor Cyan
    Write-Host ('-' * 78) -ForegroundColor DarkGray

    foreach ($m in $machines) {
        $tag = if ($m.Label) { " ($($m.Label))" } else { '' }
        Write-Host ("  {0,-26} {1,-7} {2,-6} " -f $m.Name, $m.Role, $m.Transport) -NoNewline

        $res = Invoke-Collect -M $m -Lookback 120
        if ($null -eq $res) {
            $m.Online = $false
            Write-Host 'INJOIGNABLE' -ForegroundColor Red
            Write-Host ("      -> " + $m.LastError) -ForegroundColor DarkGray
        } else {
            $m.Online = $true
            Write-Host ("OK  ({0} evenement(s) sur 2 min)$tag" -f @($res).Count) -ForegroundColor Green
        }
    }

    $up = @($machines | Where-Object Online).Count
    Write-Host ('-' * 78) -ForegroundColor DarkGray
    Write-Host ("  {0}/{1} machine(s) joignable(s)" -f $up, $machines.Count) `
        -ForegroundColor $(if ($up -eq $machines.Count) { 'Green' } elseif ($up) { 'Yellow' } else { 'Red' })
    $keep = @($machines | Where-Object { $_.Session }).Count
    if ($keep) { Info2 "$keep session(s) WinRM persistante(s) ouverte(s), reutilisees a chaque tour" }

    if ($up -lt $machines.Count) {
        Write-Host ''
        Write-Host '  Pistes en cas d''echec :' -ForegroundColor Yellow
        Write-Host '    - WinRM non active sur la cible      : Enable-PSRemoting -Force'
        Write-Host '    - droits insuffisants                : ajouter le compte au groupe local'
        Write-Host '                                           "Lecteurs des journaux d''evenements"'
        Write-Host '    - pare-feu                           : autoriser WinRM (5985) ou, en RPC,'
        Write-Host '                                           "Gestion a distance du journal des evenements"'
        Write-Host '    - machine hors domaine               : renseigner -Credential'
    }
    Write-Host ''
}

# =====================================================================
# 7. Boucle principale
# =====================================================================

Write-Host ''
Write-Host '  Surveillance centralisee NTLM / Kerberos' -ForegroundColor Cyan
Write-Host "  configuration : $ConfigPath" -ForegroundColor DarkGray
if ($cfg.domain) { Write-Host "  domaine       : $($cfg.domain)" -ForegroundColor DarkGray }
Write-Host ("  machines      : {0}   intervalle : {1}s   historique : {2} min" -f `
    $machines.Count, $interval, $backfillMin) -ForegroundColor DarkGray
if ($onlyUsers.Count)     { Write-Host "  filtre compte : $($onlyUsers -join ', ')" -ForegroundColor DarkGray }
if ($onlyProtocols.Count) { Write-Host "  filtre proto  : $($onlyProtocols -join ', ')" -ForegroundColor DarkGray }
if ($CsvPath)             { Write-Host "  export CSV    : $CsvPath" -ForegroundColor DarkGray }

Test-Machines

if ($TestOnly) { Close-MachineSessions; return }

$online = @($machines | Where-Object Online)
if ($online.Count -eq 0) { throw 'Aucune machine joignable, arret.' }

# Deduplication : cle "machine|journal|recordid". Bornee pour ne pas croitre
# indefiniment sur une session longue.
$seen = New-Object 'System.Collections.Generic.HashSet[string]'
$seenOrder = New-Object System.Collections.Queue
$seenMax = 20000

function Register-Seen {
    param([string]$Key)
    if ($seen.Contains($Key)) { return $false }
    [void]$seen.Add($Key)
    $seenOrder.Enqueue($Key)
    while ($seenOrder.Count -gt $seenMax) { [void]$seen.Remove($seenOrder.Dequeue()) }
    return $true
}

$stats = @{ Total = 0; NTLM = 0; Kerberos = 0; Echecs = 0 }
$firstPass = $true
$tick = 0
# Recouvrement : on reinterroge plus large que l'intervalle, la deduplication
# se charge d'eliminer les doublons. Evite de manquer un evenement ecrit avec
# un leger decalage.
$lookback = [Math]::Max($interval * 2 + 10, 30)

Write-Header
Write-Host '  Ctrl+C pour arreter' -ForegroundColor DarkGray

try {
    while ($true) {
        $batch = New-Object System.Collections.ArrayList
        $lb = if ($firstPass) { [Math]::Max($backfillMin * 60, $lookback) } else { $lookback }

        foreach ($m in $online) {
            $raws = Invoke-Collect -M $m -Lookback $lb
            if ($null -eq $raws) {
                if ($m.Online) {
                    $m.Online = $false
                    Write-Host ("  [!] {0} ne repond plus : {1}" -f $m.Short, $m.LastError) -ForegroundColor Red
                }
                continue
            }
            foreach ($raw in @($raws)) {
                $key = '{0}|{1}|{2}' -f $m.Short, $raw.Log, $raw.RecordId
                if (-not (Register-Seen $key)) { continue }

                $rec = Get-NormalizedRecord -Raw $raw -Machine $m.Short -Role $m.Role
                if (Test-Keep $rec) { [void]$batch.Add($rec) }
            }
        }

        # Tri chronologique global : c'est tout l'interet de la vue centralisee,
        # voir s'enchainer client -> serveur -> DC dans le bon ordre.
        foreach ($r in ($batch | Sort-Object Time)) {
            Write-Record $r
            $stats.Total++
            if ($r.Kind -eq 'NTLM')     { $stats.NTLM++ }
            if ($r.Kind -eq 'Kerberos') { $stats.Kerberos++ }
            if (-not $r.Success)        { $stats.Echecs++ }

            if ($CsvPath) {
                try {
                    $r | Select-Object Time, Machine, Role, Id, Protocol, Kind, Success, User, Domain, Ip, Detail |
                        Export-Csv -Path $CsvPath -Append -NoTypeInformation -Encoding UTF8
                } catch {
                    Write-Host "  [!] ecriture CSV impossible : $($_.Exception.Message)" -ForegroundColor Red
                    $CsvPath = $null
                }
            }
        }

        if ($firstPass) {
            $firstPass = $false
            Write-Host ('  --- fin de l''historique, surveillance en direct ---') -ForegroundColor DarkGray
        }

        # Reprise des machines tombees, testee une iteration sur six pour ne pas
        # payer un delai d'expiration a chaque tour.
        $tick++
        if ($tick % 6 -eq 0) {
            $down = @($machines | Where-Object { -not $_.Online })
            foreach ($m in $down) {
                if ($null -ne (Invoke-Collect -M $m -Lookback 60)) {
                    $m.Online = $true
                    Write-Host ("  [+] {0} de nouveau joignable" -f $m.Short) -ForegroundColor Green
                }
            }
            if ($down.Count) { $online = @($machines | Where-Object Online) }
        }

        Start-Sleep -Seconds $interval
    }
}
finally {
    Close-MachineSessions
    Write-Host ''
    Write-Host ('-' * 78) -ForegroundColor DarkGray
    Write-Host ("  {0} evenement(s) affiche(s)  -  NTLM {1}  |  Kerberos {2}  |  echecs {3}" -f `
        $stats.Total, $stats.NTLM, $stats.Kerberos, $stats.Echecs) -ForegroundColor Cyan
    if ($CsvPath -and (Test-Path $CsvPath)) {
        Write-Host "  CSV : $CsvPath" -ForegroundColor DarkGray
    }
    Write-Host ''
}
