#Requires -RunAsAdministrator
<#
.SYNOPSIS
  A executer sur le POSTE CLIENT de test (joint au domaine).
  Force NTLMv2 cote client, place le serveur en zone Intranet local
  (SSO sans invite de mot de passe) et active l'audit NTLM sortant.

.EXAMPLE
  .\setup-client.ps1 -ServerFqdn web01.corp.lab
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ServerFqdn
)
$ErrorActionPreference = 'Stop'
function Ok($m) { Write-Host "    [ok] $m" -ForegroundColor Green }

Write-Host "`n=== NTLMv2 uniquement cote client" -ForegroundColor Cyan
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
    -Name 'LmCompatibilityLevel' -Value 5 -Type DWord
$msv = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
New-Item -Path $msv -Force | Out-Null
Set-ItemProperty $msv -Name 'NtlmMinClientSec' -Value 0x20080000 -Type DWord

# 0 = autoriser sans auditer, 1 = auditer, 2 = refuser.
# 1 produit l'evenement 4020 (NTLM sortant) dans Microsoft-Windows-NTLM/
# Operational, qui nomme le PROCESSUS a l'origine de l'authentification.
#
# ATTENTION : ce parametre n'est relu par lsass qu'au demarrage. Tant que le
# poste n'a pas redemarre, l'ancienne valeur reste active et vous pouvez
# observer un evenement 4015 "Outgoing NTLM authentication traffic to remote
# servers that is blocked" qui empeche toute authentification NTLM sortante.
# Ce n'est pas la valeur 1 qui bloque, c'est l'etat fige du service.
Set-ItemProperty $msv -Name 'RestrictSendingNTLMTraffic' -Value 1 -Type DWord
Ok 'LmCompatibilityLevel = 5, audit du NTLM sortant actif (evenement 4020)'

Write-Host "`n=== Zone Intranet local pour $ServerFqdn" -ForegroundColor Cyan
# Zone 1 = Intranet local => Edge/Chrome/IE envoient les creds automatiquement
$base = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains"
$parts = $ServerFqdn.Split('.')
$host0  = $parts[0]
$domain = ($parts[1..($parts.Length-1)]) -join '.'
$key = Join-Path $base $domain
New-Item -Path (Join-Path $key $host0) -Force | Out-Null
Set-ItemProperty -Path (Join-Path $key $host0) -Name 'http' -Value 1 -Type DWord
Ok "$ServerFqdn ajoute a l'Intranet local"

Write-Host "`n=== Journal NTLM" -ForegroundColor Cyan
wevtutil sl Microsoft-Windows-NTLM/Operational /e:true 2>$null
Ok 'journal NTLM/Operational actif'

Write-Host @"

REDEMARREZ CE POSTE avant tout test.
  Les parametres NTLM ci-dessus sont lus par lsass au demarrage et ne sont pas
  relus a chaud. Sans redemarrage, l'ancienne configuration reste active et les
  symptomes sont trompeurs : boucle d'invites d'authentification, evenement 4015,
  ou absence totale d'evenement 4020.

  Restart-Computer

Pour tester proprement, ensuite :
  klist purge                      # vide le cache Kerberos
  (fermer toutes les fenetres du navigateur entre deux essais :
   les identifiants sont mis en cache pour la duree de la session)

Verifier ce que le client a en cache apres un test Kerberos :
  klist tickets                    # doit montrer HTTP/$ServerFqdn

"@ -ForegroundColor Yellow
