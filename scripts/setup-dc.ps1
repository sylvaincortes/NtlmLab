#Requires -RunAsAdministrator
<#
.SYNOPSIS
  A executer SUR UN CONTROLEUR DE DOMAINE.
  Active l'audit de validation des informations d'identification (4776)
  et l'audit NTLM a l'echelle du domaine (8004).

.NOTES
  Le serveur web voit le 4624 (ouverture de session reseau).
  Le DC voit le 4776 (validation du challenge/reponse NTLM) et le 8004.
  Pour Kerberos, le DC voit 4768 (TGT) et 4769 (ticket de service).
#>
$ErrorActionPreference = 'Stop'
function Step($m) { Write-Host "`n=== $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "    [ok] $m" -ForegroundColor Green }

Step '1. Politique d''audit du DC'
auditpol /set /subcategory:"Credential Validation"        /success:enable /failure:enable | Out-Null  # 4776
auditpol /set /subcategory:"Kerberos Authentication Service"     /success:enable /failure:enable | Out-Null  # 4768
auditpol /set /subcategory:"Kerberos Service Ticket Operations"  /success:enable /failure:enable | Out-Null  # 4769
auditpol /set /subcategory:"Logon"                        /success:enable /failure:enable | Out-Null
Ok '4776 / 4768 / 4769 / 4624 actives'

Step '2. Audit NTLM a l''echelle du domaine (evenement 8004)'
$netlogon = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
# 7 = auditer toutes les authentifications NTLM du domaine (sans les bloquer)
Set-ItemProperty -Path $netlogon -Name 'AuditNTLMInDomain' -Value 7 -Type DWord
Ok 'AuditNTLMInDomain = 7'

Step '3. Journaux'
wevtutil sl Microsoft-Windows-NTLM/Operational /e:true 2>$null
wevtutil sl Microsoft-Windows-NTLM/Operational /ms:67108864 2>$null
# Sur Windows Server 2025, les evenements NTLM vus par le DC sont emis par le
# fournisseur Security-Netlogon, dans SON PROPRE journal (et non NTLM/Operational).
wevtutil sl Microsoft-Windows-Security-Netlogon/Operational /e:true 2>$null
wevtutil sl Microsoft-Windows-Security-Netlogon/Operational /ms:67108864 2>$null
wevtutil sl Security /ms:1073741824 2>$null
Ok 'journaux NTLM, Security-Netlogon et Securite actives et dimensionnes'

Write-Host "`nRedemarrez le service Netlogon pour appliquer l'audit NTLM :" -ForegroundColor Yellow
Write-Host "  Restart-Service Netlogon -Force`n" -ForegroundColor Yellow

Write-Host "Evenements a surveiller sur ce DC :" -ForegroundColor Cyan
Write-Host "  -- journal Securite --"
Write-Host "  4776  validation NTLM  (Package : MICROSOFT_AUTHENTICATION_PACKAGE_V1_0)"
Write-Host "  4768  demande de TGT Kerberos"
Write-Host "  4769  demande de ticket de service (SPN HTTP/...)"
Write-Host "  -- journal Microsoft-Windows-Security-Netlogon/Operational (Server 2025) --"
Write-Host "  4032 / 4033  validation d'un compte du domaine du DC (succes / echec)"
Write-Host "  4030 / 4031  authentification traversant une approbation"
Write-Host "  -- journal Microsoft-Windows-NTLM/Operational --"
Write-Host "  8004  audit NTLM domaine (versions anterieures a Server 2025)"
