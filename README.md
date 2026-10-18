# NtlmLab — observer NTLMv2 et Kerberos dans les journaux Windows

Deux outils complémentaires pour comprendre, démontrer et inventorier
l'authentification Windows en environnement Active Directory.

| | |
|---|---|
| **Une application web de test** | ASP.NET Core sur IIS. Une page de choix, deux chemins qui forcent chacun un protocole, et une page de détails qui affiche le token obtenu **et retrouve l'événement de sécurité correspondant**. |
| **Un outil de surveillance centralisée** | Trois scripts PowerShell qui interrogent les journaux d'authentification de plusieurs machines depuis un seul poste et fusionnent tout dans un flux unique trié chronologiquement. |

```
00:38:04.102 WIN11A    CLI  4020  NTLM sortant          NEWGEN\root cible=HTTP/srv25a...
00:38:04.351 DCA       DC   4776  NTLM validation DC    NEWGEN\root poste=WIN11A erreur=0x0
00:38:04.402 DCA       DC   4032  NTLM DC validation    NEWGEN\root NTLMv2 status=0x0
00:38:04.583 SRV25A    SRV  4624  NTLM / NTLM V2        NEWGEN\root [10.0.0.100] type=3 proc=NtLmSsp
00:38:04.611 SRV25A    SRV  4022  NTLM entrant          NEWGEN\root NTLMv2 status=0x0
```

Le trajet complet d'une authentification NTLM, en cinq lignes et moins d'une seconde :
le client qui émet, le contrôleur de domaine qui valide le mot de passe, le serveur qui
ouvre la session.

---

## Pourquoi ce projet

Dans un domaine Active Directory, navigateur et serveur négocient spontanément Kerberos
dès qu'ils le peuvent. NTLM n'apparaît qu'en repli, de manière difficile à provoquer à la
demande — ce qui rend son observation, et donc son inventaire, laborieux.

Ce projet résout les deux problèmes :

- **Provoquer NTLMv2 à volonté**, en configurant IIS pour n'annoncer qu'un seul mécanisme
  par chemin. Le client n'a pas le choix.
- **Observer le résultat de bout en bout**, sur les trois machines concernées, dans l'ordre
  réel.

L'application ne se contente pas d'afficher « vous êtes authentifié en NTLM ». Elle lit le
**Logon ID** du token Windows de la requête HTTP en cours, puis va chercher dans le journal
Sécurité l'événement 4624 dont le `TargetLogonId` correspond. Token et événement sont
affichés côte à côte, liés par un identifiant unique : aucune interprétation possible.

## Documentation

Deux documents HTML autonomes, en français, sans dépendance externe.

| Document | Contenu |
|---|---|
| `doc/lab-ntlm-kerberos.html` | Le laboratoire complet : architecture, déploiement sur les trois machines, mécanique des deux protocoles, cartographie des événements, dépannage, référence des scripts et du fichier de configuration. 14 chapitres. |
| `scripts/watch-events-enhanced/surveillance-ntlm.html` | L'outil de surveillance seul, utilisable sur n'importe quel domaine : principe, privilèges, mise en route, campagne d'inventaire NTLM. 12 chapitres. |

GitHub affiche le HTML brut. Pour les lire, téléchargez le dépôt et ouvrez les fichiers
dans un navigateur, ou activez GitHub Pages (*Settings → Pages → branche `main`, dossier
`/`*) pour les servir directement.

## Démarrage rapide

### Le laboratoire

Trois machines : un contrôleur de domaine, un serveur web joint au domaine, un poste
client. Tout en PowerShell administrateur.

```powershell
# Sur le serveur web
.\scripts\setup-webserver.ps1 -PhysicalPath C:\inetpub\NtlmLab -Port 8080
.\scripts\install-dotnet.ps1 -Publish

# Sur le controleur de domaine
.\scripts\setup-dc.ps1 ; Restart-Service Netlogon -Force

# Sur le poste client
.\scripts\setup-client.ps1 -ServerFqdn srv01.votredomaine.local ; Restart-Computer
```

Depuis le poste client : `http://srv01.votredomaine.local:8080/`

### La surveillance centralisée

Utilisable indépendamment du laboratoire, sur n'importe quel domaine.

```powershell
cd scripts\watch-events-enhanced
# 1. Renseignez vos machines dans watch-config.json
# 2. Une fois, en administrateur des machines surveillees
.\prepare-monitoring.ps1
# 3. Verifiez les acces, puis surveillez
.\watch-events-enhanced.ps1 -TestOnly
.\watch-events-enhanced.ps1
```

Pour déléguer la surveillance à un compte non privilégié :

```powershell
.\prepare-monitoring.ps1 -GrantAccessTo DOMAINE\compte-audit
```

## Prérequis

| Composant | Version |
|---|---|
| Serveur web | Windows Server 2016 ou plus, joint au domaine, IIS avec Windows Authentication |
| Application | .NET 8 SDK et ASP.NET Core 8 Hosting Bundle |
| Surveillance | PowerShell 5.1, présent nativement |
| Machines surveillées | Windows Server 2008 R2 à 2025, Windows 10 et 11 |

La surveillance accepte **les deux numérotations d'événements NTLM** — 8001-8004 des
versions antérieures, et 4015/4020-4023/4030-4033 de Windows Server 2025 — ce qui permet
de couvrir un parc hétérogène sans configuration particulière.

## Structure

```
.
├─ Program.cs · Pages.cs · TokenInfo.cs · EventLookup.cs   application ASP.NET Core
├─ NtlmLab.csproj · web.config
├─ doc/
│  └─ lab-ntlm-kerberos.html          documentation du laboratoire
└─ scripts/
   ├─ setup-webserver.ps1             IIS, audit, NTLMv2, pare-feu
   ├─ install-dotnet.ps1              SDK, Hosting Bundle, publication
   ├─ setup-dc.ps1                    audit du contrôleur de domaine
   ├─ setup-client.ps1                NTLMv2 et zone Intranet côté client
   ├─ watch-events.ps1                surveillance locale, une machine
   ├─ diag.ps1                        collecte de diagnostic en une passe
   └─ watch-events-enhanced/          surveillance centralisée, autonome
      ├─ prepare-monitoring.ps1
      ├─ watch-config.json
      ├─ watch-events-enhanced.ps1
      └─ surveillance-ntlm.html
```

## Trois pièges qui coûtent cher

Documentés en détail, mais ils méritent d'être connus avant de commencer.

**Les paramètres NTLM du registre ne sont lus qu'au démarrage.** Tant que la machine n'a
pas redémarré, `lsass` continue avec l'ancienne configuration. Les symptômes sont
trompeurs : boucle d'invites d'authentification, événement 4015, ou absence totale
d'événement.

**Les événements NTLM du contrôleur de domaine ne sont pas dans le journal NTLM.** Sur
Windows Server 2025, ils proviennent d'un fournisseur distinct et vivent dans
`Microsoft-Windows-Security-Netlogon/Operational`. On cherche longtemps dans le mauvais
journal.

**`authPersistSingleRequest="true"` casse NTLM.** Ce protocole est orienté connexion : sa
poignée de main se déroule en trois échanges sur la même connexion TCP. Cet attribut IIS
réinitialise le contexte à chaque requête, et le message de type 3 arrive dans le vide.
Kerberos, sans état, n'est pas affecté — d'où une asymétrie déroutante.

## Avertissement

Ce projet est destiné à un **environnement de test**. L'application expose
intentionnellement des informations de token — SID, appartenances de groupes, Logon ID —
à tout utilisateur authentifié.

Les scripts modifient des paramètres de sécurité : `LmCompatibilityLevel = 5` refuse
NTLMv1, `AuditNTLMInDomain = 7` journalise toutes les authentifications NTLM du domaine.
Vérifiez qu'aucun équipement ancien n'en dépend et dimensionnez vos journaux avant de
déployer ailleurs que dans un laboratoire.

Les valeurs d'exemple — `newgen.local`, `SRV25A`, adresses en `10.0.0.x` — sont fictives
et à adapter.

## Licence

MIT. Voir [LICENSE](LICENSE).
