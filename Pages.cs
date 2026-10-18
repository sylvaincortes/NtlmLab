using System.Net;
using System.Security.Principal;
using System.Text;
using Microsoft.AspNetCore.Http.Features;   // IServerVariablesFeature

namespace NtlmLab;

public static class Pages
{
    private static string E(string? s) => WebUtility.HtmlEncode(s ?? "");

    private const string Css = """
    <style>
      :root{--bg:#0f1117;--card:#171a23;--line:#262b38;--txt:#e6e8ef;--mut:#8b93a7;
            --ok:#3ddc97;--warn:#ffb020;--err:#ff5c5c;--ntlm:#ff7a59;--kerb:#5b8dff;}
      *{box-sizing:border-box}
      body{margin:0;background:var(--bg);color:var(--txt);
           font:15px/1.55 "Segoe UI",system-ui,sans-serif;padding:32px 16px}
      .wrap{max-width:960px;margin:0 auto}
      h1{font-size:26px;margin:0 0 4px}
      h2{font-size:15px;text-transform:uppercase;letter-spacing:.08em;color:var(--mut);
         margin:28px 0 10px;font-weight:600}
      .sub{color:var(--mut);margin:0 0 28px}
      .card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px 20px}
      .choices{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:24px}
      @media(max-width:700px){.choices{grid-template-columns:1fr}}
      a.btn{display:block;text-decoration:none;color:inherit;background:var(--card);
            border:1px solid var(--line);border-radius:12px;padding:22px;transition:.15s}
      a.btn:hover{border-color:#3b4356;transform:translateY(-2px)}
      a.btn .t{font-size:19px;font-weight:600;margin-bottom:6px}
      a.btn .d{color:var(--mut);font-size:13.5px}
      .tag{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;
           font-weight:600;letter-spacing:.03em}
      .tag.ntlm{background:rgba(255,122,89,.16);color:var(--ntlm)}
      .tag.kerb{background:rgba(91,141,255,.16);color:var(--kerb)}
      table{width:100%;border-collapse:collapse;font-size:14px}
      td{padding:7px 0;border-bottom:1px solid var(--line);vertical-align:top}
      td:first-child{color:var(--mut);width:270px;padding-right:16px}
      tr:last-child td{border-bottom:0}
      code{font-family:Consolas,monospace;background:#0b0d13;padding:1px 6px;
           border-radius:4px;font-size:13px}
      .pill{font-weight:600}
      .ok{color:var(--ok)}.warn{color:var(--warn)}.err{color:var(--err)}
      .note{border-left:3px solid var(--warn);background:rgba(255,176,32,.07);
            padding:12px 16px;border-radius:0 8px 8px 0;margin:16px 0;font-size:14px}
      .note.bad{border-color:var(--err);background:rgba(255,92,92,.07)}
      .note.good{border-color:var(--ok);background:rgba(61,220,151,.07)}
      .groups{columns:2;font-size:13px;color:var(--mut);margin:0;padding-left:18px}
      @media(max-width:700px){.groups{columns:1}}
      footer{margin-top:36px;color:var(--mut);font-size:13px}
      footer a{color:var(--mut)}
    </style>
    """;

    public static string Login() => $$"""
    <!doctype html><html lang="fr"><meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>NTLM Lab - choix du mecanisme</title>{{Css}}
    <body><div class="wrap">
      <h1>Laboratoire d'authentification Windows</h1>
      <p class="sub">Choisissez le mecanisme. Chaque chemin est configure dans IIS pour
      n'annoncer qu'un seul protocole : le navigateur n'a pas le choix.</p>
      <div class="choices">
        <a class="btn" href="/ntlm">
          <div class="t"><span class="tag ntlm">NTLMv2</span></div>
          <div class="d">IIS n'envoie que <code>WWW-Authenticate: NTLM</code>.
          Genere un 4624 de type 3 avec <code>Logon Process = NtLmSsp</code>
          et <code>Package Name = NTLM V2</code>, plus un 8003 dans
          <code>Microsoft-Windows-NTLM/Operational</code>.</div>
        </a>
        <a class="btn" href="/kerberos">
          <div class="t"><span class="tag kerb">Kerberos</span></div>
          <div class="d">IIS n'envoie que <code>WWW-Authenticate: Negotiate</code>
          restreint a Kerberos. Necessite un acces par FQDN et un SPN valide,
          sinon l'authentification echoue (pas de repli NTLM).</div>
        </a>
      </div>
      <h2>Avant de tester</h2>
      <div class="card">
        <table>
          <tr><td>Depuis ou ?</td><td>Un <b>poste client du domaine</b>, pas le serveur lui-meme
            (une session locale fausse les evenements reseau).</td></tr>
          <tr><td>Rejouer une authentification</td><td>Chaque requete force une re-negociation
            (<code>authPersistSingleRequest</code>), donc un rechargement = un nouvel evenement.</td></tr>
          <tr><td>Etat du serveur</td><td><a href="/health" style="color:var(--kerb)">/health</a></td></tr>
        </table>
      </div>
    </div></body></html>
    """;

    public static object Snapshot(HttpContext ctx)
    {
        var id = ctx.User.Identity as WindowsIdentity;
        if (id is null) return new { error = "pas d'identite Windows" };
        var st = TokenInfo.Read(id);
        var ev = EventLookup.Find4624(st.LogonId);
        return new
        {
            user = id.Name,
            sid = id.User?.Value,
            authenticationType = id.AuthenticationType,
            logonId = st.LogonIdHex,
            impersonationLevel = st.ImpersonationLevel,
            event4624 = ev?.Data,
            event4624Time = ev?.Time
        };
    }

    public static string Details(HttpContext ctx, string requested,
                                 WindowsIdentity? identity = null, string? authDiag = null)
    {
        var sb = new StringBuilder();
        var isNtlmPage = requested == "NTLM";
        var tagClass = isNtlmPage ? "ntlm" : "kerb";

        sb.Append($$"""
        <!doctype html><html lang="fr"><meta charset="utf-8">
        <meta name="viewport" content="width=device-width,initial-scale=1">
        <title>Authentifie - {{E(requested)}}</title>{{Css}}
        <body><div class="wrap">
          <h1>Authentification reussie <span class="tag {{tagClass}}">{{E(requested)}} demande</span></h1>
        """);

        var id = identity ?? ctx.User.Identity as WindowsIdentity;
        if (id is null || !id.IsAuthenticated)
        {
            sb.Append("<div class='note bad'>Aucune identite Windows n'a ete propagee a "
                    + "l'application. IIS a authentifie la requete, mais le middleware "
                    + "ASP.NET n'a pas repris l'identite.</div>");

            // Elements de diagnostic : ce qu'IIS a reellement transmis.
            var sv = ctx.Features.Get<IServerVariablesFeature>();
            string V(string name)
            {
                try { return sv?[name] ?? "(vide)"; } catch { return "(indisponible)"; }
            }

            sb.Append("<h2>Diagnostic</h2><div class='card'><table>");
            Row(sb, "Type de User.Identity", E(ctx.User.Identity?.GetType().FullName ?? "null"));
            Row(sb, "User.Identity.Name", E(ctx.User.Identity?.Name) is "" ? "(vide)" : E(ctx.User.Identity?.Name));
            Row(sb, "IsAuthenticated", (ctx.User.Identity?.IsAuthenticated ?? false).ToString());
            Row(sb, "Variable IIS LOGON_USER", $"<code>{E(V("LOGON_USER"))}</code>");
            Row(sb, "Variable IIS AUTH_TYPE", $"<code>{E(V("AUTH_TYPE"))}</code>");
            Row(sb, "Variable IIS AUTH_USER", $"<code>{E(V("AUTH_USER"))}</code>");
            if (authDiag is not null)
                Row(sb, "Resolution explicite", $"<code>{E(authDiag)}</code>");
            sb.Append("</table></div>");
            sb.Append("<div class='note'>Si <code>LOGON_USER</code> contient bien un compte, "
                    + "IIS fait son travail et c'est la configuration "
                    + "<code>AddAuthentication</code> / <code>UseAuthentication</code> de "
                    + "l'application qui est en cause.</div>");

            sb.Append("<footer><a href='/'>&larr; Retour au choix</a></footer>");
            sb.Append("</div></body></html>");
            return sb.ToString();
        }

        var actual = id.AuthenticationType ?? "?";
        var stats = TokenInfo.Read(id);
        var ev = EventLookup.Find4624(stats.LogonId);

        // Le token ne rapporte que le mecanisme d'enveloppe : "Negotiate" (SPNEGO)
        // ne dit pas si Kerberos ou NTLM a reellement ete retenu a l'interieur.
        // L'evenement 4624, lui, nomme le protocole effectif.
        string EvField(string k) =>
            ev?.Data is { } dd && dd.TryGetValue(k, out var v)
            && !string.IsNullOrWhiteSpace(v) && v != "-" ? v : "";

        var evPkg = EvField("AuthenticationPackageName");
        var evLm = EvField("LmPackageName");
        var effective = evPkg != "" ? (evLm != "" ? $"{evPkg} ({evLm})" : evPkg) : actual;

        // --- coherence protocole demande / protocole reellement negocie ---
        var matches = isNtlmPage
            ? effective.Contains("NTLM", StringComparison.OrdinalIgnoreCase)
            : effective.Contains("Kerberos", StringComparison.OrdinalIgnoreCase)
              || (evPkg == "" && effective.Contains("Negotiate", StringComparison.OrdinalIgnoreCase));

        if (matches)
        {
            sb.Append($"<p class='sub'>Protocole effectif : <span class='pill ok'>{E(effective)}</span>");
            if (evPkg != "" && !actual.Equals(evPkg, StringComparison.OrdinalIgnoreCase))
                sb.Append($" <span style='color:var(--mut)'>&mdash; le token annonce "
                        + $"<code>{E(actual)}</code>, l'enveloppe SPNEGO ; "
                        + $"<code>{E(evPkg)}</code> est le protocole retenu a l'interieur</span>");
            sb.Append("</p>");
        }
        else
        {
            sb.Append($"<div class='note bad'>Vous avez demande <b>{E(requested)}</b> mais "
                    + $"l'authentification effective est <b>{E(effective)}</b>. "
                    + "Repli inattendu, a investiguer.</div>");
        }

        // --- identite ---
        sb.Append("<h2>Identite</h2><div class='card'><table>");
        Row(sb, "Compte", $"<code>{E(id.Name)}</code>");
        Row(sb, "SID", $"<code>{E(id.User?.Value)}</code>");
        Row(sb, "Type d'authentification (token)", $"<span class='pill'>{E(actual)}</span>");
        Row(sb, "Serveur", $"<code>{E(Environment.MachineName)}</code>");
        Row(sb, "Client (adresse source)", $"<code>{E(ctx.Connection.RemoteIpAddress?.ToString())}</code>");
        Row(sb, "Hote demande", $"<code>{E(ctx.Request.Host.Value)}</code>");
        sb.Append("</table></div>");

        // --- token ---
        sb.Append("<h2>Token d'acces</h2><div class='card'><table>");
        Row(sb, "Logon ID (LUID)", $"<code class='pill'>{E(stats.LogonIdHex)}</code> "
            + "<span style='color:var(--mut)'>&larr; cle de correlation avec le 4624</span>");
        Row(sb, "Type de token", E(stats.TokenType));
        Row(sb, "Niveau d'usurpation", E(stats.ImpersonationLevel));
        Row(sb, "Nombre de groupes", stats.GroupCount.ToString());
        Row(sb, "Nombre de privileges", stats.PrivilegeCount.ToString());
        if (stats.Error is not null) Row(sb, "Erreur", $"<span class='err'>{E(stats.Error)}</span>");
        sb.Append("</table></div>");

        // --- evenement 4624 ---
        sb.Append("<h2>Evenement de securite correle</h2>");
        if (ev is null)
        {
            sb.Append("<div class='note'>Aucun evenement 4624 trouve pour ce Logon ID. "
                + "Causes habituelles : audit \"Ouverture de session\" desactive "
                + "(<code>auditpol</code>), journal Securite illisible par le pool "
                + "d'applications, ou session reutilisee sans nouvelle ouverture.</div>");
        }
        else if (ev.Error is not null)
        {
            sb.Append($"<div class='note bad'>Lecture du journal Securite impossible : "
                + $"<code>{E(ev.Error)}</code><br>Ajoutez l'identite du pool d'applications "
                + "au groupe local <b>Lecteurs des journaux d'evenements</b>.</div>");
        }
        else
        {
            var d = ev.Data;
            // Les champs du 4624 contiennent parfois des identifiants de ressource
            // non resolus (%%1833) au lieu du libelle : on les traduit.
            string G(string k) => d.TryGetValue(k, out var v) ? ResolveMsgId(v) : "-";
            var pkg = G("LmPackageName");
            var isV2 = pkg.Replace(" ", "").Equals("NTLMV2", StringComparison.OrdinalIgnoreCase);

            sb.Append("<div class='card'><table>");
            Row(sb, "ID d'evenement", "<code>4624</code> (ouverture de session)");
            Row(sb, "Horodatage", E(ev.Time?.ToString("yyyy-MM-dd HH:mm:ss.fff")));
            Row(sb, "Target Logon ID", $"<code>{E(G("TargetLogonId"))}</code>");
            Row(sb, "Type d'ouverture de session", $"<code>{E(G("LogonType"))}</code> "
                + (G("LogonType") == "3" ? "<span style='color:var(--mut)'>(3 = reseau)</span>" : ""));
            Row(sb, "Processus d'ouverture", $"<code>{E(G("LogonProcessName"))}</code> "
                + (G("LogonProcessName").Trim() == "NtLmSsp"
                   ? "<span style='color:var(--mut)'>(pile NTLM)</span>" : ""));
            Row(sb, "Package d'authentification", $"<code>{E(G("AuthenticationPackageName"))}</code>");
            Row(sb, "Package Name (NTLM uniquement)",
                pkg == "-" ? "<code>-</code>"
                : isV2 ? $"<code class='pill ok'>{E(pkg)}</code>"
                       : $"<code class='pill err'>{E(pkg)}</code> &larr; ce n'est pas du NTLMv2 !");
            Row(sb, "Longueur de cle", $"<code>{E(G("KeyLength"))}</code>");
            Row(sb, "Station de travail source", $"<code>{E(G("WorkstationName"))}</code>");
            Row(sb, "Adresse reseau source", $"<code>{E(G("IpAddress"))}:{E(G("IpPort"))}</code>");
            Row(sb, "Compte cible", $"<code>{E(G("TargetDomainName"))}\\{E(G("TargetUserName"))}</code>");
            Row(sb, "Niveau d'usurpation", $"<code>{E(G("ImpersonationLevel"))}</code>");
            sb.Append("</table></div>");

            if (isNtlmPage && isV2)
                sb.Append("<div class='note good'>Confirme : NTLMv2 a bien ete utilise et "
                        + "journalise dans le journal Securite de ce serveur.</div>");
            else if (isNtlmPage && !isV2 && pkg != "-")
                sb.Append("<div class='note bad'>Le package n'est pas NTLMv2. Forcez "
                        + "<code>LmCompatibilityLevel = 5</code> sur le serveur et le client.</div>");
        }

        // --- journal NTLM operationnel ---
        if (isNtlmPage)
        {
            var ops = EventLookup.RecentNtlmOperational(3);
            sb.Append("<h2>Microsoft-Windows-NTLM / Operational</h2><div class='card'>");
            if (ops.Count == 0)
            {
                sb.Append("<div style='color:var(--mut);font-size:14px'>Aucun evenement. "
                    + "Activez l'audit NTLM entrant : <code>AuditReceivingNTLMTraffic = 2</code> "
                    + "(evenement 8003).</div>");
            }
            else
            {
                foreach (var o in ops)
                {
                    if (o.Error is not null)
                    {
                        sb.Append($"<div class='err' style='font-size:14px'>{E(o.Error)}</div>");
                        continue;
                    }
                    sb.Append($"<table><tr><td>Evenement {o.EventId}</td><td>"
                        + $"<code>{E(o.Time?.ToString("HH:mm:ss"))}</code> &mdash; ");
                    sb.Append(E(string.Join(" | ", o.Data.Select(kv => $"{kv.Key}={kv.Value}"))));
                    sb.Append("</td></tr></table>");
                }
            }
            sb.Append("</div>");
        }

        // --- groupes ---
        sb.Append("<h2>Groupes du token</h2><div class='card'><ul class='groups'>");
        foreach (var g in TokenInfo.Groups(id)) sb.Append($"<li>{E(g)}</li>");
        sb.Append("</ul></div>");

        sb.Append("<footer><a href='/'>&larr; Retour au choix</a> &nbsp;&middot;&nbsp; "
            + "Rechargez cette page pour declencher une nouvelle authentification "
            + "et un nouvel evenement.</footer>");

        sb.Append("</div></body></html>");
        return sb.ToString();
    }

    /// <summary>
    /// Traduit les identifiants de ressource que Windows laisse bruts dans le
    /// XML des evenements de securite (le libelle n'est resolu qu'a l'affichage
    /// par l'Observateur d'evenements).
    /// </summary>
    private static string ResolveMsgId(string v) => v switch
    {
        "%%1832" => "Identification",
        "%%1833" => "Impersonation",
        "%%1840" => "Delegation",
        "%%1841" => "Refuse par une ACE de niveau de confiance du processus",
        "%%1842" => "Oui",
        "%%1843" => "Non",
        "%%1844" => "Non demande",
        "%%1845" => "Oui",
        "%%1846" => "Non",
        _ => v
    };

    private static void Row(StringBuilder sb, string label, string? value) =>
        sb.Append($"<tr><td>{E(label)}</td><td>{value}</td></tr>");
}
