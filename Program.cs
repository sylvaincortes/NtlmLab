using System.Security.Principal;
using Microsoft.AspNetCore.Authentication;   // AuthenticateAsync
using Microsoft.AspNetCore.Server.IIS;       // IISServerDefaults (hebergement in-process)
using NtlmLab;

var builder = WebApplication.CreateBuilder(args);

// IIS realise l'authentification Windows : les blocs <location> du web.config
// fixent les providers (NTLM seul sur /ntlm, Negotiate sur /kerberos) et
// desactivent l'acces anonyme sur ces chemins.
//
// Cote application il faut neanmoins declarer le schema "Windows" et activer
// le middleware d'authentification, sinon l'identite negociee par IIS n'est
// pas propagee vers HttpContext.User.
//
// Attention au namespace : IISServerDefaults est dans Microsoft.AspNetCore.Server.IIS
// (hebergement in-process). IISDefaults, lui, est dans ...Server.IISIntegration
// (hebergement out-of-process). Les deux valent "Windows".
builder.Services.AddAuthentication(IISServerDefaults.AuthenticationScheme);
builder.Services.AddAuthorization();
builder.Services.Configure<IISServerOptions>(o => o.AutomaticAuthentication = true);

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

static IResult Html(string body) => Results.Content(body, "text/html; charset=utf-8");

// L'hebergement in-process ne remplit pas toujours HttpContext.User, meme quand
// IIS a authentifie la requete (LOGON_USER renseigne). On tente donc une
// resolution explicite du schema "Windows" en secours, et on remonte le detail
// de l'echec le cas echeant plutot que d'afficher une page muette.
static async Task<IResult> Protected(HttpContext ctx, string requested)
{
    // NTLM etant oriente connexion, l'authentification reste valable pour
    // toute la connexion TCP : un rechargement ne produirait aucun nouvel
    // evenement. Fermer la connexion force une poignee de main complete a
    // chaque requete, donc un 4624 par rechargement de page.
    if (requested == "NTLM") ctx.Response.Headers.Connection = "close";

    var id = ctx.User.Identity as WindowsIdentity;
    string? diag = null;

    if (id is null || !id.IsAuthenticated)
    {
        try
        {
            var r = await ctx.AuthenticateAsync(IISServerDefaults.AuthenticationScheme);
            diag = $"AuthenticateAsync(\"{IISServerDefaults.AuthenticationScheme}\") : "
                 + $"Succeeded={r.Succeeded}, None={r.None}, Failure={r.Failure?.Message ?? "aucune"}";
            if (r.Principal?.Identity is WindowsIdentity w && w.IsAuthenticated) id = w;
        }
        catch (Exception ex)
        {
            diag = $"AuthenticateAsync a leve {ex.GetType().Name} : {ex.Message}";
        }
    }

    // Pas de repli sur WindowsIdentity.GetCurrent() : il renverrait l'identite
    // du pool d'applications, pas celle de l'appelant, ce qui serait trompeur.

    if (id is null || !id.IsAuthenticated)
    {
        // Quels schemas d'authentification sont REELLEMENT enregistres ?
        try
        {
            var provider = ctx.RequestServices.GetService<IAuthenticationSchemeProvider>();
            var schemes = provider is null
                ? "(IAuthenticationSchemeProvider absent)"
                : string.Join(", ", (await provider.GetAllSchemesAsync())
                      .Select(s => $"{s.Name} -> {s.HandlerType.Name}"));
            diag += $" | schemas enregistres : {schemes}";
        }
        catch (Exception ex) { diag += $" | enumeration des schemas impossible : {ex.Message}"; }

        diag += $" | processus : {Path.GetFileName(Environment.ProcessPath)}";
    }

    return Html(Pages.Details(ctx, requested, id, diag));
}

// ---- Page de choix : anonyme (anonymousAuthentication=true a la racine) ----
app.MapGet("/", () => Html(Pages.Login()));

// Le cast en Delegate est indispensable (ASP0016) : sans lui, un lambda dont
// le seul parametre est HttpContext est traite comme un RequestDelegate, dont
// la valeur de retour est ignoree -- la reponse serait vide.
//
// ---- NTLM : IIS n'annonce que "WWW-Authenticate: NTLM" ----
app.MapGet("/ntlm", (Delegate)((HttpContext ctx) => Protected(ctx, "NTLM")));

// ---- Kerberos : IIS n'annonce que "WWW-Authenticate: Negotiate" ----
app.MapGet("/kerberos", (Delegate)((HttpContext ctx) => Protected(ctx, "Kerberos")));

// ---- Variante JSON, pratique pour scripter / curl ----
app.MapGet("/ntlm/json", (Delegate)((HttpContext ctx) => Results.Json(Pages.Snapshot(ctx))));
app.MapGet("/kerberos/json", (Delegate)((HttpContext ctx) => Results.Json(Pages.Snapshot(ctx))));

// ---- Diagnostic du serveur (anonyme) ----
app.MapGet("/health", () =>
{
    // Domaine DNS de la MACHINE (et non du compte du processus : le pool tourne
    // sous un compte virtuel dont le "domaine" est "IIS APPPOOL").
    var ip = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties();
    var dnsDomain = string.IsNullOrWhiteSpace(ip.DomainName) ? null : ip.DomainName;

    return Results.Json(new
    {
        machine = Environment.MachineName,
        dnsDomain,
        fqdn = dnsDomain is null ? ip.HostName : $"{ip.HostName}.{dnsDomain}".ToLowerInvariant(),
        domainJoined = dnsDomain is not null,
        testUrl = dnsDomain is null ? null : $"http://{ip.HostName}.{dnsDomain}:8080/".ToLowerInvariant(),
        processIdentity = System.Security.Principal.WindowsIdentity.GetCurrent().Name,
        canReadSecurityLog = EventLookup.CanReadSecurityLog(),
        lmCompatibilityLevel = HostInfo.LmCompatibilityLevel(),
        ntlmAuditIncoming = HostInfo.AuditReceivingNtlmTraffic(),
        utc = DateTime.UtcNow
    });
});

app.Run();
