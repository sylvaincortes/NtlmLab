using System.Diagnostics.Eventing.Reader;
using System.Xml.Linq;
using Microsoft.Win32;

namespace NtlmLab;

public record EventInfo(
    int EventId,
    string Log,
    DateTime? Time,
    Dictionary<string, string> Data,
    string? Error = null);

public static class EventLookup
{
    /// <summary>
    /// Retrouve le 4624 (ouverture de session) dont le TargetLogonId correspond
    /// au Logon ID du token de la requete HTTP. C'est LA preuve de correlation.
    /// </summary>
    public static EventInfo? Find4624(ulong logonId)
    {
        if (logonId == 0) return null;
        var hex = "0x" + logonId.ToString("x");
        var xpath = $"*[System[(EventID=4624)] and EventData[Data[@Name='TargetLogonId']='{hex}']]";

        try
        {
            // Le 4624 peut etre ecrit avec un leger decalage : on retente ~1,5 s.
            for (int i = 0; i < 6; i++)
            {
                var rec = ReadFirst("Security", xpath);
                if (rec is not null) return rec;
                Thread.Sleep(250);
            }
            return null;
        }
        catch (Exception ex)
        {
            return new EventInfo(4624, "Security", null, new(), ex.Message);
        }
    }

    /// <summary>Derniers evenements du journal Microsoft-Windows-NTLM/Operational.</summary>
    public static List<EventInfo> RecentNtlmOperational(int max = 5)
    {
        var list = new List<EventInfo>();
        const string log = "Microsoft-Windows-NTLM/Operational";
        try
        {
            // 8001-8004 : Windows Server 2008 R2 a 2022.
            // 4020-4023 : Windows Server 2025 / Windows 11 recent, messages bien
            //             plus detailles (version NTLM, drapeaux negocies,
            //             channel binding, statut). Repartition par role :
            //               4020 / 4021  client, authentification NTLM sortante
            //               4022 / 4023  serveur de ressource, NTLM entrant
            //             (les evenements du DC, 4030-4033, viennent d'un autre
            //              fournisseur : Microsoft-Windows-Security-Netlogon)
            //             4015 signale un NTLM sortant BLOQUE cote client.
            var query = new EventLogQuery(log, PathType.LogName,
                "*[System[(EventID=4015 or EventID=4020 or EventID=4021 or " +
                "EventID=4022 or EventID=4023 or " +
                "EventID=8001 or EventID=8002 or EventID=8003 or EventID=8004)]]")
            { ReverseDirection = true };

            using var reader = new EventLogReader(query);
            EventRecord? rec;
            while (list.Count < max && (rec = reader.ReadEvent()) is not null)
            {
                using (rec)
                    list.Add(new EventInfo(rec.Id, log, rec.TimeCreated, ParseData(rec.ToXml())));
            }
        }
        catch (Exception ex)
        {
            list.Add(new EventInfo(0, log, null, new(), ex.Message));
        }
        return list;
    }

    public static bool CanReadSecurityLog()
    {
        try
        {
            var q = new EventLogQuery("Security", PathType.LogName, "*") { ReverseDirection = true };
            using var r = new EventLogReader(q);
            r.ReadEvent()?.Dispose();
            return true;
        }
        catch { return false; }
    }

    private static EventInfo? ReadFirst(string log, string xpath)
    {
        var query = new EventLogQuery(log, PathType.LogName, xpath) { ReverseDirection = true };
        using var reader = new EventLogReader(query);
        var rec = reader.ReadEvent();
        if (rec is null) return null;
        using (rec)
            return new EventInfo(rec.Id, log, rec.TimeCreated, ParseData(rec.ToXml()));
    }

    private static Dictionary<string, string> ParseData(string xml)
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var doc = XDocument.Parse(xml);
            var ns = doc.Root!.GetDefaultNamespace();
            foreach (var d in doc.Descendants(ns + "Data"))
            {
                var name = d.Attribute("Name")?.Value;
                if (string.IsNullOrEmpty(name)) continue;
                dict.TryAdd(name, d.Value);
            }
        }
        catch { /* best effort */ }
        return dict;
    }
}

public static class HostInfo
{
    public static string LmCompatibilityLevel()
    {
        var v = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa",
                                  "LmCompatibilityLevel", null);
        return v is null ? "non defini (= 3 par defaut)" : v.ToString()!;
    }

    public static string AuditReceivingNtlmTraffic()
    {
        var v = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0",
                                  "AuditReceivingNTLMTraffic", null);
        return v?.ToString() switch
        {
            "2" => "2 (audit de tout le trafic NTLM entrant)",
            "1" => "1 (audit des comptes de domaine uniquement)",
            null => "non defini (pas d'audit NTLM)",
            var o => o!
        };
    }
}
