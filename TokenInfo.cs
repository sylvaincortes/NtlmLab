using System.Runtime.InteropServices;
using System.Security.Principal;

namespace NtlmLab;

/// <summary>
/// Extrait du token Windows les informations qui permettent de faire le lien
/// avec les evenements de securite : surtout l'AuthenticationId (= "Logon ID"
/// affiche dans l'evenement 4624).
/// </summary>
public static class TokenInfo
{
    [StructLayout(LayoutKind.Sequential)]
    private struct LUID
    {
        public uint LowPart;
        public int HighPart;
        public ulong ToUInt64() => ((ulong)(uint)HighPart << 32) | LowPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_STATISTICS
    {
        public LUID TokenId;
        public LUID AuthenticationId;
        public long ExpirationTime;
        public int TokenType;            // 1 = Primary, 2 = Impersonation
        public int ImpersonationLevel;   // 0..3
        public uint DynamicCharged;
        public uint DynamicAvailable;
        public uint GroupCount;
        public uint PrivilegeCount;
        public LUID ModifiedId;
    }

    private const int TokenStatistics = 10;

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(
        IntPtr TokenHandle, int TokenInformationClass,
        IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);

    public record Stats(
        ulong LogonId,
        string LogonIdHex,
        string TokenType,
        string ImpersonationLevel,
        uint GroupCount,
        uint PrivilegeCount,
        string? Error);

    public static Stats Read(WindowsIdentity identity)
    {
        IntPtr buf = IntPtr.Zero;
        try
        {
            var handle = identity.AccessToken.DangerousGetHandle();
            int size = Marshal.SizeOf<TOKEN_STATISTICS>();
            buf = Marshal.AllocHGlobal(size);

            if (!GetTokenInformation(handle, TokenStatistics, buf, size, out _))
                return new Stats(0, "n/a", "?", "?", 0, 0,
                    $"GetTokenInformation a echoue (Win32 {Marshal.GetLastWin32Error()})");

            var st = Marshal.PtrToStructure<TOKEN_STATISTICS>(buf);
            ulong luid = st.AuthenticationId.ToUInt64();

            return new Stats(
                luid,
                "0x" + luid.ToString("x"),
                st.TokenType == 1 ? "Primary" : st.TokenType == 2 ? "Impersonation" : st.TokenType.ToString(),
                st.ImpersonationLevel switch
                {
                    0 => "Anonymous",
                    1 => "Identification",
                    2 => "Impersonation",
                    3 => "Delegation",
                    _ => st.ImpersonationLevel.ToString()
                },
                st.GroupCount,
                st.PrivilegeCount,
                null);
        }
        catch (Exception ex)
        {
            return new Stats(0, "n/a", "?", "?", 0, 0, ex.Message);
        }
        finally
        {
            if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
        }
    }

    /// <summary>Groupes du token resolus en noms lisibles.</summary>
    public static List<string> Groups(WindowsIdentity identity, int max = 40)
    {
        var result = new List<string>();
        foreach (var g in identity.Groups ?? Enumerable.Empty<IdentityReference>())
        {
            if (result.Count >= max) { result.Add("..."); break; }
            try { result.Add(g.Translate(typeof(NTAccount)).Value); }
            catch { result.Add(g.Value); }
        }
        result.Sort(StringComparer.OrdinalIgnoreCase);
        return result;
    }
}
