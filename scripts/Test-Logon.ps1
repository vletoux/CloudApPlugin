# Submits an interactive logon straight to the CloudAP package: the SEC_WINNT_AUTH_IDENTITY_EX2 the
# credential provider serializes. Domain = the plug-in name routes it to the plug-in
# (cloudAP!_LsaApLogonUserEx2, see the README). Prints the token it gets.
# Run as SYSTEM (psexec -s): LsaRegisterLogonProcess needs SeTcbPrivilege.
param(
    [string]$User = 'user',
    [string]$Provider = 'MYCP',
    [string]$Secret = '123456',
    [string]$CredType = '28bfc32f-10f6-4738-98d1-1ac061df716a',   # SEC_WINNT_AUTH_DATA_TYPE_PASSWORD
    [int]$LogonType = 2)
$ErrorActionPreference = 'Continue'
Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
public static class CloudApLogon {
  [StructLayout(LayoutKind.Sequential)] struct LSA_STRING { public ushort Length, MaximumLength; public IntPtr Buffer; }
  [StructLayout(LayoutKind.Sequential)] struct TOKEN_SOURCE { [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)] public byte[] Name; public long Id; }
  [StructLayout(LayoutKind.Sequential)] struct QUOTA_LIMITS { public IntPtr a, b, c, d, e; public long f; }
  [DllImport("secur32")] static extern int LsaRegisterLogonProcess(ref LSA_STRING name, out IntPtr handle, out ulong mode);
  [DllImport("secur32")] static extern int LsaLookupAuthenticationPackage(IntPtr handle, ref LSA_STRING name, out uint package);
  [DllImport("secur32")] static extern int LsaLogonUser(IntPtr handle, ref LSA_STRING origin, int logonType, uint package,
    byte[] buffer, int length, IntPtr groups, ref TOKEN_SOURCE source, out IntPtr profile, out int profileLength,
    out long luid, out IntPtr token, out QUOTA_LIMITS quotas, out int subStatus);
  [DllImport("secur32")] static extern int LsaFreeReturnBuffer(IntPtr p);
  [DllImport("secur32")] static extern int LsaDeregisterLogonProcess(IntPtr handle);
  [DllImport("kernel32")] static extern bool CloseHandle(IntPtr h);
  static LSA_STRING Ansi(string s) { return new LSA_STRING { Length = (ushort)s.Length, MaximumLength = (ushort)(s.Length + 1), Buffer = Marshal.StringToHGlobalAnsi(s) }; }

  // SEC_WINNT_AUTH_IDENTITY_EX2 (0x30 header) + User + Domain + SEC_WINNT_AUTH_PACKED_CREDENTIALS
  // (0x1C header: cbHeaderLength, cbStructureLength, CredType GUID, ByteArrayOffset, ByteArrayLength).
  public static byte[] Ex2(string user, string domain, Guid credType, byte[] cred) {
    byte[] u = Encoding.Unicode.GetBytes(user), d = Encoding.Unicode.GetBytes(domain);
    int uOff = 0x30, dOff = uOff + u.Length, pOff = (dOff + d.Length + 3) & ~3, pLen = 0x1C + cred.Length;
    var m = new MemoryStream(); var w = new BinaryWriter(m);
    w.Write(0x201u); w.Write((ushort)0x30); w.Write((ushort)0); w.Write((uint)(pOff + pLen));
    w.Write((uint)uOff); w.Write((ushort)u.Length); w.Write((ushort)0);
    w.Write((uint)dOff); w.Write((ushort)d.Length); w.Write((ushort)0);
    w.Write((uint)pOff); w.Write((ushort)pLen); w.Write((ushort)0);
    w.Write(0x2u);                                   // Flags: SEC_WINNT_AUTH_IDENTITY_UNICODE
    w.Write(0u); w.Write((ushort)0); w.Write((ushort)0);   // no PackageList
    w.Write(u); w.Write(d); while (m.Length < pOff) w.Write((byte)0);
    w.Write((ushort)0x1C); w.Write((ushort)pLen); w.Write(credType.ToByteArray());
    w.Write(0x1Cu); w.Write((ushort)cred.Length); w.Write((ushort)0); w.Write(cred);
    return m.ToArray();
  }

  public static string Run(string user, string domain, Guid credType, byte[] cred, int logonType) {
    var name = Ansi("CloudApLogon"); var pkg = Ansi("CloudAP"); var origin = Ansi("CloudApLogon");
    IntPtr h; ulong mode; uint id;
    int s = LsaRegisterLogonProcess(ref name, out h, out mode);
    if (s != 0) return string.Format("LsaRegisterLogonProcess 0x{0:X8}", s);
    try {
      s = LsaLookupAuthenticationPackage(h, ref pkg, out id);
      if (s != 0) return string.Format("LsaLookupAuthenticationPackage(CloudAP) 0x{0:X8}", s);
      byte[] b = Ex2(user, domain, credType, cred);
      var src = new TOKEN_SOURCE { Name = Encoding.ASCII.GetBytes("CloudAp\0") };
      IntPtr profile, token; int profileLength, sub; long luid; QUOTA_LIMITS q;
      s = LsaLogonUser(h, ref origin, logonType, id, b, b.Length, IntPtr.Zero, ref src,
        out profile, out profileLength, out luid, out token, out q, out sub);
      if (profile != IntPtr.Zero) LsaFreeReturnBuffer(profile);
      string who = "";
      if (token != IntPtr.Zero) {
        using (var wi = new System.Security.Principal.WindowsIdentity(token)) {
          who = string.Format("\n  token: {0} ({1}), auth type {2}, {3} groups:", wi.Name, wi.User, wi.AuthenticationType, wi.Groups.Count);
          foreach (var g in wi.Groups) {
            string n; try { n = g.Translate(typeof(System.Security.Principal.NTAccount)).Value; } catch { n = ""; }
            who += string.Format("\n    {0} {1}", g.Value, n);
          }
        }
        CloseHandle(token);
      }
      return string.Format("LsaLogonUser(CloudAP pkg {0}, type {1}, {2} bytes, {3}\\{4}): 0x{5:X8} sub 0x{6:X8} luid 0x{7:X}{8}",
        id, logonType, b.Length, domain, user, s, sub, luid, who);
    } finally { LsaDeregisterLogonProcess(h); }
  }
}
"@
[CloudApLogon]::Run($User, $Provider, [Guid]$CredType, [Text.Encoding]::Unicode.GetBytes($Secret), $LogonType)
Get-Content C:\Windows\Temp\CloudApPlugin.txt -Tail 10 -ErrorAction SilentlyContinue
