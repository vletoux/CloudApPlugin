<#
.SYNOPSIS
    CloudAP call-package message 0 = cloudAP!CloudAPReinitPlugins:
    UninitializePlugins then InitializePlugins, i.e. every IdentityStore\Providers\{guid}\ApPluginDLLPath
    loaded again. Run as SYSTEM (trusted LSA connection: LsaRegisterLogonProcess needs SeTcbPrivilege).
#>
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class CloudApReinit {
  [StructLayout(LayoutKind.Sequential)] struct LSA_STRING { public ushort Length, MaximumLength; public IntPtr Buffer; }
  [DllImport("secur32")] static extern int LsaRegisterLogonProcess(ref LSA_STRING name, out IntPtr handle, out ulong mode);
  [DllImport("secur32")] static extern int LsaLookupAuthenticationPackage(IntPtr handle, ref LSA_STRING name, out uint package);
  [DllImport("secur32")] static extern int LsaCallAuthenticationPackage(IntPtr handle, uint package, byte[] buffer, int length,
    out IntPtr ret, out int retLength, out int status);
  [DllImport("secur32")] static extern int LsaFreeReturnBuffer(IntPtr p);
  [DllImport("secur32")] static extern int LsaDeregisterLogonProcess(IntPtr handle);
  static LSA_STRING Ansi(string s) { return new LSA_STRING { Length = (ushort)s.Length, MaximumLength = (ushort)(s.Length + 1), Buffer = Marshal.StringToHGlobalAnsi(s) }; }
  public static string Run() {
    var logon = Ansi("CloudApReinit"); var pkg = Ansi("CloudAP");
    IntPtr h; ulong mode; uint id;
    int s = LsaRegisterLogonProcess(ref logon, out h, out mode);
    if (s != 0) return string.Format("LsaRegisterLogonProcess 0x{0:X8}", s);
    try {
      s = LsaLookupAuthenticationPackage(h, ref pkg, out id);
      if (s != 0) return string.Format("LsaLookupAuthenticationPackage(CloudAP) 0x{0:X8}", s);
      IntPtr ret; int retLength, status;
      s = LsaCallAuthenticationPackage(h, id, new byte[4], 4, out ret, out retLength, out status);   // ULONG MessageType = 0
      if (ret != IntPtr.Zero) LsaFreeReturnBuffer(ret);
      return string.Format("CloudAP (package {0}) message 0 ReinitPlugins: call 0x{1:X8}, status 0x{2:X8}", id, s, status);
    } finally { LsaDeregisterLogonProcess(h); }
  }
}
"@
[CloudApReinit]::Run()
