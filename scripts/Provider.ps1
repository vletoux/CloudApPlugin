<#
.SYNOPSIS
    Declares the CloudAP plug-in as an identity provider. Run as SYSTEM (psexec -s) or as an
    administrator: the script only needs SeRestorePrivilege and SeBackupPrivilege.

.DESCRIPTION
    -Step Register   : HKLM\SOFTWARE\Microsoft\IdentityStore\Providers\{guid} with Name and
                       ApPluginDLLPath, and LoadParameters\{guid}\Enabled = 1.
                       The Providers key belongs to TrustedInstaller. Its ACL is not changed: the key is
                       opened with REG_OPTION_BACKUP_RESTORE, which checks the privilege instead of the DACL.
    -Step Unregister : removes both keys.
    -Step Show       : the IdentityStore keys and the end of C:\Windows\Temp\CloudApPlugin.txt.
#>
param(
    [Parameter(Mandatory)][ValidateSet('Register', 'Unregister', 'Show')][string]$Step,
    [string]$Guid = '{5A0C2E62-7D4B-4C1A-9F3E-2B8D6E1A4C70}',
    [string]$Name = 'MYCP',                                     # = PROVIDER_NAME in CloudApPlugin.c
    [string]$PluginPath = '%SystemRoot%\System32\CloudApPlugin.dll'
)
$ErrorActionPreference = 'Stop'
$providers = 'SOFTWARE\Microsoft\IdentityStore\Providers'
$load = "HKLM\SOFTWARE\Microsoft\IdentityStore\LoadParameters\$Guid"

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class IdStore {
  [DllImport("advapi32", CharSet = CharSet.Unicode)] static extern int RegCreateKeyExW(IntPtr root, string sub, int reserved, string cls,
    int options, int sam, IntPtr sa, out IntPtr key, out int disposition);
  [DllImport("advapi32", CharSet = CharSet.Unicode)] static extern int RegSetValueExW(IntPtr key, string name, int reserved, int type, string data, int cb);
  [DllImport("advapi32", CharSet = CharSet.Unicode)] static extern int RegDeleteKeyExW(IntPtr root, string sub, int sam, int reserved);
  [DllImport("advapi32")] static extern int RegCloseKey(IntPtr key);
  [DllImport("ntdll")] static extern int RtlAdjustPrivilege(int privilege, bool enable, bool thread, out bool old);
  static readonly IntPtr HKLM = new IntPtr(unchecked((int)0x80000002));
  const int REG_OPTION_BACKUP_RESTORE = 4, KEY_WOW64_64KEY = 0x100;
  static void Privileges() { bool old; RtlAdjustPrivilege(18, true, false, out old); RtlAdjustPrivilege(17, true, false, out old); }
  public static string Write(string path, string[] names, string[] types, string[] values) {
    Privileges();
    IntPtr key; int disposition;
    int r = RegCreateKeyExW(HKLM, path, 0, null, REG_OPTION_BACKUP_RESTORE, 0x20006 | KEY_WOW64_64KEY, IntPtr.Zero, out key, out disposition);
    if (r != 0) return string.Format("RegCreateKeyEx({0}) {1}", path, r);
    for (int i = 0; i < names.Length; i++) {
      int type = types[i] == "expand" ? 2 : 1;
      r = RegSetValueExW(key, names[i], 0, type, values[i], (values[i].Length + 1) * 2);
      if (r != 0) { RegCloseKey(key); return string.Format("RegSetValueEx({0}) {1}", names[i], r); }
    }
    RegCloseKey(key);
    return string.Format("{0} {1}", path, disposition == 1 ? "created" : "updated");
  }
  public static string Delete(string path) {
    Privileges();
    IntPtr key; int disposition;
    int r = RegCreateKeyExW(HKLM, path, 0, null, REG_OPTION_BACKUP_RESTORE, 0x10000 | KEY_WOW64_64KEY, IntPtr.Zero, out key, out disposition);
    if (r != 0) return string.Format("open {0} {1}", path, r);
    RegCloseKey(key);
    return string.Format("RegDeleteKeyEx({0}) {1}", path, RegDeleteKeyExW(HKLM, path, KEY_WOW64_64KEY, 0));
  }
}
"@

switch ($Step) {
    'Register' {
        [IdStore]::Write("$providers\$Guid", @('Name', 'ApPluginDLLPath'), @('sz', 'expand'), @($Name, $PluginPath))
        reg add $load /v Enabled /t REG_DWORD /d 1 /f | Out-Null
        reg query "HKLM\$providers\$Guid"
        reg query $load
    }
    'Unregister' {
        [IdStore]::Delete("$providers\$Guid")
        reg delete $load /f
    }
    'Show' {
        reg query "HKLM\$providers" /s
        reg query HKLM\SOFTWARE\Microsoft\IdentityStore\LoadParameters /s
        '--- C:\Windows\Temp\CloudApPlugin.txt'
        Get-Content C:\Windows\Temp\CloudApPlugin.txt -Tail 30 -ErrorAction SilentlyContinue
    }
}
